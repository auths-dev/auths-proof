//! Durable gateway records: one-use attempt claims, count and sum slots, and
//! the shared connection record. This store does not infer provider effect.
//!
//! [`GatewayAttempts`] owns the attempt record format
//! `auths.gateway-attempt/9`, its stages, and which stage changes are valid;
//! the transition rule itself is the translated leaf
//! `auths_gateway_kernel::transition::valid_transition`. Records persist
//! through a [`GatewayAttemptStore`], which is only an all-or-none
//! insert-once, compare-and-swap, and sweep mechanism over opaque bounded
//! bytes of seven closed kinds: [`FileGatewayAttemptStore`] for one host, and
//! the multi-host `PostgresLifecycleStore`, whose production qualification is
//! still open.

use crate::effect::{ApprovedEffect, EffectBinding, EffectPolicy, ExactEffectApproval};
use crate::recipe::ObservationTemplate;
use crate::{
    ClosedObservationRequest, ClosedProviderRequest, LogicalOperationId, OperatorNamespace,
    echo_token,
};
use auths_gateway_kernel::transition::{self, AttemptView, Link, Reading, Stage};
use auths_lifecycle::StoreError;
use auths_stores::{GatewayRecordInsert, PostgresLifecycleStore};
use base64ct::{Base64, Encoding as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Instant,
};
use tempfile::NamedTempFile;
use thiserror::Error;

pub use auths_stores::GatewayRecordKind;

const SCHEMA: &str = "auths.gateway-attempt/9";
const PRE_ENTRY_DOMAIN: &[u8] = b"auths.gateway-pre-entry/1\0";
const BATCH_SCHEMA: &str = "auths.gateway-file-batch/1";
const SLOT_FILE_SCHEMA: &str = "auths.gateway-file-slot/1";
const BATCH_FILE: &str = ".batch.json";
const LOCK_FILE: &str = ".replace.lock";
/// A load that keeps finding a crashed batch gives up after this many
/// rollbacks rather than spin.
const MAX_RECOVERY_ROUNDS: usize = 8;
const MAX_RECORD_BYTES: usize = auths_stores::MAX_GATEWAY_RECORD_BYTES;
const MAX_BATCH_ENTRIES: usize = auths_stores::MAX_GATEWAY_BATCH_ENTRIES;
/// A slot file wraps its record in base64 with its expiry.
const MAX_SLOT_FILE_BYTES: usize = MAX_RECORD_BYTES * 2;
/// A batch file lists every target with its bytes.
const MAX_BATCH_FILE_BYTES: usize = MAX_SLOT_FILE_BYTES * MAX_BATCH_ENTRIES;
const MAX_EVIDENCE_BYTES: usize = 65_536;
const MAX_PRE_ENTRY_OBSERVATIONS: usize = 4;
const MAX_COUNTERS: usize = 34;
const MAX_REFUSAL_BYTES: usize = 128;
const MAX_LOCATOR_VALUES: usize = 2;
const MAX_LOCATOR_VALUE_BYTES: usize = 255;
const MAX_JSON_INTEGER: u64 = (1 << 53) - 1;

/// Conservative gateway attempt stages; a response is not effect evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayAttemptStage {
    /// Transport entry was durably excluded after a claim.
    NotEntered,
    /// Durable admission and capacity reservation; no provider entry yet.
    Reserved,
    /// A unique durable grant exists; external entry may have occurred.
    EntryGranted,
    /// A complete bounded HTTP response was durably recorded.
    ResponseRecorded,
    /// Entry or effect is ambiguous; no automatic retry.
    Unknown,
    /// A separate read-only comparison completed; match is not causation.
    Observed,
    /// A read-back returned exactly this attempt's echo token and the verified
    /// value. The link to the authorization holds only while no other party
    /// with write access to that provider field wrote the same token.
    ObservedByProvider,
}

impl GatewayAttemptStage {
    const fn kernel(self) -> Stage {
        match self {
            Self::NotEntered => Stage::NotEntered,
            Self::Reserved => Stage::Reserved,
            Self::EntryGranted => Stage::EntryGranted,
            Self::ResponseRecorded => Stage::ResponseRecorded,
            Self::Unknown => Stage::Unknown,
            Self::Observed => Stage::Observed,
            Self::ObservedByProvider => Stage::ObservedByProvider,
        }
    }
}

/// Additional secret-free fact recorded with an `observed` stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayObservationFact {
    /// The echo field held a token other than this attempt's. Another writer
    /// changed it, or this write never applied; the gateway does not guess.
    EchoMismatch,
}

/// How provider-held evidence was obtained.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayEvidenceChannel {
    /// A bounded read-only GET over the pinned origin with the gateway credential.
    ReadBack,
}

/// Secret-free provider evidence kept for every `observed-by-provider` stage.
/// The bytes inherit the provider data's sensitivity and must not be logged;
/// `Debug` reports only their length.
#[derive(Clone, Eq, PartialEq)]
pub struct GatewayProviderEvidence {
    channel: GatewayEvidenceChannel,
    locator: String,
    echo: String,
    evidence_digest: [u8; 32],
    evidence: Vec<u8>,
    observed_at: u64,
}

impl GatewayProviderEvidence {
    /// Returns the evidence channel.
    #[must_use]
    pub const fn channel(&self) -> GatewayEvidenceChannel {
        self.channel
    }
    /// Returns the observation URL, built from the plan fixed at the claim.
    #[must_use]
    pub fn locator(&self) -> &str {
        &self.locator
    }
    /// Returns the echo token found in the provider record.
    #[must_use]
    pub fn echo(&self) -> &str {
        &self.echo
    }
    /// Returns SHA-256 of the exact observation response bytes.
    #[must_use]
    pub const fn evidence_digest(&self) -> &[u8; 32] {
        &self.evidence_digest
    }
    /// Returns the bounded observation response bytes.
    #[must_use]
    pub fn evidence(&self) -> &[u8] {
        &self.evidence
    }
    /// Returns gateway wall-clock seconds; this time is not authenticated.
    #[must_use]
    pub const fn observed_at(&self) -> u64 {
        self.observed_at
    }
}

impl std::fmt::Debug for GatewayProviderEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayProviderEvidence")
            .field("channel", &self.channel)
            .field("locator", &self.locator)
            .field("echo", &self.echo)
            .field("evidence_digest", &hex::encode(self.evidence_digest))
            .field("evidence_bytes", &self.evidence.len())
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

/// Typed conservative projection of one operation in the shared journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayOperationStage {
    /// Provider mutation facts, including supported independent observations.
    Mutation(GatewayAttemptStage),
    /// Provider acquisition facts; never mutation success or recipient delivery.
    Acquisition(AcquisitionStage),
}

impl GatewayOperationStage {
    pub(crate) const fn protocol(self) -> &'static str {
        match self {
            Self::Mutation(_) => "mutation",
            Self::Acquisition(_) => "acquisition",
        }
    }
}

/// The kind of a reserved counter.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayCounterKind {
    /// A per-window count.
    Count,
    /// A per-window sum.
    Sum,
}

/// One counter slot reserved with the claim.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GatewayCounterEntry {
    /// The counter kind.
    pub kind: GatewayCounterKind,
    /// The counter key.
    pub counter: [u8; 32],
    /// The reserved slot number.
    pub slot: u64,
}

/// The relative-ceiling basis the gateway read after the lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayRelativeBasis {
    /// The basis value.
    pub value: u64,
    /// SHA-256 of the basis response body.
    pub response_digest: [u8; 32],
    /// The gateway clock at the read; not authenticated.
    pub read_at: u64,
}

/// What was read after the lease and before the write: the signed pre-entry
/// observations, in pointer order, and the relative-ceiling basis.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GatewayPreEntry {
    /// Canonical signed `auths.gateway-readback/1` observations.
    pub observations: Vec<Vec<u8>>,
    /// The relative-ceiling basis, when one was read.
    pub basis: Option<GatewayRelativeBasis>,
}

impl GatewayPreEntry {
    /// Whether nothing was read.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.observations.is_empty() && self.basis.is_none()
    }

    /// SHA-256 of `auths.gateway-pre-entry/1`, NUL, and each observation's
    /// four-byte big-endian length and bytes, or `None` without
    /// observations.
    #[must_use]
    pub fn digest(&self) -> Option<[u8; 32]> {
        pre_entry_digest(&self.observations)
    }
}

/// The pre-entry digest of `observations`, or `None` when there are none.
#[must_use]
pub fn pre_entry_digest(observations: &[Vec<u8>]) -> Option<[u8; 32]> {
    if observations.is_empty() {
        return None;
    }
    let mut hash = Sha256::new();
    hash.update(PRE_ENTRY_DOMAIN);
    for observation in observations {
        hash.update(u32::try_from(observation.len()).ok()?.to_be_bytes());
        hash.update(observation);
    }
    Some(hash.finalize().into())
}

/// Secret-free persisted evidence for one logical operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayAttemptSnapshot {
    revision: u64,
    namespace: OperatorNamespace,
    operation_id: LogicalOperationId,
    action_commitment: [u8; 32],
    recipe_digest: [u8; 32],
    evaluated_at: u64,
    stage: GatewayAttemptStage,
    refusal: Option<String>,
    counters: Vec<GatewayCounterEntry>,
    response_status: Option<u16>,
    response_digest: Option<[u8; 32]>,
    response_locator: Option<BTreeMap<String, String>>,
    observation_match: Option<bool>,
    observation_fact: Option<GatewayObservationFact>,
    provider_evidence: Option<GatewayProviderEvidence>,
    pre_entry: Option<GatewayPreEntry>,
    recovery_evidence: Option<acquisition::RecoveryEvidenceLink>,
}

impl GatewayAttemptSnapshot {
    /// Whether this history was refined by an independently authorized read.
    #[must_use]
    pub const fn has_recovery_evidence(&self) -> bool {
        self.recovery_evidence.is_some()
    }

    /// Returns the read's original receipt time, without refreshing it on replay.
    #[must_use]
    pub fn recovery_received_at(&self) -> Option<u64> {
        self.recovery_evidence
            .as_ref()
            .map(|link| link.received_at())
    }

    /// Returns the durable journal revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the operator namespace.
    #[must_use]
    pub const fn namespace(&self) -> &OperatorNamespace {
        &self.namespace
    }
    /// Returns the stable operation ID.
    #[must_use]
    pub const fn operation_id(&self) -> &LogicalOperationId {
        &self.operation_id
    }
    /// Returns the exact action commitment.
    #[must_use]
    pub const fn action_commitment(&self) -> &[u8; 32] {
        &self.action_commitment
    }
    /// Returns the installed recipe digest.
    #[must_use]
    pub const fn recipe_digest(&self) -> &[u8; 32] {
        &self.recipe_digest
    }
    /// Returns the gateway clock when native verification ran.
    #[must_use]
    pub const fn evaluated_at(&self) -> u64 {
        self.evaluated_at
    }
    /// Returns the conservative stage.
    #[must_use]
    pub const fn stage(&self) -> GatewayAttemptStage {
        self.stage
    }
    /// Returns the stable refusal code, exactly when `not-entered`.
    #[must_use]
    pub fn refusal(&self) -> Option<&str> {
        self.refusal.as_deref()
    }
    /// Returns the counter slots reserved with the claim, sorted.
    #[must_use]
    pub fn counters(&self) -> &[GatewayCounterEntry] {
        &self.counters
    }
    /// Returns the HTTP status only after a complete response.
    #[must_use]
    pub const fn response_status(&self) -> Option<u16> {
        self.response_status
    }
    /// Returns SHA-256 of the complete response body.
    #[must_use]
    pub const fn response_digest(&self) -> Option<&[u8; 32]> {
        self.response_digest.as_ref()
    }
    /// Returns the response-locator values, pointer to value.
    #[must_use]
    pub const fn response_locator(&self) -> Option<&BTreeMap<String, String>> {
        self.response_locator.as_ref()
    }
    /// Returns read-back equality, never exclusive causation.
    #[must_use]
    pub const fn observation_match(&self) -> Option<bool> {
        self.observation_match
    }
    /// Returns an additional fact recorded with the observation.
    #[must_use]
    pub const fn observation_fact(&self) -> Option<GatewayObservationFact> {
        self.observation_fact
    }
    /// Returns provider-held evidence for `observed-by-provider` only.
    #[must_use]
    pub const fn provider_evidence(&self) -> Option<&GatewayProviderEvidence> {
        self.provider_evidence.as_ref()
    }
    /// Returns what was read after the lease and before the write.
    #[must_use]
    pub const fn pre_entry(&self) -> Option<&GatewayPreEntry> {
        self.pre_entry.as_ref()
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceWire {
    channel: GatewayEvidenceChannel,
    locator: String,
    echo: String,
    evidence_digest: String,
    evidence_b64: String,
    observed_at: u64,
}

impl EvidenceWire {
    fn decode(
        &self,
        locator: &str,
        expected_echo: &str,
    ) -> Result<GatewayProviderEvidence, GatewayAttemptError> {
        let evidence_digest = digest_bytes(&self.evidence_digest)?;
        let evidence =
            Base64::decode_vec(&self.evidence_b64).map_err(|_| GatewayAttemptError::Corrupt)?;
        if self.locator != locator
            || self.echo != expected_echo
            || evidence.is_empty()
            || evidence.len() > MAX_EVIDENCE_BYTES
            || <[u8; 32]>::from(Sha256::digest(&evidence)) != evidence_digest
        {
            return Err(GatewayAttemptError::Corrupt);
        }
        Ok(GatewayProviderEvidence {
            channel: self.channel,
            locator: self.locator.clone(),
            echo: self.echo.clone(),
            evidence_digest,
            evidence,
            observed_at: self.observed_at,
        })
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CounterWire {
    kind: GatewayCounterKind,
    counter: String,
    slot: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BasisWire {
    value: u64,
    response_digest: String,
    read_at: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PreEntryWire {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    observations_b64: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    basis: Option<BasisWire>,
}

impl PreEntryWire {
    fn encode(pre_entry: &GatewayPreEntry) -> Result<Option<Self>, GatewayAttemptError> {
        if pre_entry.is_empty() {
            return Ok(None);
        }
        let wire = Self {
            observations_b64: pre_entry
                .observations
                .iter()
                .map(|bytes| Base64::encode_string(bytes))
                .collect(),
            digest: pre_entry.digest().map(hex::encode),
            basis: pre_entry.basis.map(|basis| BasisWire {
                value: basis.value,
                response_digest: hex::encode(basis.response_digest),
                read_at: basis.read_at,
            }),
        };
        wire.decode()?;
        Ok(Some(wire))
    }

    fn decode(&self) -> Result<GatewayPreEntry, GatewayAttemptError> {
        if self.observations_b64.len() > MAX_PRE_ENTRY_OBSERVATIONS {
            return Err(GatewayAttemptError::Corrupt);
        }
        let observations = self
            .observations_b64
            .iter()
            .map(|text| {
                let bytes = Base64::decode_vec(text).map_err(|_| GatewayAttemptError::Corrupt)?;
                if bytes.is_empty() || bytes.len() > auths_model::MAX_OBSERVATION_BYTES {
                    return Err(GatewayAttemptError::Corrupt);
                }
                Ok(bytes)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let digest = self.digest.as_deref().map(digest_bytes).transpose()?;
        if digest != pre_entry_digest(&observations) {
            return Err(GatewayAttemptError::Corrupt);
        }
        let basis = self
            .basis
            .as_ref()
            .map(|basis| {
                if basis.value > MAX_JSON_INTEGER {
                    return Err(GatewayAttemptError::Corrupt);
                }
                Ok(GatewayRelativeBasis {
                    value: basis.value,
                    response_digest: digest_bytes(&basis.response_digest)?,
                    read_at: basis.read_at,
                })
            })
            .transpose()?;
        let decoded = GatewayPreEntry {
            observations,
            basis,
        };
        if decoded.is_empty() {
            return Err(GatewayAttemptError::Corrupt);
        }
        Ok(decoded)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record<S = MutationState> {
    revision: u64,
    schema: String,
    binding_canonical: String,
    approval_canonical: String,
    namespace: String,
    operation_id: String,
    action_commitment: String,
    recipe_digest: String,
    nonce: String,
    evaluated_at: u64,
    entry: Option<EntryAudit>,
    state: S,
}

impl<S> Record<S> {
    fn new(
        binding: &EffectBinding,
        approval: &ExactEffectApproval,
        evaluated_at: u64,
        state: S,
    ) -> Result<Self, GatewayAttemptError> {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| GatewayAttemptError::Unavailable)?;
        Ok(Record {
            revision: 1,
            schema: SCHEMA.to_owned(),
            binding_canonical: String::from_utf8(
                binding
                    .to_private_bytes()
                    .map_err(|_| GatewayAttemptError::Corrupt)?
                    .to_vec(),
            )
            .map_err(|_| GatewayAttemptError::Corrupt)?,
            approval_canonical: String::from_utf8(
                approval
                    .to_private_bytes()
                    .map_err(|_| GatewayAttemptError::Corrupt)?
                    .to_vec(),
            )
            .map_err(|_| GatewayAttemptError::Corrupt)?,
            namespace: binding.journal_identity().0.to_owned(),
            operation_id: binding.journal_identity().1.to_owned(),
            action_commitment: hex::encode(binding.journal_identity().2),
            recipe_digest: hex::encode(binding.journal_identity().3),
            nonce: hex::encode(nonce),
            evaluated_at,
            entry: None,
            state,
        })
    }

    fn validate_header(&self) -> Result<EffectBinding, GatewayAttemptError> {
        let binding = EffectBinding::from_private_bytes(self.binding_canonical.as_bytes())
            .map_err(|_| GatewayAttemptError::Corrupt)?;
        let approval = ExactEffectApproval::from_private_bytes(self.approval_canonical.as_bytes())
            .map_err(|_| GatewayAttemptError::Corrupt)?;
        binding
            .validate_recorded_approval(&approval, self.evaluated_at)
            .map_err(|_| GatewayAttemptError::Corrupt)?;
        let (namespace, operation, action, recipe) = binding.journal_identity();
        if namespace != self.namespace
            || operation != self.operation_id
            || hex::encode(action) != self.action_commitment
            || hex::encode(recipe) != self.recipe_digest
        {
            return Err(GatewayAttemptError::Corrupt);
        }
        if self.entry.as_ref().is_some_and(|entry| {
            entry.schema != "auths.effect-entry/2"
                || entry.revision < 2
                || entry.revision > self.revision
                || entry.authorization_started_at < self.evaluated_at
                || entry.granted_at < entry.authorization_started_at
                || entry.granted_at < self.evaluated_at
                || entry.granted_at > MAX_JSON_INTEGER
                || entry.effect_id != hex::encode(binding.id().as_bytes())
                || entry.dependencies.len() >= auths_stores::MAX_GATEWAY_FENCE_RECORDS
                || entry
                    .dependencies
                    .iter()
                    .any(|value| digest_bytes(value).is_err())
        }) {
            return Err(GatewayAttemptError::Corrupt);
        }
        if let Some(entry) = &self.entry {
            let approval =
                ExactEffectApproval::from_private_bytes(entry.approval_canonical.as_bytes())
                    .map_err(|_| GatewayAttemptError::Corrupt)?;
            binding
                .validate_recorded_approval(&approval, entry.granted_at)
                .map_err(|_| GatewayAttemptError::Corrupt)?;
            if let Some(pre_entry) = &entry.pre_entry {
                pre_entry.decode()?;
            }
        }
        if self.schema != SCHEMA
            || self.nonce.len() != 32
            || !self
                .nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(GatewayAttemptError::Corrupt);
        }
        Ok(binding)
    }

    fn record_grant(
        &mut self,
        approved: &ApprovedEffect,
        authorization_started_at: u64,
        now: u64,
        pre_entry: Option<PreEntryWire>,
        dependencies: &[Option<Vec<u8>>],
    ) -> Result<(), GatewayAttemptError> {
        if self.entry.is_some() || authorization_started_at < self.evaluated_at {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(GatewayAttemptError::InvalidTransition)?;
        self.entry = Some(EntryAudit {
            revision: self.revision,
            authorization_started_at,
            pre_entry,
            approval_canonical: String::from_utf8(
                approved
                    .approval()
                    .to_private_bytes()
                    .map_err(|_| GatewayAttemptError::Corrupt)?
                    .to_vec(),
            )
            .map_err(|_| GatewayAttemptError::Corrupt)?,
            schema: "auths.effect-entry/2".to_owned(),
            granted_at: now,
            effect_id: hex::encode(approved.effect().binding().id().as_bytes()),
            dependencies: dependencies
                .iter()
                .map(|bytes| {
                    let bytes = bytes.as_deref().ok_or(GatewayAttemptError::Corrupt)?;
                    auths_codec::domain_commitment("auths.effect-entry-dependency/1", bytes)
                        .map(|digest| hex::encode(digest.as_bytes()))
                        .map_err(|_| GatewayAttemptError::Corrupt)
                })
                .collect::<Result<Vec<_>, _>>()?,
        });
        Ok(())
    }

    fn map_state<T>(
        self,
        map: impl FnOnce(S) -> Result<T, GatewayAttemptError>,
    ) -> Result<Record<T>, GatewayAttemptError> {
        Ok(Record {
            revision: self.revision,
            schema: self.schema,
            binding_canonical: self.binding_canonical,
            approval_canonical: self.approval_canonical,
            namespace: self.namespace,
            operation_id: self.operation_id,
            action_commitment: self.action_commitment,
            recipe_digest: self.recipe_digest,
            nonce: self.nonce,
            evaluated_at: self.evaluated_at,
            entry: self.entry,
            state: map(self.state)?,
        })
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(
    tag = "protocol",
    content = "facts",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
enum ProtocolState {
    Mutation(MutationState),
    Acquisition(acquisition::AcquisitionState),
}

mod acquisition;
pub use acquisition::{
    AcquisitionClaim, AcquisitionSnapshot, AcquisitionStage, GatewayRecoveryReport,
    RecoveryDisposition, RecoverySnapshot, RecoverySourceFacts, ReservedAcquisition,
};
pub(crate) use acquisition::{AcquisitionEntryPermit, AcquisitionRequest, PrerequisiteResponse};

trait JournalProtocol: Clone + Sized {
    fn wrap(self) -> ProtocolState;
    fn extract(state: ProtocolState) -> Result<Self, GatewayAttemptError>;
    fn view(record: &Record<Self>) -> Result<AttemptView, GatewayAttemptError>;
    fn validate(record: &Record<Self>) -> Result<(), GatewayAttemptError>;
}

impl JournalProtocol for MutationState {
    fn wrap(self) -> ProtocolState {
        ProtocolState::Mutation(self)
    }
    fn extract(state: ProtocolState) -> Result<Self, GatewayAttemptError> {
        match state {
            ProtocolState::Mutation(state) => Ok(state),
            ProtocolState::Acquisition(_) => Err(GatewayAttemptError::BindingConflict),
        }
    }
    fn view(record: &Record<Self>) -> Result<AttemptView, GatewayAttemptError> {
        record.view()
    }
    fn validate(record: &Record<Self>) -> Result<(), GatewayAttemptError> {
        record.snapshot(false).map(|_| ())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MutationState {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    counters: Vec<CounterWire>,
    stage: GatewayAttemptStage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refusal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response_locator: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    observation_plan: Option<ObservationTemplate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    observation_match: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    observation_fact: Option<GatewayObservationFact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider_evidence: Option<EvidenceWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pre_entry: Option<PreEntryWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_evidence: Option<acquisition::RecoveryEvidenceLink>,
}

/// Private immutable evidence of the unique acknowledged grant. It does not
/// attest to a socket send and cannot be deserialized into a transport permit.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EntryAudit {
    revision: u64,
    authorization_started_at: u64,
    approval_canonical: String,
    pre_entry: Option<PreEntryWire>,
    schema: String,
    granted_at: u64,
    effect_id: String,
    dependencies: Vec<String>,
}

/// The fields no transition may change, in a fixed order.
#[derive(Serialize)]
struct FixedFields<'a> {
    schema: &'a str,
    binding_canonical: &'a str,
    approval_canonical: &'a str,
    namespace: &'a str,
    operation_id: &'a str,
    action_commitment: &'a str,
    recipe_digest: &'a str,
    nonce: &'a str,
    evaluated_at: u64,
    counters: &'a [CounterWire],
    observation_plan: Option<&'a ObservationTemplate>,
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, GatewayAttemptError> {
    serde_json::to_vec(value).map_err(|_| GatewayAttemptError::Corrupt)
}

impl Record {
    fn counters(&self) -> Result<Vec<GatewayCounterEntry>, GatewayAttemptError> {
        if self.state.counters.len() > MAX_COUNTERS {
            return Err(GatewayAttemptError::Corrupt);
        }
        let counters = self
            .state
            .counters
            .iter()
            .map(|entry| {
                Ok(GatewayCounterEntry {
                    kind: entry.kind,
                    counter: digest_bytes(&entry.counter)?,
                    slot: entry.slot,
                })
            })
            .collect::<Result<Vec<_>, GatewayAttemptError>>()?;
        if counters.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(GatewayAttemptError::Corrupt);
        }
        Ok(counters)
    }

    fn recovery_target(&self) -> Result<crate::effect::RecoveryReadTarget, GatewayAttemptError> {
        let stage_resolvable = match self.state.stage {
            GatewayAttemptStage::EntryGranted
            | GatewayAttemptStage::Unknown
            | GatewayAttemptStage::ResponseRecorded => true,
            GatewayAttemptStage::Reserved
            | GatewayAttemptStage::NotEntered
            | GatewayAttemptStage::Observed
            | GatewayAttemptStage::ObservedByProvider => false,
        };
        if !stage_resolvable {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        self.recovery_target_data()
    }

    /// The immutable observation contract also remains available after final
    /// evidence, so history can be checked without acquiring new authority.
    fn recovery_target_data(
        &self,
    ) -> Result<crate::effect::RecoveryReadTarget, GatewayAttemptError> {
        let binding = self.validate_header()?;
        let request = self
            .observation_request()
            .ok_or(GatewayAttemptError::InvalidTransition)?;
        let echo = self
            .state
            .observation_plan
            .as_ref()
            .filter(|plan| plan.echo_pointer.is_some())
            .map(|_| self.echo_token())
            .transpose()?;
        crate::effect::RecoveryReadTarget::from_journal(binding, request, echo)
            .map_err(|_| GatewayAttemptError::Corrupt)
    }

    fn echo_token(&self) -> Result<String, GatewayAttemptError> {
        let namespace =
            OperatorNamespace::parse(&self.namespace).map_err(|_| GatewayAttemptError::Corrupt)?;
        let operation_id = LogicalOperationId::parse(&self.operation_id)
            .map_err(|_| GatewayAttemptError::Corrupt)?;
        Ok(echo_token(
            &namespace,
            &operation_id,
            &digest_bytes(&self.action_commitment)?,
        ))
    }

    fn link(&self) -> Link {
        self.state
            .observation_plan
            .as_ref()
            .map_or(Link::None, ObservationTemplate::link)
    }

    /// The projection the translated transition rule inspects.
    fn view(&self) -> Result<AttemptView, GatewayAttemptError> {
        let reading = match (self.state.observation_match, self.state.observation_fact) {
            (None, None) => Reading::None,
            (Some(true), None) => Reading::Match,
            (Some(false), None) => Reading::Mismatch,
            (Some(false), Some(GatewayObservationFact::EchoMismatch)) => Reading::EchoMismatch,
            (Some(true) | None, Some(_)) => return Err(GatewayAttemptError::Corrupt),
        };
        let response = match (self.state.response_status, &self.state.response_digest) {
            (None, None) => Vec::new(),
            (Some(status), Some(digest)) => canonical(&(status, digest))?,
            _ => return Err(GatewayAttemptError::Corrupt),
        };
        Ok(AttemptView {
            protocol: transition::Protocol::Mutation,
            revision: self.revision,
            entry: self
                .entry
                .as_ref()
                .map(canonical)
                .transpose()?
                .unwrap_or_default(),
            fixed: canonical(&FixedFields {
                schema: &self.schema,
                binding_canonical: &self.binding_canonical,
                approval_canonical: &self.approval_canonical,
                namespace: &self.namespace,
                operation_id: &self.operation_id,
                action_commitment: &self.action_commitment,
                recipe_digest: &self.recipe_digest,
                nonce: &self.nonce,
                evaluated_at: self.evaluated_at,
                counters: &self.state.counters,
                observation_plan: self.state.observation_plan.as_ref(),
            })?,
            stage: self.state.stage.kernel(),
            refusal: self.state.refusal.is_some(),
            pre_entry: self
                .state
                .pre_entry
                .as_ref()
                .map(canonical)
                .transpose()?
                .unwrap_or_default(),
            response,
            locator: self
                .state
                .response_locator
                .as_ref()
                .map(canonical)
                .transpose()?
                .unwrap_or_default(),
            reading,
            evidence: self.state.provider_evidence.is_some(),
            observation: self.state.observation_plan.is_some(),
            link: self.link(),
        })
    }

    /// The read-back request of the stored plan and locator, when one can
    /// be built.
    fn observation_request(&self) -> Option<ClosedObservationRequest> {
        self.state
            .observation_plan
            .as_ref()?
            .request(self.state.response_locator.as_ref())
    }

    fn validate_reservations(
        &self,
        key: GatewayAttemptKey,
        bound: Option<&crate::bounds::BoundAdmission>,
        snapshots: &[Option<Vec<u8>>],
        now: u64,
    ) -> Result<(), GatewayAttemptError> {
        let counters = self.counters()?;
        let Some(bound) = bound else {
            return if counters.is_empty() && snapshots.is_empty() {
                Ok(())
            } else {
                Err(GatewayAttemptError::Corrupt)
            };
        };
        if counters.len() != bound.counts.len() + bound.sums.len()
            || snapshots.len() != counters.len()
            || bound.window_seconds == 0
            || bound.counts.iter().any(|bound| {
                counters
                    .iter()
                    .filter(|counter| {
                        counter.kind == GatewayCounterKind::Count && counter.counter == bound.key
                    })
                    .count()
                    != 1
            })
            || bound.sums.iter().any(|bound| {
                counters
                    .iter()
                    .filter(|counter| {
                        counter.kind == GatewayCounterKind::Sum && counter.counter == bound.key
                    })
                    .count()
                    != 1
            })
            || now >= bound.window_end
            || now / bound.window_seconds != bound.window_index
        {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        let claim = hex::encode(key.as_bytes());
        for (counter, bytes) in counters.iter().zip(snapshots) {
            let bytes = bytes.as_deref().ok_or(GatewayAttemptError::Corrupt)?;
            let valid = match counter.kind {
                GatewayCounterKind::Count => {
                    let slot: CountSlotRecord =
                        serde_json::from_slice(bytes).map_err(|_| GatewayAttemptError::Corrupt)?;
                    let limit = bound
                        .counts
                        .iter()
                        .find(|candidate| candidate.key == counter.counter)
                        .ok_or(GatewayAttemptError::Corrupt)?;
                    canonical(&slot)? == bytes
                        && slot.schema == COUNT_SLOT_SCHEMA
                        && slot.counter == hex::encode(counter.counter)
                        && slot.slot == counter.slot
                        && slot.slot < limit.capacity
                        && slot.namespace == self.namespace
                        && slot.operation_id == self.operation_id
                        && slot.claim == claim
                        && slot.window_seconds == bound.window_seconds
                        && slot.window_index == bound.window_index
                        && slot.window_end == bound.window_end
                }
                GatewayCounterKind::Sum => {
                    let slot: SumSlotRecord =
                        serde_json::from_slice(bytes).map_err(|_| GatewayAttemptError::Corrupt)?;
                    let limit = bound
                        .sums
                        .iter()
                        .find(|candidate| candidate.key == counter.counter)
                        .ok_or(GatewayAttemptError::Corrupt)?;
                    canonical(&slot)? == bytes
                        && slot.schema == SUM_SLOT_SCHEMA
                        && slot.counter == hex::encode(counter.counter)
                        && slot.slot == counter.slot
                        && slot.slot < limit.slots
                        && slot.namespace == self.namespace
                        && slot.operation_id == self.operation_id
                        && slot.claim == claim
                        && slot.window_seconds == bound.window_seconds
                        && slot.window_index == bound.window_index
                        && slot.window_end == bound.window_end
                        && slot.amount == bound.argument
                        && slot.amount <= slot.cumulative
                        && slot.cumulative <= limit.capacity
                }
            };
            if !valid {
                return Err(GatewayAttemptError::Corrupt);
            }
        }
        Ok(())
    }

    fn locator_valid(&self) -> bool {
        match (&self.state.response_locator, &self.state.observation_plan) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(locator), Some(plan)) => {
                plan.has_response_fields()
                    && locator.len() <= MAX_LOCATOR_VALUES
                    && locator
                        .values()
                        .all(|value| value.len() <= MAX_LOCATOR_VALUE_BYTES)
                    && plan.locator_fits(locator)
            }
        }
    }

    fn snapshot(&self, recovered: bool) -> Result<GatewayAttemptSnapshot, GatewayAttemptError> {
        if !self.validate_header()?.is_mutation() {
            return Err(GatewayAttemptError::Corrupt);
        }
        if self.schema != SCHEMA
            || self.nonce.len() != 32
            || !self
                .nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !self.state.refusal.as_deref().is_none_or(valid_code)
            || !self
                .state
                .observation_plan
                .as_ref()
                .is_none_or(ObservationTemplate::valid)
            || !self.locator_valid()
            || !transition::consistent(&self.view()?)
        {
            return Err(GatewayAttemptError::Corrupt);
        }
        let namespace =
            OperatorNamespace::parse(&self.namespace).map_err(|_| GatewayAttemptError::Corrupt)?;
        let operation_id = LogicalOperationId::parse(&self.operation_id)
            .map_err(|_| GatewayAttemptError::Corrupt)?;
        let action_commitment = digest_bytes(&self.action_commitment)?;
        let recipe_digest = digest_bytes(&self.recipe_digest)?;
        let response_digest = self
            .state
            .response_digest
            .as_deref()
            .map(digest_bytes)
            .transpose()?;
        if self
            .state
            .response_status
            .is_some_and(|status| !(100..=599).contains(&status))
        {
            return Err(GatewayAttemptError::Corrupt);
        }
        if let Some(link) = &self.state.recovery_evidence {
            link.validate(self)?;
        }
        let provider_evidence = match &self.state.provider_evidence {
            Some(wire) => {
                let locator = self
                    .observation_request()
                    .ok_or(GatewayAttemptError::Corrupt)?;
                Some(wire.decode(locator.url(), &self.echo_token()?)?)
            }
            None => None,
        };
        let pre_entry = self
            .entry
            .as_ref()
            .map_or(self.state.pre_entry.as_ref(), |entry| {
                entry.pre_entry.as_ref()
            })
            .map(PreEntryWire::decode)
            .transpose()?;
        Ok(GatewayAttemptSnapshot {
            revision: self.revision,
            namespace,
            operation_id,
            action_commitment,
            recipe_digest,
            evaluated_at: self.evaluated_at,
            stage: if recovered && self.state.stage == GatewayAttemptStage::EntryGranted {
                GatewayAttemptStage::Unknown
            } else {
                self.state.stage
            },
            refusal: self.state.refusal.clone(),
            counters: self.counters()?,
            response_status: self.state.response_status,
            response_digest,
            response_locator: self.state.response_locator.clone(),
            observation_match: self.state.observation_match,
            observation_fact: self.state.observation_fact,
            provider_evidence,
            pre_entry,
            recovery_evidence: self.state.recovery_evidence.clone(),
        })
    }
}

/// A stable code: 1–128 bytes of lowercase letters, digits, `.`, and `-`.
fn valid_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= MAX_REFUSAL_BYTES
        && code.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}

fn digest_bytes(value: &str) -> Result<[u8; 32], GatewayAttemptError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(GatewayAttemptError::Corrupt);
    }
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| GatewayAttemptError::Corrupt)?;
    Ok(bytes)
}

/// Closed durable claim errors. A replay never licenses another provider entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum GatewayAttemptError {
    /// A logical ID was already claimed, regardless of proof challenge or body.
    #[error("logical operation already claimed")]
    Replay,
    /// The logical operation exists with a different complete effect binding.
    #[error("logical operation binding conflict")]
    BindingConflict,
    /// The state directory is not a private, normalized local directory.
    #[error("unsafe attempt directory")]
    UnsafeDirectory,
    /// Existing state is incomplete, obsolete, or contradictory; fail closed.
    #[error("corrupt attempt record")]
    Corrupt,
    /// Storage or synchronization failed; an in-flight effect may be unknown.
    #[error("attempt store unavailable")]
    Unavailable,
    /// A claimed attempt attempted an invalid transition.
    #[error("invalid attempt transition")]
    InvalidTransition,
    /// Another gateway process advanced this attempt first; nothing was
    /// recorded by this caller.
    #[error("attempt advanced concurrently")]
    Conflict,
}

/// Why a directory is not private to this process's effective UID.
#[derive(Debug, Error)]
pub enum PrivateDirectoryError {
    /// The path is relative or holds a `.` or `..` component.
    #[error("not an absolute path free of `.` and `..` components")]
    NotNormalizedAbsolute,
    /// The directory or its canonical form could not be read.
    #[error("{0}")]
    Unavailable(std::io::Error),
    /// The path differs from its canonical form: it passes through a
    /// symbolic link, as `/tmp` and `/var` do on macOS.
    #[error("not canonical; it resolves to {}", canonical.display())]
    NotCanonical {
        /// The path the directory resolves to.
        canonical: PathBuf,
    },
    /// The path names something other than a directory.
    #[error("not a directory")]
    NotDirectory,
    /// The mode grants group or other permission bits.
    #[error("mode {mode:04o} grants group or other access; it must be 0700 or narrower")]
    Shared {
        /// The permission bits, without the file type.
        mode: u32,
    },
    /// Another UID owns the directory.
    #[error("owned by UID {uid}, not by the expected owner")]
    Foreign {
        /// The owner's UID.
        uid: u32,
    },
}

fn is_normalized_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

/// Checks, without creating anything, that `path` is an existing directory
/// private to this process's effective UID: absolute and free of `.` and
/// `..`, equal to its canonical form, a directory, owned by the effective
/// UID, and with no group or other permission bits.
///
/// # Errors
/// Returns the first check that fails. The canonical form is checked before
/// the file type, so a path through a symbolic link reports the path it
/// resolves to.
pub fn check_private_directory(path: &Path) -> Result<(), PrivateDirectoryError> {
    #[cfg(unix)]
    let owner = rustix::process::geteuid().as_raw();
    #[cfg(not(unix))]
    let owner = 0;
    check_private_directory_owned_by(path, owner)
}

/// [`check_private_directory`] with an explicit owner, for a privileged
/// caller checking a directory another UID must own.
///
/// # Errors
/// As [`check_private_directory`].
pub fn check_private_directory_owned_by(
    path: &Path,
    owner: u32,
) -> Result<(), PrivateDirectoryError> {
    if !is_normalized_absolute(path) {
        return Err(PrivateDirectoryError::NotNormalizedAbsolute);
    }
    let metadata = fs::symlink_metadata(path).map_err(PrivateDirectoryError::Unavailable)?;
    match fs::canonicalize(path) {
        Ok(canonical) if canonical != path => {
            return Err(PrivateDirectoryError::NotCanonical { canonical });
        }
        Ok(_) => {}
        Err(_) if !metadata.file_type().is_dir() => {
            return Err(PrivateDirectoryError::NotDirectory);
        }
        Err(error) => return Err(PrivateDirectoryError::Unavailable(error)),
    }
    if !metadata.file_type().is_dir() {
        return Err(PrivateDirectoryError::NotDirectory);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let mode = metadata.permissions().mode() & 0o7777;
        if mode & 0o077 != 0 {
            return Err(PrivateDirectoryError::Shared { mode });
        }
        if metadata.uid() != owner {
            return Err(PrivateDirectoryError::Foreign {
                uid: metadata.uid(),
            });
        }
    }
    #[cfg(not(unix))]
    let _ = owner;
    Ok(())
}

/// Storage key of one gateway record.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GatewayAttemptKey([u8; 32]);

impl GatewayAttemptKey {
    /// Derives a replay key from installed partition/epoch, namespace and
    /// operation. The effect digest is deliberately excluded.
    ///
    /// # Errors
    /// Refuses invalid installed policy or an encoding failure.
    pub fn for_operation(
        policy: &EffectPolicy,
        namespace: &OperatorNamespace,
        operation_id: &LogicalOperationId,
    ) -> Result<Self, GatewayAttemptError> {
        policy
            .operation_key(namespace, operation_id)
            .map(Self)
            .map_err(|_| GatewayAttemptError::Corrupt)
    }

    /// Uses `bytes`, a key derived under another record kind's hash domain.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One record to insert.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayRecordEntry {
    /// The record kind.
    pub kind: GatewayRecordKind,
    /// The record key.
    pub key: GatewayAttemptKey,
    /// The opaque record bytes.
    pub record: Vec<u8>,
    /// Gateway-clock seconds after which a slot may be swept; present
    /// exactly for slot kinds.
    pub expires_at: Option<u64>,
}

impl GatewayRecordEntry {
    fn mechanism(&self) -> auths_stores::GatewayRecordEntry {
        auths_stores::GatewayRecordEntry {
            kind: self.kind,
            key: self.key.0,
            record: self.record.clone(),
            expires_at: self.expires_at,
        }
    }
}

fn validate_batch(entries: &[GatewayRecordEntry]) -> Result<(), GatewayAttemptError> {
    let mechanism: Vec<_> = entries.iter().map(GatewayRecordEntry::mechanism).collect();
    auths_stores::validate_gateway_batch(&mechanism).map_err(postgres_error)
}

/// Result of an all-or-none batch insert.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayInsert {
    /// Every entry was inserted by this call; no other caller can.
    Inserted,
    /// The entry at `index` already existed, so nothing was inserted.
    Exists {
        /// The index, in the caller's order, of an entry whose key existed.
        index: usize,
    },
}

/// One bounded native decision over a snapshot held behind the adapter's
/// writer fence. It must not perform custody, provider or nested store I/O.
/// The adapter invokes it at most once; returning bytes does not grant entry.
pub type GatewayFenceDecision<'a> =
    dyn FnMut(&[Option<Vec<u8>>]) -> Result<Vec<u8>, GatewayAttemptError> + 'a;

fn fence_keys(
    keys: &[(GatewayRecordKind, GatewayAttemptKey)],
) -> Result<Vec<(GatewayRecordKind, [u8; 32])>, GatewayAttemptError> {
    if keys.is_empty() || keys.len() > auths_stores::MAX_GATEWAY_FENCE_RECORDS {
        return Err(GatewayAttemptError::Corrupt);
    }
    let keys: Vec<_> = keys.iter().map(|(kind, key)| (*kind, key.0)).collect();
    auths_stores::validate_gateway_fence(&keys).map_err(postgres_error)?;
    Ok(keys)
}

/// Durable storage of opaque gateway records of seven closed kinds.
/// Implementations never interpret the bytes.
///
/// Every implementation must pass the same conformance suite: one winner per
/// key across processes, all-or-none batches, no lost replacement, bounded
/// sweeps of expired slots only, and fail-closed reads that never report
/// unreadable state as absent.
pub trait GatewayAttemptStore: Send + Sync {
    /// Atomically inserts a fixed batch after a native decision over dependencies
    /// under the common writer fence. The decision replaces only the first
    /// record's bytes. Existing keys return without a decision or new charges.
    ///
    /// # Errors
    /// Refuses overlapping/oversized sets, missing/corrupt dependencies as
    /// interpreted by the decision, failed authorization, deadlines or ambiguous
    /// durability. The combined read/write set is at most 64 records.
    fn fenced_insert_all(
        &self,
        entries: &[GatewayRecordEntry],
        dependencies: &[(GatewayRecordKind, GatewayAttemptKey)],
        decide: &mut GatewayFenceDecision<'_>,
    ) -> Result<GatewayInsert, GatewayAttemptError>;

    /// Reads the bounded set while excluding every participating writer, calls
    /// `decide` once, and durably replaces the first record. This is a storage
    /// mechanism; the gateway owns validation and the one-use permit.
    ///
    /// # Errors
    /// Refuses invalid sets, missing target, unavailable locking, corrupt
    /// state, decision failures and ambiguous durability. No automatic retry.
    fn fenced_replace(
        &self,
        keys: &[(GatewayRecordKind, GatewayAttemptKey)],
        decide: &mut GatewayFenceDecision<'_>,
    ) -> Result<(), GatewayAttemptError>;

    /// Inserts every entry, or none when any key already exists.
    ///
    /// # Errors
    /// Returns [`GatewayAttemptError::Corrupt`] for an entry outside its
    /// bounds and [`GatewayAttemptError::Unavailable`] when storage fails;
    /// nothing is inserted in either case.
    fn insert_all(
        &self,
        entries: &[GatewayRecordEntry],
    ) -> Result<GatewayInsert, GatewayAttemptError>;

    /// Inserts one entry only when its key has never been stored.
    ///
    /// # Errors
    /// Returns [`GatewayAttemptError::Replay`] when the key already exists,
    /// including a record left by a crashed claim.
    fn insert(&self, entry: &GatewayRecordEntry) -> Result<(), GatewayAttemptError> {
        match self.insert_all(std::slice::from_ref(entry))? {
            GatewayInsert::Inserted => Ok(()),
            GatewayInsert::Exists { .. } => Err(GatewayAttemptError::Replay),
        }
    }

    /// Loads the record of `kind` stored under `key`.
    ///
    /// # Errors
    /// Returns [`GatewayAttemptError::Corrupt`] for unreadable or oversized
    /// state; it is never reported as an absent key.
    fn load(
        &self,
        kind: GatewayRecordKind,
        key: &GatewayAttemptKey,
    ) -> Result<Option<Vec<u8>>, GatewayAttemptError>;

    /// Replaces the record of `kind` under `key` with `next` only while it
    /// still holds exactly `current`. Slots are insert-only.
    ///
    /// # Errors
    /// Returns [`GatewayAttemptError::Conflict`] when another writer replaced
    /// it first, and [`GatewayAttemptError::InvalidTransition`] for a slot.
    fn replace(
        &self,
        kind: GatewayRecordKind,
        key: &GatewayAttemptKey,
        current: &[u8],
        next: &[u8],
    ) -> Result<(), GatewayAttemptError>;

    /// Deletes at most `limit` count and sum slots whose expiry is at or
    /// before `now`, and returns how many were deleted.
    ///
    /// # Errors
    /// Returns [`GatewayAttemptError::Unavailable`] when storage fails.
    fn sweep_expired(&self, now: u64, limit: usize) -> Result<usize, GatewayAttemptError>;

    /// Lists at most `limit` keys of stored attempts, in key order. A key is
    /// a digest and names no operation.
    ///
    /// # Errors
    /// Returns [`GatewayAttemptError::Unavailable`] when storage fails.
    fn attempt_keys(&self, limit: usize) -> Result<Vec<GatewayAttemptKey>, GatewayAttemptError>;
}

/// Atomic file store for one host. This is not a multi-host store and does
/// not establish credential isolation by itself.
///
/// Files are named by kind (`claim-`, `slot-`, `sum-`, `conn-`, `commission-`, then the hex
/// key and `.json`). Every mutation holds a host-wide exclusive `flock` on
/// `.replace.lock` and every load holds it shared. A batch first writes
/// `.batch.json` listing each target and its bytes, then creates the
/// targets, then deletes the batch file; a batch file found later means the
/// batch never returned, so its targets are deleted.
pub struct FileGatewayAttemptStore {
    root: PathBuf,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BatchFile {
    schema: String,
    targets: Vec<BatchTarget>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BatchTarget {
    file: String,
    bytes_b64: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SlotFile {
    schema: String,
    expires_at: u64,
    record_b64: String,
}

/// Where a conformance test stops a batch, to leave the state a crash at
/// that step would leave. Production batches never stop early.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BatchCrash {
    /// After the batch file is durable and before any target exists.
    AfterBatchFile,
    /// After this many targets exist.
    AfterTargets(usize),
    /// After every target exists and before the batch file is deleted.
    BeforeBatchDelete,
}

impl FileGatewayAttemptStore {
    /// Opens or creates an owner-private directory, retaining every record,
    /// and rolls back a batch a crashed process left.
    ///
    /// # Errors
    /// Rejects symlinks, broad permissions, foreign ownership, a malformed
    /// batch file, and I/O errors.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, GatewayAttemptError> {
        let root = root.into();
        if !is_normalized_absolute(&root) {
            return Err(GatewayAttemptError::UnsafeDirectory);
        }
        if !root.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&root)
                    .map_err(|_| GatewayAttemptError::Unavailable)?;
            }
            #[cfg(not(unix))]
            return Err(GatewayAttemptError::UnsafeDirectory);
        }
        check_private_directory(&root).map_err(|error| match error {
            PrivateDirectoryError::Unavailable(_) => GatewayAttemptError::Unavailable,
            _ => GatewayAttemptError::UnsafeDirectory,
        })?;
        let store = Self { root };
        store.recover()?;
        Ok(store)
    }

    fn file_name(kind: GatewayRecordKind, key: &GatewayAttemptKey) -> String {
        let prefix = match kind {
            GatewayRecordKind::Attempt => "claim-",
            GatewayRecordKind::CountSlot => "slot-",
            GatewayRecordKind::SumSlot => "sum-",
            GatewayRecordKind::Connection => "conn-",
            GatewayRecordKind::CommissioningBudget => "commission-",
            GatewayRecordKind::EffectConfiguration => "config-",
            GatewayRecordKind::EffectAllocation => "allocation-",
        };
        format!("{prefix}{}.json", hex::encode(key.as_bytes()))
    }

    fn path_for(&self, kind: GatewayRecordKind, key: &GatewayAttemptKey) -> PathBuf {
        self.root.join(Self::file_name(kind, key))
    }

    fn read_file(path: &Path, maximum: usize) -> Result<Option<Vec<u8>>, GatewayAttemptError> {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(GatewayAttemptError::Unavailable),
        };
        // Bound allocation before decoding, even if a record or rollback file
        // has been replaced by an oversized file on disk.
        let limit = u64::try_from(maximum)
            .ok()
            .and_then(|n| n.checked_add(1))
            .ok_or(GatewayAttemptError::Corrupt)?;
        let mut bytes = Vec::new();
        file.take(limit)
            .read_to_end(&mut bytes)
            .map_err(|_| GatewayAttemptError::Unavailable)?;
        if bytes.is_empty() || bytes.len() > maximum {
            return Err(GatewayAttemptError::Corrupt);
        }
        Ok(Some(bytes))
    }

    /// The bytes a record's file holds: the record itself, or for a slot
    /// the record wrapped with its expiry.
    fn file_bytes(entry: &GatewayRecordEntry) -> Result<Vec<u8>, GatewayAttemptError> {
        match entry.expires_at {
            None => Ok(entry.record.clone()),
            Some(expires_at) => canonical(&SlotFile {
                schema: SLOT_FILE_SCHEMA.to_owned(),
                expires_at,
                record_b64: Base64::encode_string(&entry.record),
            }),
        }
    }

    fn decode_slot(bytes: &[u8]) -> Result<(u64, Vec<u8>), GatewayAttemptError> {
        let slot: SlotFile =
            serde_json::from_slice(bytes).map_err(|_| GatewayAttemptError::Corrupt)?;
        let record =
            Base64::decode_vec(&slot.record_b64).map_err(|_| GatewayAttemptError::Corrupt)?;
        if slot.schema != SLOT_FILE_SCHEMA || record.is_empty() || record.len() > MAX_RECORD_BYTES {
            return Err(GatewayAttemptError::Corrupt);
        }
        Ok((slot.expires_at, record))
    }

    fn pending(&self, bytes: &[u8]) -> Result<NamedTempFile, GatewayAttemptError> {
        let mut pending =
            NamedTempFile::new_in(&self.root).map_err(|_| GatewayAttemptError::Unavailable)?;
        pending
            .write_all(bytes)
            .and_then(|()| pending.as_file().sync_all())
            .map_err(|_| GatewayAttemptError::Unavailable)?;
        Ok(pending)
    }

    fn load_locked(
        &self,
        kind: GatewayRecordKind,
        key: &GatewayAttemptKey,
    ) -> Result<Option<Vec<u8>>, GatewayAttemptError> {
        let path = self.path_for(kind, key);
        if kind.expires() {
            Self::read_file(&path, MAX_SLOT_FILE_BYTES)?
                .map(|bytes| Self::decode_slot(&bytes).map(|(_, record)| record))
                .transpose()
        } else {
            Self::read_file(&path, MAX_RECORD_BYTES)
        }
    }

    fn lock(&self, operation: rustix::fs::FlockOperation) -> Result<File, GatewayAttemptError> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let lock = options
            .open(self.root.join(LOCK_FILE))
            .map_err(|_| GatewayAttemptError::Unavailable)?;
        let nonblocking = match operation {
            rustix::fs::FlockOperation::LockExclusive => {
                rustix::fs::FlockOperation::NonBlockingLockExclusive
            }
            rustix::fs::FlockOperation::LockShared => {
                rustix::fs::FlockOperation::NonBlockingLockShared
            }
            _ => return Err(GatewayAttemptError::Unavailable),
        };
        let started = Instant::now();
        loop {
            match rustix::fs::flock(&lock, nonblocking) {
                Ok(()) => return Ok(lock),
                Err(error)
                    if error == rustix::io::Errno::WOULDBLOCK
                        || error == rustix::io::Errno::INTR => {}
                Err(_) => return Err(GatewayAttemptError::Unavailable),
            }
            let Some(remaining) = auths_stores::GATEWAY_LOCK_TIMEOUT.checked_sub(started.elapsed())
            else {
                return Err(GatewayAttemptError::Unavailable);
            };
            if remaining.is_zero() {
                return Err(GatewayAttemptError::Unavailable);
            }
            std::thread::sleep(remaining.min(std::time::Duration::from_millis(5)));
        }
    }

    /// Serializes mutations across every process on this host.
    fn exclusive(&self) -> Result<File, GatewayAttemptError> {
        let lock = self.lock(rustix::fs::FlockOperation::LockExclusive)?;
        self.recover_locked()?;
        Ok(lock)
    }

    /// Excludes mutations for the duration of a load. A batch file seen
    /// under the shared lock was left by a crashed process, since every
    /// batch holds the exclusive lock until its file is gone; it is rolled
    /// back under the exclusive lock before the load proceeds.
    fn shared(&self) -> Result<File, GatewayAttemptError> {
        for _ in 0..MAX_RECOVERY_ROUNDS {
            let lock = self.lock(rustix::fs::FlockOperation::LockShared)?;
            if !self.root.join(BATCH_FILE).exists() {
                return Ok(lock);
            }
            drop(lock);
            let _exclusive = self.lock(rustix::fs::FlockOperation::LockExclusive)?;
            self.recover_locked()?;
        }
        Err(GatewayAttemptError::Unavailable)
    }

    /// Rolls back a batch a crashed process left, under the exclusive lock.
    fn recover(&self) -> Result<(), GatewayAttemptError> {
        if self.root.join(BATCH_FILE).exists() {
            let _lock = self.lock(rustix::fs::FlockOperation::LockExclusive)?;
            self.recover_locked()?;
        }
        Ok(())
    }

    /// Deletes each listed target whose bytes equal the listed bytes, then
    /// the batch file. The caller holds the exclusive lock.
    fn recover_locked(&self) -> Result<(), GatewayAttemptError> {
        let path = self.root.join(BATCH_FILE);
        let Some(bytes) = Self::read_file(&path, MAX_BATCH_FILE_BYTES)? else {
            return Ok(());
        };
        let batch: BatchFile =
            serde_json::from_slice(&bytes).map_err(|_| GatewayAttemptError::Corrupt)?;
        if batch.schema != BATCH_SCHEMA || batch.targets.len() > MAX_BATCH_ENTRIES {
            return Err(GatewayAttemptError::Corrupt);
        }
        for target in &batch.targets {
            if !valid_file_name(&target.file) {
                return Err(GatewayAttemptError::Corrupt);
            }
            let listed =
                Base64::decode_vec(&target.bytes_b64).map_err(|_| GatewayAttemptError::Corrupt)?;
            let target_path = self.root.join(&target.file);
            if Self::read_file(&target_path, MAX_SLOT_FILE_BYTES)?.as_deref() == Some(&listed) {
                fs::remove_file(&target_path).map_err(|_| GatewayAttemptError::Unavailable)?;
            }
        }
        sync_directory(&self.root)?;
        fs::remove_file(&path).map_err(|_| GatewayAttemptError::Unavailable)?;
        sync_directory(&self.root)
    }

    fn insert_batch(
        &self,
        entries: &[GatewayRecordEntry],
        crash: Option<BatchCrash>,
    ) -> Result<GatewayInsert, GatewayAttemptError> {
        validate_batch(entries)?;
        let _lock = self.exclusive()?;
        self.insert_batch_locked(entries, crash, None)
    }

    /// The caller holds the writer fence, including crash-batch recovery.
    fn insert_batch_locked(
        &self,
        entries: &[GatewayRecordEntry],
        crash: Option<BatchCrash>,
        started: Option<Instant>,
    ) -> Result<GatewayInsert, GatewayAttemptError> {
        validate_batch(entries)?;
        let files = entries
            .iter()
            .map(|entry| {
                Ok((
                    Self::file_name(entry.kind, &entry.key),
                    Self::file_bytes(entry)?,
                ))
            })
            .collect::<Result<Vec<_>, GatewayAttemptError>>()?;
        for (index, (name, _)) in files.iter().enumerate() {
            if self.root.join(name).exists() {
                return Ok(GatewayInsert::Exists { index });
            }
        }
        let batch = canonical(&BatchFile {
            schema: BATCH_SCHEMA.to_owned(),
            targets: files
                .iter()
                .map(|(name, bytes)| BatchTarget {
                    file: name.clone(),
                    bytes_b64: Base64::encode_string(bytes),
                })
                .collect(),
        })?;
        admission_deadline(started)?;
        self.pending(&batch)?
            .persist_noclobber(self.root.join(BATCH_FILE))
            .map_err(|_| GatewayAttemptError::Unavailable)?;
        sync_directory(&self.root)?;
        if crash == Some(BatchCrash::AfterBatchFile) {
            return Ok(GatewayInsert::Inserted);
        }
        for (index, (name, bytes)) in files.iter().enumerate() {
            if crash == Some(BatchCrash::AfterTargets(index)) {
                sync_directory(&self.root)?;
                return Ok(GatewayInsert::Inserted);
            }
            admission_deadline(started)?;
            self.pending(bytes)?
                .persist_noclobber(self.root.join(name))
                .map_err(|_| GatewayAttemptError::Unavailable)?;
        }
        sync_directory(&self.root)?;
        if crash == Some(BatchCrash::BeforeBatchDelete) {
            return Ok(GatewayInsert::Inserted);
        }
        admission_deadline(started)?;
        fs::remove_file(self.root.join(BATCH_FILE))
            .map_err(|_| GatewayAttemptError::Unavailable)?;
        sync_directory(&self.root)?;
        Ok(GatewayInsert::Inserted)
    }

    /// Runs a batch that stops where a crash at `crash` would stop it.
    #[cfg(test)]
    pub(crate) fn insert_all_until(
        &self,
        entries: &[GatewayRecordEntry],
        crash: BatchCrash,
    ) -> Result<(), GatewayAttemptError> {
        self.insert_batch(entries, Some(crash)).map(drop)
    }
}

/// A record or batch file name this store writes.
fn valid_file_name(name: &str) -> bool {
    let Some(rest) = [
        "claim-",
        "slot-",
        "sum-",
        "conn-",
        "commission-",
        "config-",
        "allocation-",
    ]
    .iter()
    .find_map(|prefix| name.strip_prefix(prefix)) else {
        return false;
    };
    rest.strip_suffix(".json").is_some_and(|key| {
        key.len() == 64
            && key
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn admission_deadline(started: Option<Instant>) -> Result<(), GatewayAttemptError> {
    if started.is_some_and(|started| started.elapsed() >= auths_stores::GATEWAY_FENCE_DEADLINE) {
        return Err(GatewayAttemptError::Unavailable);
    }
    Ok(())
}

impl GatewayAttemptStore for FileGatewayAttemptStore {
    fn fenced_insert_all(
        &self,
        entries: &[GatewayRecordEntry],
        dependencies: &[(GatewayRecordKind, GatewayAttemptKey)],
        decide: &mut GatewayFenceDecision<'_>,
    ) -> Result<GatewayInsert, GatewayAttemptError> {
        validate_batch(entries)?;
        let mut keys: Vec<_> = entries
            .iter()
            .map(|entry| (entry.kind, entry.key))
            .collect();
        keys.extend_from_slice(dependencies);
        fence_keys(&keys)?;
        let _lock = self.exclusive()?;
        let started = Some(Instant::now());
        for (index, entry) in entries.iter().enumerate() {
            admission_deadline(started)?;
            if self.load_locked(entry.kind, &entry.key)?.is_some() {
                return Ok(GatewayInsert::Exists { index });
            }
        }
        let snapshots = dependencies
            .iter()
            .map(|(kind, key)| {
                admission_deadline(started)?;
                self.load_locked(*kind, key)
            })
            .collect::<Result<Vec<_>, GatewayAttemptError>>()?;
        admission_deadline(started)?;
        let next = decide(&snapshots)?;
        let mut entries = entries.to_vec();
        entries[0].record = next;
        self.insert_batch_locked(&entries, None, started)
    }

    fn fenced_replace(
        &self,
        keys: &[(GatewayRecordKind, GatewayAttemptKey)],
        decide: &mut GatewayFenceDecision<'_>,
    ) -> Result<(), GatewayAttemptError> {
        fence_keys(keys)?;
        let _lock = self.exclusive()?;
        let started = Instant::now();
        let records = keys
            .iter()
            .map(|(kind, key)| {
                if started.elapsed() >= auths_stores::GATEWAY_FENCE_DEADLINE {
                    return Err(GatewayAttemptError::Unavailable);
                }
                self.load_locked(*kind, key)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if records[0].is_none() {
            return Err(GatewayAttemptError::Conflict);
        }
        if started.elapsed() >= auths_stores::GATEWAY_FENCE_DEADLINE {
            return Err(GatewayAttemptError::Unavailable);
        }
        let next = decide(&records)?;
        if next.is_empty() || next.len() > MAX_RECORD_BYTES {
            return Err(GatewayAttemptError::Corrupt);
        }
        let pending = self.pending(&next)?;
        if started.elapsed() >= auths_stores::GATEWAY_FENCE_DEADLINE {
            return Err(GatewayAttemptError::Unavailable);
        }
        pending
            .persist(self.path_for(keys[0].0, &keys[0].1))
            .map_err(|_| GatewayAttemptError::Unavailable)?;
        sync_directory(&self.root)
    }

    fn attempt_keys(&self, limit: usize) -> Result<Vec<GatewayAttemptKey>, GatewayAttemptError> {
        self.claimed_keys(limit)
    }

    fn insert_all(
        &self,
        entries: &[GatewayRecordEntry],
    ) -> Result<GatewayInsert, GatewayAttemptError> {
        self.insert_batch(entries, None)
    }

    fn insert(&self, entry: &GatewayRecordEntry) -> Result<(), GatewayAttemptError> {
        validate_batch(std::slice::from_ref(entry))?;
        let bytes = Self::file_bytes(entry)?;
        let _lock = self.exclusive()?;
        match self
            .pending(&bytes)?
            .persist_noclobber(self.path_for(entry.kind, &entry.key))
        {
            Ok(_) => sync_directory(&self.root),
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(GatewayAttemptError::Replay)
            }
            Err(_) => Err(GatewayAttemptError::Unavailable),
        }
    }

    fn load(
        &self,
        kind: GatewayRecordKind,
        key: &GatewayAttemptKey,
    ) -> Result<Option<Vec<u8>>, GatewayAttemptError> {
        let _lock = self.shared()?;
        self.load_locked(kind, key)
    }

    fn replace(
        &self,
        kind: GatewayRecordKind,
        key: &GatewayAttemptKey,
        current: &[u8],
        next: &[u8],
    ) -> Result<(), GatewayAttemptError> {
        if kind.expires() {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        if next.is_empty() || next.len() > MAX_RECORD_BYTES {
            return Err(GatewayAttemptError::Corrupt);
        }
        let path = self.path_for(kind, key);
        let _lock = self.exclusive()?;
        if Self::read_file(&path, MAX_RECORD_BYTES)?.as_deref() != Some(current) {
            return Err(GatewayAttemptError::Conflict);
        }
        self.pending(next)?
            .persist(&path)
            .map_err(|_| GatewayAttemptError::Unavailable)?;
        sync_directory(&self.root)
    }

    fn sweep_expired(&self, now: u64, limit: usize) -> Result<usize, GatewayAttemptError> {
        let _lock = self.exclusive()?;
        let mut names: Vec<String> = fs::read_dir(&self.root)
            .map_err(|_| GatewayAttemptError::Unavailable)?
            .map(|entry| {
                entry
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .map_err(|_| GatewayAttemptError::Unavailable)
            })
            .collect::<Result<Vec<_>, _>>()?;
        names.retain(|name| {
            (name.starts_with("slot-") || name.starts_with("sum-")) && valid_file_name(name)
        });
        names.sort_unstable();
        let mut deleted = 0;
        for name in names {
            if deleted >= limit {
                break;
            }
            let path = self.root.join(&name);
            let Some(bytes) = Self::read_file(&path, MAX_SLOT_FILE_BYTES)? else {
                continue;
            };
            if Self::decode_slot(&bytes)?.0 <= now {
                fs::remove_file(&path).map_err(|_| GatewayAttemptError::Unavailable)?;
                deleted += 1;
            }
        }
        if deleted > 0 {
            sync_directory(&self.root)?;
        }
        Ok(deleted)
    }
}

/// The multi-host store, not yet production-qualified: records live in the
/// lifecycle database under the same TLS, pooling, and schema contract as
/// lifecycle records.
///
/// The pooled client blocks on its own runtime, so it is connected, used,
/// and dropped only off the async executor.
pub struct PostgresGatewayAttemptStore {
    store: Option<Arc<PostgresLifecycleStore>>,
}

impl PostgresGatewayAttemptStore {
    /// Uses an already connected lifecycle store, which may be shared with
    /// lifecycle work in the same process.
    #[must_use]
    pub const fn new(store: Arc<PostgresLifecycleStore>) -> Self {
        Self { store: Some(store) }
    }

    fn store(&self) -> Result<&PostgresLifecycleStore, GatewayAttemptError> {
        self.store
            .as_deref()
            .ok_or(GatewayAttemptError::Unavailable)
    }
}

impl Drop for PostgresGatewayAttemptStore {
    fn drop(&mut self) {
        if let Some(store) = self.store.take() {
            let _ = std::thread::spawn(move || drop(store)).join();
        }
    }
}

impl FileGatewayAttemptStore {
    fn claimed_keys(&self, limit: usize) -> Result<Vec<GatewayAttemptKey>, GatewayAttemptError> {
        let _lock = self.shared()?;
        let mut keys = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(|_| GatewayAttemptError::Unavailable)? {
            let name = entry
                .map_err(|_| GatewayAttemptError::Unavailable)?
                .file_name();
            let key = name
                .to_str()
                .filter(|name| valid_file_name(name))
                .and_then(|name| name.strip_prefix("claim-"))
                .and_then(|name| name.strip_suffix(".json"));
            if let Some(key) = key {
                let mut bytes = [0_u8; 32];
                hex::decode_to_slice(key, &mut bytes).map_err(|_| GatewayAttemptError::Corrupt)?;
                keys.push(GatewayAttemptKey(bytes));
            }
        }
        keys.sort_unstable();
        keys.truncate(limit);
        Ok(keys)
    }
}

impl GatewayAttemptStore for PostgresGatewayAttemptStore {
    fn fenced_insert_all(
        &self,
        entries: &[GatewayRecordEntry],
        dependencies: &[(GatewayRecordKind, GatewayAttemptKey)],
        decide: &mut GatewayFenceDecision<'_>,
    ) -> Result<GatewayInsert, GatewayAttemptError> {
        let mechanism: Vec<_> = entries.iter().map(GatewayRecordEntry::mechanism).collect();
        let dependencies: Vec<_> = dependencies
            .iter()
            .map(|(kind, key)| (*kind, key.0))
            .collect();
        match self
            .store()?
            .fenced_gateway_insert(&mechanism, &dependencies, decide)?
        {
            GatewayRecordInsert::Inserted => Ok(GatewayInsert::Inserted),
            GatewayRecordInsert::Exists { index } => Ok(GatewayInsert::Exists { index }),
        }
    }

    fn fenced_replace(
        &self,
        keys: &[(GatewayRecordKind, GatewayAttemptKey)],
        decide: &mut GatewayFenceDecision<'_>,
    ) -> Result<(), GatewayAttemptError> {
        let keys = fence_keys(keys)?;
        self.store()?.fenced_gateway_replace(&keys, decide)
    }

    fn attempt_keys(&self, limit: usize) -> Result<Vec<GatewayAttemptKey>, GatewayAttemptError> {
        self.store()?
            .list_gateway_record_keys(GatewayRecordKind::Attempt, limit)
            .map(|keys| keys.into_iter().map(GatewayAttemptKey).collect())
            .map_err(postgres_error)
    }

    fn insert_all(
        &self,
        entries: &[GatewayRecordEntry],
    ) -> Result<GatewayInsert, GatewayAttemptError> {
        let mechanism: Vec<_> = entries.iter().map(GatewayRecordEntry::mechanism).collect();
        match self.store()?.insert_gateway_records(&mechanism) {
            Ok(GatewayRecordInsert::Inserted) => Ok(GatewayInsert::Inserted),
            Ok(GatewayRecordInsert::Exists { index }) => Ok(GatewayInsert::Exists { index }),
            Err(error) => Err(postgres_error(error)),
        }
    }

    fn load(
        &self,
        kind: GatewayRecordKind,
        key: &GatewayAttemptKey,
    ) -> Result<Option<Vec<u8>>, GatewayAttemptError> {
        self.store()?
            .load_gateway_record(kind, key.as_bytes())
            .map_err(postgres_error)
    }

    fn replace(
        &self,
        kind: GatewayRecordKind,
        key: &GatewayAttemptKey,
        current: &[u8],
        next: &[u8],
    ) -> Result<(), GatewayAttemptError> {
        if kind.expires() {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        self.store()?
            .replace_gateway_record(kind, key.as_bytes(), current, next)
            .map_err(postgres_error)
    }

    fn sweep_expired(&self, now: u64, limit: usize) -> Result<usize, GatewayAttemptError> {
        self.store()?
            .sweep_expired_gateway_records(now, limit)
            .map_err(postgres_error)
    }
}

impl From<StoreError> for GatewayAttemptError {
    fn from(error: StoreError) -> Self {
        postgres_error(error)
    }
}

const fn postgres_error(error: StoreError) -> GatewayAttemptError {
    match error {
        StoreError::Conflict => GatewayAttemptError::Conflict,
        StoreError::Corrupt
        | StoreError::LimitExceeded
        | StoreError::SchemaMismatch
        | StoreError::InvalidAcknowledgement
        | StoreError::Rejected(_) => GatewayAttemptError::Corrupt,
        StoreError::Unavailable | StoreError::PoolExhausted | StoreError::Timeout => {
            GatewayAttemptError::Unavailable
        }
    }
}

/// Runs one blocking store operation off the async executor. The pooled
/// `PostgreSQL` client must never block an executor thread.
async fn blocking<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, GatewayAttemptError> + Send + 'static,
) -> Result<T, GatewayAttemptError> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| GatewayAttemptError::Unavailable)?
}

/// A fresh `reserved` claim record for `request`, with a random nonce and
/// no counters.
fn claim_record(
    request: &ClosedProviderRequest,
    binding: &EffectBinding,
    approval: &ExactEffectApproval,
    evaluated_at: u64,
) -> Result<Record, GatewayAttemptError> {
    let record = Record::new(
        binding,
        approval,
        evaluated_at,
        MutationState {
            counters: Vec::new(),
            stage: GatewayAttemptStage::Reserved,
            refusal: None,
            response_status: None,
            response_digest: None,
            response_locator: None,
            observation_plan: request.observation_template().cloned(),
            observation_match: None,
            observation_fact: None,
            provider_evidence: None,
            recovery_evidence: None,
            pre_entry: None,
        },
    );
    let record = record?;
    record.snapshot(false)?;
    Ok(record)
}

/// Gateway attempt semantics over one durable [`GatewayAttemptStore`].
#[derive(Clone)]
pub struct GatewayAttempts {
    store: Arc<dyn GatewayAttemptStore>,
    policy: EffectPolicy,
}

impl GatewayAttempts {
    /// Uses one installed partition and epoch for every claim and lookup.
    ///
    /// # Errors
    /// Refuses invalid installed policy. There is no implicit replay namespace.
    pub fn new(
        store: Arc<dyn GatewayAttemptStore>,
        policy: EffectPolicy,
    ) -> Result<Self, GatewayAttemptError> {
        policy
            .validate()
            .map_err(|_| GatewayAttemptError::Corrupt)?;
        Ok(Self { store, policy })
    }

    pub(crate) fn policy(&self) -> &EffectPolicy {
        &self.policy
    }

    fn key(
        &self,
        namespace: &OperatorNamespace,
        operation: &LogicalOperationId,
    ) -> Result<GatewayAttemptKey, GatewayAttemptError> {
        GatewayAttemptKey::for_operation(&self.policy, namespace, operation)
    }

    /// Returns the underlying mechanism.
    #[must_use]
    pub fn store(&self) -> Arc<dyn GatewayAttemptStore> {
        Arc::clone(&self.store)
    }

    /// Reference-store oracle only; production admission requires ApprovedEffect.
    #[cfg(test)]
    pub(crate) async fn claim(
        &self,
        request: &ClosedProviderRequest,
        recipe_digest: [u8; 32],
        evaluated_at: u64,
    ) -> Result<ClaimedGatewayAttempt, GatewayAttemptError> {
        let binding =
            crate::effect::store_binding_fixture(request, recipe_digest, [0; 32], &self.policy)
                .map_err(|_| GatewayAttemptError::Corrupt)?;
        let approval = crate::effect::approval_fixture(&binding, evaluated_at)
            .map_err(|_| GatewayAttemptError::Corrupt)?;
        self.claim_binding(request, &binding, &approval, evaluated_at)
            .await
    }

    #[cfg(test)]
    async fn claim_binding(
        &self,
        request: &ClosedProviderRequest,
        binding: &EffectBinding,
        approval: &ExactEffectApproval,
        evaluated_at: u64,
    ) -> Result<ClaimedGatewayAttempt, GatewayAttemptError> {
        if !self.policy.contains(binding) {
            return Err(GatewayAttemptError::BindingConflict);
        }
        let key = self.key(request.namespace(), request.operation_id())?;
        let record = claim_record(request, binding, approval, evaluated_at)?;
        let stored = encode(&record)?;
        let store = Arc::clone(&self.store);
        let entry = GatewayRecordEntry {
            kind: GatewayRecordKind::Attempt,
            key,
            record: stored.clone(),
            expires_at: None,
        };
        let expected = record.binding_canonical.clone();
        blocking(move || match store.insert(&entry) {
            Err(GatewayAttemptError::Replay) => Err(existing_binding(&*store, key, &expected)),
            result => result,
        })
        .await?;
        Ok(ClaimedGatewayAttempt {
            attempt: Attempt {
                store: Arc::clone(&self.store),
                key,
                stored,
                record,
            },
        })
    }

    /// Lists at most `limit` stored attempts as the hexadecimal digest that
    /// keys each one and its conservative stage, restricted to this installed
    /// partition and epoch. At most `limit` raw entries are inspected; entries
    /// in another scope can make the result shorter. Nothing else of an attempt
    /// is returned: no operation identifier, argument, or provider value.
    ///
    /// # Errors
    /// Malformed state is a hard failure.
    pub async fn stages(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, GatewayOperationStage)>, GatewayAttemptError> {
        let store = Arc::clone(&self.store);
        let policy = self.policy.clone();
        blocking(move || {
            store
                .attempt_keys(limit)?
                .into_iter()
                .filter_map(|key| {
                    let stage = store
                        .load(GatewayRecordKind::Attempt, &key)
                        .and_then(|bytes| bytes.map(|bytes| decode_protocol(&bytes)).transpose())
                        .and_then(|record| {
                            let Some(record) = record else {
                                return Ok(None);
                            };
                            let binding = EffectBinding::from_private_bytes(
                                record.binding_canonical.as_bytes(),
                            )
                            .map_err(|_| GatewayAttemptError::Corrupt)?;
                            if !policy.contains(&binding) {
                                return Ok(None);
                            }
                            let stage = match &record.state {
                                ProtocolState::Mutation(_) => GatewayOperationStage::Mutation(
                                    record
                                        .map_state(MutationState::extract)?
                                        .snapshot(true)?
                                        .stage(),
                                ),
                                ProtocolState::Acquisition(_) => {
                                    GatewayOperationStage::Acquisition(
                                        record
                                            .map_state(acquisition::AcquisitionState::extract)?
                                            .snapshot()?
                                            .stage,
                                    )
                                }
                            };
                            Ok(Some(stage))
                        });
                    match stage {
                        Ok(Some(snapshot)) => Some(Ok((hex::encode(key.as_bytes()), snapshot))),
                        // Deleted between the listing and the read.
                        Ok(None) => None,
                        Err(error) => Some(Err(error)),
                    }
                })
                .collect()
        })
        .await
    }

    /// Reads a secret-free durable snapshot. An `entry-granted` stage is
    /// conservatively projected as `unknown`: another process may hold it, or
    /// it may have crashed.
    ///
    /// # Errors
    /// Malformed or obsolete state is a hard failure, not an unclaimed slot.
    pub async fn read(
        &self,
        namespace: &OperatorNamespace,
        operation_id: &LogicalOperationId,
    ) -> Result<Option<GatewayAttemptSnapshot>, GatewayAttemptError> {
        self.load(namespace, operation_id)
            .await?
            .map(|(_, record)| record.snapshot(true))
            .transpose()
    }

    /// Reads history only when the complete immutable binding matches the
    /// approved native effect. Renewed approval is not part of that identity.
    pub(crate) async fn read_effect(
        &self,
        approved: &ApprovedEffect,
    ) -> Result<Option<GatewayAttemptSnapshot>, GatewayAttemptError> {
        let request = &approved
            .command()
            .ok_or(GatewayAttemptError::InvalidTransition)?
            .request;
        let Some((_, record)) = self
            .load(request.namespace(), request.operation_id())
            .await?
        else {
            return Ok(None);
        };
        if record.binding_canonical.as_bytes()
            != approved
                .effect()
                .binding()
                .to_private_bytes()
                .map_err(|_| GatewayAttemptError::Corrupt)?
                .as_slice()
        {
            return Err(GatewayAttemptError::BindingConflict);
        }
        record.snapshot(true).map(Some)
    }

    /// Retained source contract, including terminal history. Compiling it does
    /// not permit a new read: acquisition entry separately requires an eligible
    /// source under the writer fence. This enables exact read replay after a
    /// source was refined without recreating a provider permit.
    pub(crate) async fn retained_recovery_target(
        &self,
        namespace: &OperatorNamespace,
        operation_id: &LogicalOperationId,
        recipe_digest: [u8; 32],
    ) -> Result<crate::effect::RecoveryReadTarget, GatewayAttemptError> {
        let (_, record) = self
            .load(namespace, operation_id)
            .await?
            .ok_or(GatewayAttemptError::Unavailable)?;
        record.snapshot(true)?;
        if record.recipe_digest != hex::encode(recipe_digest)
            || !transition::requires_entry(record.state.stage.kernel())
        {
            return Err(GatewayAttemptError::BindingConflict);
        }
        record.recovery_target_data()
    }

    /// Reopens a stored attempt for the operator's read-only
    /// re-observation. The recipe must match and the stored stage must permit
    /// evidence from its stored plan. Application replay cannot call this path.
    ///
    /// # Errors
    /// Malformed state is a hard failure.
    pub async fn resume_observable_operation(
        &self,
        namespace: &OperatorNamespace,
        operation_id: &LogicalOperationId,
        recipe_digest: [u8; 32],
    ) -> Result<Option<ObservableGatewayAttempt>, GatewayAttemptError> {
        let Some((stored, record)) = self.load(namespace, operation_id).await? else {
            return Ok(None);
        };
        record.snapshot(false)?;
        let resumable =
            record.recipe_digest == hex::encode(recipe_digest) && record.recovery_target().is_ok();
        let key = self.key(namespace, operation_id)?;
        Ok(resumable.then(|| ObservableGatewayAttempt {
            attempt: Attempt {
                store: Arc::clone(&self.store),
                key,
                stored,
                record,
            },
        }))
    }

    async fn load(
        &self,
        namespace: &OperatorNamespace,
        operation_id: &LogicalOperationId,
    ) -> Result<Option<(Vec<u8>, Record)>, GatewayAttemptError> {
        let key = self.key(namespace, operation_id)?;
        let store = Arc::clone(&self.store);
        let Some(bytes) = blocking(move || store.load(GatewayRecordKind::Attempt, &key)).await?
        else {
            return Ok(None);
        };
        let record = decode(&bytes)?;
        let binding = EffectBinding::from_private_bytes(record.binding_canonical.as_bytes())
            .map_err(|_| GatewayAttemptError::Corrupt)?;
        if !self.policy.contains(&binding)
            || record.namespace != namespace.as_str()
            || record.operation_id != operation_id.as_str()
        {
            return Err(GatewayAttemptError::Corrupt);
        }
        Ok(Some((bytes, record)))
    }

    /// Deletes at most `limit` expired slots off the async executor.
    ///
    /// # Errors
    /// Returns the store's failure.
    pub async fn sweep_expired(
        &self,
        now: u64,
        limit: usize,
    ) -> Result<usize, GatewayAttemptError> {
        let store = Arc::clone(&self.store);
        blocking(move || store.sweep_expired(now, limit)).await
    }
}

/// One loaded or claimed attempt and the exact bytes it was read as.
struct Attempt<S = MutationState> {
    store: Arc<dyn GatewayAttemptStore>,
    key: GatewayAttemptKey,
    stored: Vec<u8>,
    record: Record<S>,
}

impl<S: JournalProtocol> Attempt<S> {
    /// Persists `next` only as a valid stage change from the exact stored
    /// record; a concurrent change by another process is a conflict.
    async fn advance(mut self, mut next: Record<S>) -> Result<Self, GatewayAttemptError> {
        next.revision = self
            .record
            .revision
            .checked_add(1)
            .ok_or(GatewayAttemptError::InvalidTransition)?;
        if !valid_transition(&self.record, &next)? {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        let bytes = encode(&next)?;
        let store = Arc::clone(&self.store);
        let key = self.key;
        let current = std::mem::take(&mut self.stored);
        let replacement = bytes.clone();
        blocking(move || store.replace(GatewayRecordKind::Attempt, &key, &current, &replacement))
            .await?;
        self.stored = bytes;
        self.record = next;
        Ok(self)
    }
}

/// A durable attempt handle. A reservation does not authorize transport; only
/// a newly acknowledged grant produces a one-use provider permit.
pub struct ClaimedGatewayAttempt {
    attempt: Attempt,
}

impl ClaimedGatewayAttempt {
    /// Validates the native authority, dependencies and every existing slot
    /// under the same writer fence, then persists one immutable grant. No
    /// deserialization path can construct the returned transport permit.
    pub(crate) async fn grant_entry(
        self,
        approved: Arc<ApprovedEffect>,
        validation: crate::entry::EntryValidation,
        authorization_started_at: u64,
        pre_entry: &GatewayPreEntry,
    ) -> Result<(Self, ProviderEntryPermit), GatewayAttemptError> {
        let pre_entry = PreEntryWire::encode(pre_entry)?;
        let request = approved
            .command()
            .ok_or(GatewayAttemptError::InvalidTransition)?
            .request
            .clone();
        blocking(move || {
            let mut attempt = self.attempt;
            let dependencies = validation.dependencies();
            let counters = attempt.record.counters()?;
            let prerequisites = approved
                .prerequisite_plans()
                .map_err(|_| GatewayAttemptError::InvalidTransition)?;
            let mut keys = vec![(GatewayRecordKind::Attempt, attempt.key)];
            keys.extend_from_slice(&dependencies);
            keys.extend(counters.iter().map(|counter| match counter.kind {
                GatewayCounterKind::Count => (
                    GatewayRecordKind::CountSlot,
                    GatewayAttemptKey(crate::bounds::count_slot_key(
                        &counter.counter,
                        counter.slot,
                    )),
                ),
                GatewayCounterKind::Sum => (
                    GatewayRecordKind::SumSlot,
                    GatewayAttemptKey(crate::bounds::sum_slot_key(&counter.counter, counter.slot)),
                ),
            }));
            let counter_end = keys.len();
            keys.extend(acquisition::prerequisite_dependencies(
                attempt.key,
                &prerequisites,
            )?);
            let mut committed = None;
            attempt.store.fenced_replace(&keys, &mut |snapshots| {
                if snapshots.len() != keys.len()
                    || snapshots[0].as_deref() != Some(attempt.stored.as_slice())
                {
                    return Err(GatewayAttemptError::Conflict);
                }
                let current = decode(
                    snapshots[0]
                        .as_deref()
                        .ok_or(GatewayAttemptError::Corrupt)?,
                )?;
                if current.state.stage != GatewayAttemptStage::Reserved
                    || current.binding_canonical.as_bytes()
                        != approved
                            .effect()
                            .binding()
                            .to_private_bytes()
                            .map_err(|_| GatewayAttemptError::Corrupt)?
                            .as_slice()
                {
                    return Err(GatewayAttemptError::InvalidTransition);
                }
                let dependency_end = 1 + dependencies.len();
                let now = validation
                    .validate(
                        &approved,
                        &snapshots[1..dependency_end],
                        authorization_started_at,
                    )
                    .map_err(|_| GatewayAttemptError::InvalidTransition)?;
                current.validate_reservations(
                    attempt.key,
                    approved
                        .command()
                        .ok_or(GatewayAttemptError::InvalidTransition)?
                        .bound
                        .as_ref(),
                    &snapshots[dependency_end..counter_end],
                    now,
                )?;
                let acquired = acquisition::validate_prerequisites(
                    attempt.key,
                    approved.effect().binding(),
                    &prerequisites,
                    &snapshots[counter_end..],
                    now,
                )?;
                let evidence = pre_entry
                    .as_ref()
                    .map(PreEntryWire::decode)
                    .transpose()?
                    .unwrap_or_default();
                validation
                    .validate_prerequisite_evidence(&approved, &evidence, &acquired, now)
                    .map_err(|_| GatewayAttemptError::InvalidTransition)?;
                let mut next = current.clone();
                next.record_grant(
                    &approved,
                    authorization_started_at,
                    now,
                    pre_entry.clone(),
                    &snapshots[1..],
                )?;
                next.state.stage = GatewayAttemptStage::EntryGranted;
                if !valid_transition(&current, &next)? {
                    return Err(GatewayAttemptError::InvalidTransition);
                }
                let bytes = encode(&next)?;
                committed = Some((next, bytes.clone()));
                Ok(bytes)
            })?;
            // A callback result alone is insufficient. This point is reached
            // only after the adapter acknowledges durable publication.
            let (record, stored) = committed.ok_or(GatewayAttemptError::Unavailable)?;
            attempt.record = record;
            attempt.stored = stored;
            Ok((
                Self { attempt },
                ProviderEntryPermit {
                    _approved: approved,
                    request,
                },
            ))
        })
        .await
    }

    /// Records, once and before transport entry, what was read after the
    /// lease: the pre-entry observations and the relative-ceiling basis.
    ///
    /// # Errors
    /// Rejects an empty first checkpoint, post-grant calls and persistence failure.
    /// A resumed reservation retains its first checkpoint; its fresh reads are
    /// separately bound in the immutable entry audit.
    pub async fn record_checkpoint(
        self,
        pre_entry: &GatewayPreEntry,
    ) -> Result<Self, GatewayAttemptError> {
        if self.attempt.record.state.stage != GatewayAttemptStage::Reserved {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        let fresh = PreEntryWire::encode(pre_entry)?;
        if self.attempt.record.state.pre_entry.is_some() {
            return Ok(self);
        }
        let mut next = self.attempt.record.clone();
        next.state.pre_entry = fresh;
        Ok(Self {
            attempt: self.attempt.advance(next).await?,
        })
    }

    /// Records definite pre-entry exclusion with its stable code, keeping
    /// any evidence read before the refusal.
    ///
    /// # Errors
    /// Persistence failure does not permit a retry.
    pub async fn record_not_entered(
        self,
        refusal: &str,
        pre_entry: Option<&GatewayPreEntry>,
    ) -> Result<GatewayAttemptSnapshot, GatewayAttemptError> {
        let mut next = self.attempt.record.clone();
        next.state.stage = GatewayAttemptStage::NotEntered;
        next.state.refusal = Some(refusal.to_owned());
        if let Some(pre_entry) = pre_entry
            && next.state.pre_entry.is_none()
        {
            next.state.pre_entry = PreEntryWire::encode(pre_entry)?;
        }
        self.attempt.advance(next).await?.record.snapshot(false)
    }

    /// Records an ambiguous outcome while retaining replay history.
    ///
    /// # Errors
    /// Persistence failure does not permit a retry.
    pub async fn record_unknown(self) -> Result<GatewayAttemptSnapshot, GatewayAttemptError> {
        let mut next = self.attempt.record.clone();
        next.state.stage = GatewayAttemptStage::Unknown;
        self.attempt.advance(next).await?.record.snapshot(false)
    }

    /// Records a complete bounded HTTP response, never effect success, and
    /// the response-locator values read from it.
    ///
    /// # Errors
    /// Rejects an invalid status or locator and persistence failure.
    pub async fn record_response(
        self,
        status: u16,
        digest: [u8; 32],
        locator: Option<BTreeMap<String, String>>,
    ) -> Result<ObservableGatewayAttempt, GatewayAttemptError> {
        if !(100..=599).contains(&status) {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        let mut next = self.attempt.record.clone();
        next.state.stage = GatewayAttemptStage::ResponseRecorded;
        next.state.response_status = Some(status);
        next.state.response_digest = Some(hex::encode(digest));
        next.state.response_locator = locator;
        Ok(ObservableGatewayAttempt {
            attempt: self.attempt.advance(next).await?,
        })
    }
}

/// One-use native transport capability, constructed only after a new durable
/// entry acknowledgement. The shared reference retains the approved effect;
/// the permit itself is neither cloneable nor deserializable.
pub(crate) struct ProviderEntryPermit {
    _approved: Arc<ApprovedEffect>,
    // Immutable clone of the exact sealed mutation request checked at grant.
    request: ClosedProviderRequest,
}

impl ProviderEntryPermit {
    pub(crate) fn request(&self) -> &ClosedProviderRequest {
        &self.request
    }
}

/// A protected view of a stored attempt and its observation contract.
/// Production refinement requires independently acquired evidence through
/// the recovery fence; this view grants no provider or journal-entry capability.
pub struct ObservableGatewayAttempt {
    attempt: Attempt,
}

impl ObservableGatewayAttempt {
    /// Returns response evidence without asserting effect.
    ///
    /// # Errors
    /// Rejects contradictory state.
    pub fn snapshot(&self) -> Result<GatewayAttemptSnapshot, GatewayAttemptError> {
        self.attempt.record.snapshot(false)
    }

    /// The read-back request built from the plan fixed at the claim and the
    /// recorded locator, when one can be built.
    #[must_use]
    pub fn observation_request(&self) -> Option<ClosedObservationRequest> {
        self.attempt.record.observation_request()
    }

    /// Native private compilation target from this validated journal's plan.
    /// It contains private data but grants no read or write authority.
    ///
    /// # Errors
    /// Refuses corrupt binding data or a missing closed observation request.
    pub fn recovery_target(
        &self,
    ) -> Result<crate::effect::RecoveryReadTarget, GatewayAttemptError> {
        self.attempt.record.recovery_target()
    }

    /// Returns this attempt's echo token, derived from the stored verified
    /// commitment, when the recipe declared an echo field.
    #[must_use]
    pub fn echo_token(&self) -> Option<String> {
        self.attempt
            .record
            .state
            .observation_plan
            .as_ref()
            .filter(|plan| plan.echo_pointer.is_some())
            .and_then(|_| self.attempt.record.echo_token().ok())
    }

    /// Records read-back equality; a match does not prove this write caused it.
    /// Only a `response-recorded` attempt can take this transition.
    ///
    /// # Errors
    /// Persistence failure retains only the recorded response.
    #[cfg(test)]
    pub(crate) async fn record_observation(
        self,
        matched: bool,
    ) -> Result<GatewayAttemptSnapshot, GatewayAttemptError> {
        let mut next = self.attempt.record.clone();
        next.state.stage = GatewayAttemptStage::Observed;
        next.state.observation_match = Some(matched);
        self.attempt.advance(next).await?.record.snapshot(false)
    }

    /// Records `observed` with `matched: false` and the `echo-mismatch` fact.
    /// Only a `response-recorded` attempt can take this transition.
    ///
    /// # Errors
    /// Persistence failure retains only the recorded response.
    #[cfg(test)]
    pub(crate) async fn record_echo_mismatch(
        self,
    ) -> Result<GatewayAttemptSnapshot, GatewayAttemptError> {
        let mut next = self.attempt.record.clone();
        next.state.stage = GatewayAttemptStage::Observed;
        next.state.observation_match = Some(false);
        next.state.observation_fact = Some(GatewayObservationFact::EchoMismatch);
        self.attempt.advance(next).await?.record.snapshot(false)
    }

    /// Records terminal `observed-by-provider` with the exact response bytes.
    /// The caller must already have found this attempt's token in them; the
    /// stored token is re-derived from this record, never taken from input.
    ///
    /// # Errors
    /// Rejects a recipe without echo, empty or oversized evidence, and
    /// persistence failure.
    #[cfg(test)]
    pub(crate) async fn record_provider_evidence(
        self,
        evidence: &[u8],
        observed_at: u64,
    ) -> Result<GatewayAttemptSnapshot, GatewayAttemptError> {
        let record = &self.attempt.record;
        let locator = record
            .observation_request()
            .filter(|_| {
                record
                    .state
                    .observation_plan
                    .as_ref()
                    .is_some_and(|plan| plan.echo_pointer.is_some())
            })
            .ok_or(GatewayAttemptError::InvalidTransition)?;
        if evidence.is_empty() || evidence.len() > MAX_EVIDENCE_BYTES {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        let mut next = record.clone();
        next.state.provider_evidence = Some(EvidenceWire {
            channel: GatewayEvidenceChannel::ReadBack,
            locator: locator.url().to_owned(),
            echo: record.echo_token()?,
            evidence_digest: hex::encode(Sha256::digest(evidence)),
            evidence_b64: Base64::encode_string(evidence),
            observed_at,
        });
        next.state.stage = GatewayAttemptStage::ObservedByProvider;
        self.attempt.advance(next).await?.record.snapshot(false)
    }
}

fn encode<S: JournalProtocol>(record: &Record<S>) -> Result<Vec<u8>, GatewayAttemptError> {
    let record = record.clone();
    let wire = record.map_state(|state| Ok(state.wrap()))?;
    let bytes = serde_json::to_vec(&wire).map_err(|_| GatewayAttemptError::Corrupt)?;
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(GatewayAttemptError::Corrupt);
    }
    Ok(bytes)
}

/// Existing claims never disappear. A loser compares the immutable complete
/// binding after the insert transaction reports a collision, without minting
/// any capability or consuming another reservation.
fn existing_binding(
    store: &dyn GatewayAttemptStore,
    key: GatewayAttemptKey,
    expected: &str,
) -> GatewayAttemptError {
    let checked = (|| {
        let bytes = store
            .load(GatewayRecordKind::Attempt, &key)?
            .ok_or(GatewayAttemptError::Corrupt)?;
        let record = decode_protocol(&bytes)?;
        Ok::<_, GatewayAttemptError>(record.binding_canonical == expected)
    })();
    match checked {
        Ok(true) => GatewayAttemptError::Replay,
        Ok(false) => GatewayAttemptError::BindingConflict,
        Err(error) => error,
    }
}

fn decode(bytes: &[u8]) -> Result<Record, GatewayAttemptError> {
    decode_as(bytes)
}

fn decode_as<S: JournalProtocol>(bytes: &[u8]) -> Result<Record<S>, GatewayAttemptError> {
    decode_protocol(bytes)?.map_state(S::extract)
}

fn decode_protocol(bytes: &[u8]) -> Result<Record<ProtocolState>, GatewayAttemptError> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(GatewayAttemptError::Corrupt);
    }
    let record: Record<ProtocolState> =
        serde_json::from_slice(bytes).map_err(|_| GatewayAttemptError::Corrupt)?;
    record.validate_header()?;
    match &record.state {
        ProtocolState::Mutation(_) => {
            let typed = record.clone().map_state(MutationState::extract)?;
            MutationState::validate(&typed)?;
        }
        ProtocolState::Acquisition(_) => {
            let typed = record
                .clone()
                .map_state(acquisition::AcquisitionState::extract)?;
            acquisition::AcquisitionState::validate(&typed)?;
        }
    }
    Ok(record)
}

/// The snapshot of one stored record's bytes, for the fuzz targets.
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_snapshot(bytes: &[u8]) -> Option<GatewayAttemptSnapshot> {
    decode(bytes).ok()?.snapshot(false).ok()
}

/// Whether one stored record's bytes may replace another's, for the fuzz
/// targets.
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_transition(old: &[u8], new: &[u8]) -> Option<bool> {
    valid_transition(&decode(old).ok()?, &decode(new).ok()?).ok()
}

/// Whether `new` may replace `old`: the translated transition rule on both
/// projections, and a fully valid `new`.
fn valid_transition<S: JournalProtocol>(
    old: &Record<S>,
    new: &Record<S>,
) -> Result<bool, GatewayAttemptError> {
    Ok(transition::valid_transition(&S::view(old)?, &S::view(new)?) && S::validate(new).is_ok())
}

fn sync_directory(root: &Path) -> Result<(), GatewayAttemptError> {
    #[cfg(unix)]
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| GatewayAttemptError::Unavailable)?;
    #[cfg(not(unix))]
    let _ = root;
    Ok(())
}

const COUNT_SLOT_SCHEMA: &str = "auths.gateway-bounded-count/2";
const SUM_SLOT_SCHEMA: &str = "auths.gateway-bounded-sum/1";
/// A claim that keeps losing slot races gives up after this many rounds and
/// stores nothing.
const MAX_CLAIM_ROUNDS: usize = 32;

/// Slot record `auths.gateway-bounded-count/2`.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CountSlotRecord {
    schema: String,
    counter: String,
    slot: u64,
    window_seconds: u64,
    window_index: u64,
    window_end: u64,
    namespace: String,
    operation_id: String,
    claim: String,
}

/// Sum slot record `auths.gateway-bounded-sum/1`. `cumulative` is the
/// window's sum through this slot and is fixed once inserted.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SumSlotRecord {
    schema: String,
    counter: String,
    slot: u64,
    amount: u64,
    cumulative: u64,
    window_seconds: u64,
    window_index: u64,
    window_end: u64,
    namespace: String,
    operation_id: String,
    claim: String,
}

/// The outcome of a claim with its count and sum slots.
pub(crate) enum BoundedClaim {
    /// The claim and every slot were inserted in one all-or-none batch.
    Claimed(Box<ClaimedGatewayAttempt>),
    /// A counter was full, so the claim alone was stored `not-entered` with
    /// this code; the operation ID is consumed and no slot was taken.
    Exhausted(&'static str),
    /// Every round lost a slot race; nothing was stored.
    Contended,
}

enum Reserved {
    Claimed {
        stored: Vec<u8>,
        record: Box<Record>,
    },
    Exhausted(&'static str),
    Contended,
}

/// The lowest free slot below `bound` of one counter, by binary search over
/// its occupied prefix. Slots are inserted only at an observed frontier and
/// never deleted inside their window, so the occupied slots form a prefix.
fn frontier(
    store: &dyn GatewayAttemptStore,
    kind: GatewayRecordKind,
    counter: &[u8; 32],
    bound: u64,
    slot_key: fn(&[u8; 32], u64) -> [u8; 32],
) -> Result<u64, GatewayAttemptError> {
    let (mut low, mut high) = (0_u64, bound);
    while low < high {
        let middle = low + (high - low) / 2;
        let key = GatewayAttemptKey(slot_key(counter, middle));
        if store.load(kind, &key)?.is_some() {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    Ok(low)
}

/// The cumulative sum stored in slot `slot` of sum counter `counter`. An
/// absent or malformed slot fails closed.
fn cumulative(
    store: &dyn GatewayAttemptStore,
    counter: &[u8; 32],
    slot: u64,
) -> Result<u64, GatewayAttemptError> {
    let key = GatewayAttemptKey(crate::bounds::sum_slot_key(counter, slot));
    let bytes = store
        .load(GatewayRecordKind::SumSlot, &key)?
        .ok_or(GatewayAttemptError::Corrupt)?;
    let record: SumSlotRecord =
        serde_json::from_slice(&bytes).map_err(|_| GatewayAttemptError::Corrupt)?;
    if record.schema != SUM_SLOT_SCHEMA
        || record.counter != hex::encode(counter)
        || record.slot != slot
        || record.amount > record.cumulative
    {
        return Err(GatewayAttemptError::Corrupt);
    }
    Ok(record.cumulative)
}

/// Stores `base` alone as `not-entered` with `code`.
fn store_exhausted(
    store: &dyn GatewayAttemptStore,
    key: GatewayAttemptKey,
    base: &Record,
    code: &'static str,
    admission: &Admission,
) -> Result<Reserved, GatewayAttemptError> {
    let mut record = base.clone();
    record.state.stage = GatewayAttemptStage::NotEntered;
    record.state.refusal = Some(code.to_owned());
    record.snapshot(false)?;
    let entries = [GatewayRecordEntry {
        kind: GatewayRecordKind::Attempt,
        key,
        record: encode(&record)?,
        expires_at: None,
    }];
    match insert_claim(store, &mut record, &entries, admission, None, &[], &[])? {
        GatewayInsert::Inserted => Ok(Reserved::Exhausted(code)),
        GatewayInsert::Exists { .. } => Err(GatewayAttemptError::Replay),
    }
}

/// The claim record with the reserved slots, and the batch that inserts it
/// with one slot record per count and sum counter.
fn claim_batch(
    key: GatewayAttemptKey,
    base: &Record,
    bound: &crate::bounds::BoundAdmission,
    counts: &[u64],
    sums: &[u64],
    totals: &[u64],
) -> Result<(Record, Vec<u8>, Vec<GatewayRecordEntry>), GatewayAttemptError> {
    use crate::bounds::{count_slot_key, sum_slot_key};
    let mut record = base.clone();
    let mut counters: Vec<GatewayCounterEntry> = bound
        .counts
        .iter()
        .zip(counts)
        .map(|(counter, slot)| GatewayCounterEntry {
            kind: GatewayCounterKind::Count,
            counter: counter.key,
            slot: *slot,
        })
        .chain(
            bound
                .sums
                .iter()
                .zip(sums)
                .map(|(counter, slot)| GatewayCounterEntry {
                    kind: GatewayCounterKind::Sum,
                    counter: counter.key,
                    slot: *slot,
                }),
        )
        .collect();
    counters.sort_unstable();
    record.state.counters = counters
        .iter()
        .map(|entry| CounterWire {
            kind: entry.kind,
            counter: hex::encode(entry.counter),
            slot: entry.slot,
        })
        .collect();
    record.snapshot(false)?;
    let stored = encode(&record)?;
    let claim = hex::encode(key.as_bytes());
    let mut entries = Vec::with_capacity(1 + counts.len() + sums.len());
    entries.push(GatewayRecordEntry {
        kind: GatewayRecordKind::Attempt,
        key,
        record: stored.clone(),
        expires_at: None,
    });
    for (counter, slot) in bound.counts.iter().zip(counts) {
        let slot_record = CountSlotRecord {
            schema: COUNT_SLOT_SCHEMA.to_owned(),
            counter: hex::encode(counter.key),
            slot: *slot,
            window_seconds: bound.window_seconds,
            window_index: bound.window_index,
            window_end: bound.window_end,
            namespace: base.namespace.clone(),
            operation_id: base.operation_id.clone(),
            claim: claim.clone(),
        };
        entries.push(GatewayRecordEntry {
            kind: GatewayRecordKind::CountSlot,
            key: GatewayAttemptKey(count_slot_key(&counter.key, *slot)),
            record: canonical(&slot_record)?,
            expires_at: Some(bound.expires_at()),
        });
    }
    for ((counter, slot), total) in bound.sums.iter().zip(sums).zip(totals) {
        let slot_record = SumSlotRecord {
            schema: SUM_SLOT_SCHEMA.to_owned(),
            counter: hex::encode(counter.key),
            slot: *slot,
            amount: bound.argument,
            cumulative: total
                .checked_add(bound.argument)
                .ok_or(GatewayAttemptError::Corrupt)?,
            window_seconds: bound.window_seconds,
            window_index: bound.window_index,
            window_end: bound.window_end,
            namespace: base.namespace.clone(),
            operation_id: base.operation_id.clone(),
            claim: claim.clone(),
        };
        entries.push(GatewayRecordEntry {
            kind: GatewayRecordKind::SumSlot,
            key: GatewayAttemptKey(sum_slot_key(&counter.key, *slot)),
            record: canonical(&slot_record)?,
            expires_at: Some(bound.expires_at()),
        });
    }
    Ok((record, stored, entries))
}

/// Finds each counter's frontier, then inserts the claim and one slot per
/// count and sum counter in one all-or-none batch. A full counter stores
/// the claim alone as `not-entered`; a lost race advances that counter and
/// retries, at most [`MAX_CLAIM_ROUNDS`] times. The count and sum checks are
/// the translated leaves `chain_counts_admit` and `chain_sums_admit`.
fn reserve_with_claim(
    store: &dyn GatewayAttemptStore,
    key: GatewayAttemptKey,
    base: &Record,
    bound: &crate::bounds::BoundAdmission,
    admission: &Admission,
) -> Result<Reserved, GatewayAttemptError> {
    use crate::bounds::{count_slot_key, sum_slot_key};
    use auths_bounded_policy::kernel::{chain_counts_admit, chain_sums_admit};
    let mut counts = bound
        .counts
        .iter()
        .map(|counter| {
            frontier(
                store,
                GatewayRecordKind::CountSlot,
                &counter.key,
                counter.capacity,
                count_slot_key,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut sums = bound
        .sums
        .iter()
        .map(|counter| {
            frontier(
                store,
                GatewayRecordKind::SumSlot,
                &counter.key,
                counter.slots,
                sum_slot_key,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut totals = sums
        .iter()
        .zip(&bound.sums)
        .map(|(slot, counter)| match slot.checked_sub(1) {
            None => Ok(0),
            Some(previous) => cumulative(store, &counter.key, previous),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let count_capacities: Vec<u64> = bound
        .counts
        .iter()
        .map(|counter| counter.capacity)
        .collect();
    let sum_capacities: Vec<u64> = bound.sums.iter().map(|counter| counter.capacity).collect();
    for _ in 0..MAX_CLAIM_ROUNDS {
        let sum_slots_left = sums
            .iter()
            .zip(&bound.sums)
            .all(|(slot, counter)| *slot < counter.slots);
        if !chain_counts_admit(&counts, &count_capacities) || !sum_slots_left {
            return store_exhausted(
                store,
                key,
                base,
                "gateway.policy.window-exhausted",
                admission,
            );
        }
        if !chain_sums_admit(&totals, bound.argument, &sum_capacities) {
            return store_exhausted(store, key, base, "gateway.policy.sum-exhausted", admission);
        }
        let (mut record, _, entries) = claim_batch(key, base, bound, &counts, &sums, &totals)?;
        match insert_claim(
            store,
            &mut record,
            &entries,
            admission,
            Some(bound),
            &sums,
            &totals,
        )? {
            GatewayInsert::Inserted => {
                return Ok(Reserved::Claimed {
                    stored: encode(&record)?,
                    record: Box::new(record),
                });
            }
            GatewayInsert::Exists { index: 0 } => return Err(GatewayAttemptError::Replay),
            GatewayInsert::Exists { index } => {
                let position = index - 1;
                if let Some(slot) = counts.get_mut(position) {
                    *slot += 1;
                } else {
                    let position = position - counts.len();
                    let (Some(slot), Some(total), Some(counter)) = (
                        sums.get_mut(position),
                        totals.get_mut(position),
                        bound.sums.get(position),
                    ) else {
                        return Err(GatewayAttemptError::Corrupt);
                    };
                    *total = cumulative(store, &counter.key, *slot)?;
                    *slot += 1;
                }
            }
        }
    }
    Ok(Reserved::Contended)
}

/// Current native authority captured before custody and sampled again only
/// inside the adapter writer fence. It never grants transport entry.
struct Admission {
    approved: Arc<ApprovedEffect>,
    validation: crate::entry::EntryValidation,
    authorization_started_at: u64,
}

impl Admission {
    fn dependencies(&self) -> Vec<(GatewayRecordKind, GatewayAttemptKey)> {
        self.validation.dependencies()
    }

    fn stamp<S: JournalProtocol>(
        &self,
        record: &mut Record<S>,
        snapshots: &[Option<Vec<u8>>],
    ) -> Result<(), GatewayAttemptError> {
        if record.revision != 1
            || record.entry.is_some()
            || record.validate_header()? != *self.approved.effect().binding()
        {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        let now = self
            .validation
            .validate(&self.approved, snapshots, self.authorization_started_at)
            .map_err(|_| GatewayAttemptError::InvalidTransition)?;
        record.evaluated_at = now;
        S::validate(record)
    }
}

/// Capacity candidates are chosen outside the lock, but target vacancy and
/// immutable sum predecessors are checked with current authority before insert.
fn insert_claim(
    store: &dyn GatewayAttemptStore,
    record: &mut Record,
    entries: &[GatewayRecordEntry],
    admission: &Admission,
    bound: Option<&crate::bounds::BoundAdmission>,
    sums: &[u64],
    totals: &[u64],
) -> Result<GatewayInsert, GatewayAttemptError> {
    let mut dependencies = admission.dependencies();
    let native_end = dependencies.len();
    if let Some(bound) = bound {
        if sums.len() != bound.sums.len() || totals.len() != sums.len() {
            return Err(GatewayAttemptError::Corrupt);
        }
        for (counter, slot) in bound.sums.iter().zip(sums) {
            if let Some(previous) = slot.checked_sub(1) {
                dependencies.push((
                    GatewayRecordKind::SumSlot,
                    GatewayAttemptKey(crate::bounds::sum_slot_key(&counter.key, previous)),
                ));
            }
        }
    } else if !sums.is_empty() || !totals.is_empty() {
        return Err(GatewayAttemptError::Corrupt);
    }
    store.fenced_insert_all(entries, &dependencies, &mut |snapshots| {
        if snapshots.len() != dependencies.len() {
            return Err(GatewayAttemptError::Corrupt);
        }
        admission.stamp(record, &snapshots[..native_end])?;
        if let Some(bound) = bound {
            let mut predecessors = snapshots[native_end..].iter();
            for ((counter, slot), total) in bound.sums.iter().zip(sums).zip(totals) {
                match slot.checked_sub(1) {
                    None if *total != 0 => return Err(GatewayAttemptError::Corrupt),
                    None => {}
                    Some(previous) => {
                        let bytes = predecessors
                            .next()
                            .and_then(|bytes| bytes.as_deref())
                            .ok_or(GatewayAttemptError::Corrupt)?;
                        let row: SumSlotRecord = serde_json::from_slice(bytes)
                            .map_err(|_| GatewayAttemptError::Corrupt)?;
                        if canonical(&row)? != bytes
                            || row.schema != SUM_SLOT_SCHEMA
                            || row.counter != hex::encode(counter.key)
                            || row.slot != previous
                            || row.amount > row.cumulative
                            || row.cumulative != *total
                            || row.window_seconds != bound.window_seconds
                            || row.window_index != bound.window_index
                            || row.window_end != bound.window_end
                            || row.cumulative > counter.capacity
                        {
                            return Err(GatewayAttemptError::Corrupt);
                        }
                    }
                }
            }
        }
        encode(record)
    })
}

impl GatewayAttempts {
    /// Claims one logical ID together with one slot of every count and sum
    /// counter `bound` names, in one all-or-none batch, before credential
    /// access or transport entry. Unbounded effects insert only the claim.
    /// Slots are never released, and a replay consumes none.
    ///
    /// # Errors
    /// An identical reserved binding reopens without another charge. An existing
    /// grant or terminal operation is `Replay`; a changed binding is
    /// `BindingConflict`. Reopening itself never authorizes provider entry.
    pub(crate) async fn claim_bounded(
        &self,
        approved: &Arc<ApprovedEffect>,
        evaluated_at: u64,
        validation: crate::entry::EntryValidation,
    ) -> Result<BoundedClaim, GatewayAttemptError> {
        match self
            .claim_new_bounded(approved, evaluated_at, validation)
            .await
        {
            Err(GatewayAttemptError::Replay) => {
                let request = &approved
                    .command()
                    .ok_or(GatewayAttemptError::InvalidTransition)?
                    .request;
                let (stored, record) = self
                    .load(request.namespace(), request.operation_id())
                    .await?
                    .ok_or(GatewayAttemptError::Unavailable)?;
                if record.binding_canonical.as_bytes()
                    != approved
                        .effect()
                        .binding()
                        .to_private_bytes()
                        .map_err(|_| GatewayAttemptError::Corrupt)?
                        .as_slice()
                {
                    return Err(GatewayAttemptError::BindingConflict);
                }
                if record.state.stage != GatewayAttemptStage::Reserved {
                    return Err(GatewayAttemptError::Replay);
                }
                // This handle grants no entry. A fresh fenced CAS still checks
                // native authority, approval and every retained slot.
                Ok(BoundedClaim::Claimed(Box::new(ClaimedGatewayAttempt {
                    attempt: Attempt {
                        store: Arc::clone(&self.store),
                        key: self.key(request.namespace(), request.operation_id())?,
                        stored,
                        record,
                    },
                })))
            }
            result => result,
        }
    }

    async fn claim_new_bounded(
        &self,
        approved: &Arc<ApprovedEffect>,
        evaluated_at: u64,
        validation: crate::entry::EntryValidation,
    ) -> Result<BoundedClaim, GatewayAttemptError> {
        let command = approved
            .command()
            .ok_or(GatewayAttemptError::InvalidTransition)?;
        let request = &command.request;
        let binding = approved.effect().binding();
        if !self.policy.contains(binding) {
            return Err(GatewayAttemptError::BindingConflict);
        }
        let key = self.key(request.namespace(), request.operation_id())?;
        let expected = String::from_utf8(
            binding
                .to_private_bytes()
                .map_err(|_| GatewayAttemptError::Corrupt)?
                .to_vec(),
        )
        .map_err(|_| GatewayAttemptError::Corrupt)?;
        let store = Arc::clone(&self.store);
        let bound = command.bound.clone();
        let admission = Admission {
            approved: Arc::clone(approved),
            validation,
            authorization_started_at: evaluated_at,
        };
        let reserved = blocking(move || {
            // History precedes candidate admission. Expiry cannot erase replay
            // or turn an existing reservation into a new charged operation.
            if store.load(GatewayRecordKind::Attempt, &key)?.is_some() {
                return Err(existing_binding(&*store, key, &expected));
            }
            let base = claim_record(
                &admission
                    .approved
                    .command()
                    .ok_or(GatewayAttemptError::InvalidTransition)?
                    .request,
                admission.approved.effect().binding(),
                admission.approved.approval(),
                evaluated_at,
            )?;
            let result = match &bound {
                Some(bound) => reserve_with_claim(&*store, key, &base, bound, &admission),
                None => {
                    let mut record = base.clone();
                    let entries = [GatewayRecordEntry {
                        kind: GatewayRecordKind::Attempt,
                        key,
                        record: encode(&record)?,
                        expires_at: None,
                    }];
                    match insert_claim(&*store, &mut record, &entries, &admission, None, &[], &[])?
                    {
                        GatewayInsert::Inserted => Ok(Reserved::Claimed {
                            stored: encode(&record)?,
                            record: Box::new(record),
                        }),
                        GatewayInsert::Exists { .. } => Err(GatewayAttemptError::Replay),
                    }
                }
            };
            match result {
                Err(GatewayAttemptError::Replay) => {
                    Err(existing_binding(&*store, key, &base.binding_canonical))
                }
                result => result,
            }
        })
        .await?;
        Ok(match reserved {
            Reserved::Claimed { stored, record } => {
                BoundedClaim::Claimed(Box::new(ClaimedGatewayAttempt {
                    attempt: Attempt {
                        store: Arc::clone(&self.store),
                        key,
                        stored,
                        record: *record,
                    },
                }))
            }
            Reserved::Exhausted(code) => BoundedClaim::Exhausted(code),
            Reserved::Contended => BoundedClaim::Contended,
        })
    }
}

#[cfg(test)]
#[path = "entry_tests.rs"]
mod entry_tests;
