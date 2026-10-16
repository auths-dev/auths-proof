//! Durable gateway records: one-use attempt claims, count and sum slots, and
//! the shared connection record. This store does not infer provider effect.
//!
//! [`GatewayAttempts`] owns the attempt record format
//! `auths.gateway-attempt/3`, its stages, and which stage changes are valid;
//! the transition rule itself is the translated leaf
//! `auths_gateway_kernel::transition::valid_transition`. Records persist
//! through a [`GatewayAttemptStore`], which is only an all-or-none
//! insert-once, compare-and-swap, and sweep mechanism over opaque bounded
//! bytes of five closed kinds: [`FileGatewayAttemptStore`] for one host, and
//! the multi-host `PostgresLifecycleStore`, whose production qualification is
//! still open.

use crate::recipe::ObservationTemplate;
use crate::{
    ClosedObservationRequest, ClosedProviderRequest, LogicalOperationId, OperatorNamespace,
    echo_token,
};
use auths_gateway_kernel::transition::{self, AttemptView, Link, Reading, Stage};
use auths_lifecycle::StoreError;
use auths_stores::{
    GatewayRecordInsert, PostgresLifecycleStore, advance_gateway_collection, gateway_window_open,
};
use base64ct::{Base64, Encoding as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Component, Path, PathBuf},
    sync::Arc,
};
use tempfile::NamedTempFile;
use thiserror::Error;

pub use auths_stores::GatewayRecordKind;

const SCHEMA: &str = "auths.gateway-attempt/3";
const PRE_ENTRY_DOMAIN: &[u8] = b"auths.gateway-pre-entry/1\0";
const BATCH_SCHEMA: &str = "auths.gateway-file-batch/1";
const SLOT_FILE_SCHEMA: &str = "auths.gateway-file-slot/1";
const BATCH_FILE: &str = ".batch.json";
const LOCK_FILE: &str = ".replace.lock";
const COLLECTION_FILE: &str = ".collection.json";
const FILE_STORE_SCHEMA: &str = "auths.gateway-file-store/1";
const MAX_COLLECTION_FILE_BYTES: usize = 512;
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
    /// Transport may have started; restart projects this to `Unknown`.
    Attempting,
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
            Self::Attempting => Stage::Attempting,
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
}

impl GatewayAttemptSnapshot {
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
struct Record {
    schema: String,
    namespace: String,
    operation_id: String,
    action_commitment: String,
    recipe_digest: String,
    nonce: String,
    evaluated_at: u64,
    stage: GatewayAttemptStage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refusal: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    counters: Vec<CounterWire>,
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
}

/// The fields no transition may change, in a fixed order.
#[derive(Serialize)]
struct FixedFields<'a> {
    schema: &'a str,
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
        self.observation_plan
            .as_ref()
            .map_or(Link::None, ObservationTemplate::link)
    }

    /// The projection the translated transition rule inspects.
    fn view(&self) -> Result<AttemptView, GatewayAttemptError> {
        let reading = match (self.observation_match, self.observation_fact) {
            (None, None) => Reading::None,
            (Some(true), None) => Reading::Match,
            (Some(false), None) => Reading::Mismatch,
            (Some(false), Some(GatewayObservationFact::EchoMismatch)) => Reading::EchoMismatch,
            (Some(true) | None, Some(_)) => return Err(GatewayAttemptError::Corrupt),
        };
        let response = match (self.response_status, &self.response_digest) {
            (None, None) => Vec::new(),
            (Some(status), Some(digest)) => canonical(&(status, digest))?,
            _ => return Err(GatewayAttemptError::Corrupt),
        };
        Ok(AttemptView {
            fixed: canonical(&FixedFields {
                schema: &self.schema,
                namespace: &self.namespace,
                operation_id: &self.operation_id,
                action_commitment: &self.action_commitment,
                recipe_digest: &self.recipe_digest,
                nonce: &self.nonce,
                evaluated_at: self.evaluated_at,
                counters: &self.counters,
                observation_plan: self.observation_plan.as_ref(),
            })?,
            stage: self.stage.kernel(),
            refusal: self.refusal.is_some(),
            pre_entry: self
                .pre_entry
                .as_ref()
                .map(canonical)
                .transpose()?
                .unwrap_or_default(),
            response,
            locator: self
                .response_locator
                .as_ref()
                .map(canonical)
                .transpose()?
                .unwrap_or_default(),
            reading,
            evidence: self.provider_evidence.is_some(),
            observation: self.observation_plan.is_some(),
            link: self.link(),
        })
    }

    /// The read-back request of the stored plan and locator, when one can
    /// be built.
    fn observation_request(&self) -> Option<ClosedObservationRequest> {
        self.observation_plan
            .as_ref()?
            .request(self.response_locator.as_ref())
    }

    fn counters(&self) -> Result<Vec<GatewayCounterEntry>, GatewayAttemptError> {
        if self.counters.len() > MAX_COUNTERS {
            return Err(GatewayAttemptError::Corrupt);
        }
        let counters = self
            .counters
            .iter()
            .map(|entry| {
                Ok(GatewayCounterEntry {
                    kind: entry.kind,
                    counter: digest_bytes(&entry.counter)?,
                    slot: entry.slot,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if counters.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(GatewayAttemptError::Corrupt);
        }
        Ok(counters)
    }

    fn locator_valid(&self) -> bool {
        match (&self.response_locator, &self.observation_plan) {
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
        if self.schema != SCHEMA
            || self.nonce.len() != 32
            || !self
                .nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !self.refusal.as_deref().is_none_or(valid_code)
            || !self
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
            .response_digest
            .as_deref()
            .map(digest_bytes)
            .transpose()?;
        if self
            .response_status
            .is_some_and(|status| !(100..=599).contains(&status))
        {
            return Err(GatewayAttemptError::Corrupt);
        }
        let provider_evidence = match &self.provider_evidence {
            Some(wire) => {
                let locator = self
                    .observation_request()
                    .ok_or(GatewayAttemptError::Corrupt)?;
                Some(wire.decode(locator.url(), &self.echo_token()?)?)
            }
            None => None,
        };
        let pre_entry = self
            .pre_entry
            .as_ref()
            .map(PreEntryWire::decode)
            .transpose()?;
        Ok(GatewayAttemptSnapshot {
            namespace,
            operation_id,
            action_commitment,
            recipe_digest,
            evaluated_at: self.evaluated_at,
            stage: if recovered && self.stage == GatewayAttemptStage::Attempting {
                GatewayAttemptStage::Unknown
            } else {
                self.stage
            },
            refusal: self.refusal.clone(),
            counters: self.counters()?,
            response_status: self.response_status,
            response_digest,
            response_locator: self.response_locator.clone(),
            observation_match: self.observation_match,
            observation_fact: self.observation_fact,
            provider_evidence,
            pre_entry,
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
    /// Derives the key of `operation_id` in `namespace`.
    #[must_use]
    pub fn for_operation(namespace: &OperatorNamespace, operation_id: &LogicalOperationId) -> Self {
        let preimage = auths_gateway_kernel::identity::logical_operation_preimage(
            namespace.as_str().as_bytes(),
            operation_id.as_str().as_bytes(),
        );
        Self(Sha256::digest(preimage).into())
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
    /// At least one slot belongs to a closed window; nothing was inserted.
    ClosedWindow {
        /// The shared durable cutoff checked atomically with this batch.
        collected_through: u64,
    },
}

/// Durable storage of opaque gateway records of five closed kinds.
/// Implementations never interpret the bytes.
///
/// Every implementation must pass the same conformance suite: one winner per
/// key across processes, all-or-none batches, no lost replacement, bounded
/// sweeps of expired slots only, and fail-closed reads that never report
/// unreadable state as absent.
pub trait GatewayAttemptStore: Send + Sync {
    /// Inserts every entry only when every key is absent and every slot's
    /// expiry is strictly after the shared durable collection cutoff. The
    /// cutoff check and insertion have one ordered linearization point.
    ///
    /// # Errors
    /// Returns [`GatewayAttemptError::Corrupt`] for an entry outside its
    /// bounds and [`GatewayAttemptError::Unavailable`] when storage fails.
    /// An unavailable result may follow an all-or-none commit whose
    /// acknowledgement was lost; it must never produce an execution handle.
    fn insert_all(
        &self,
        entries: &[GatewayRecordEntry],
    ) -> Result<GatewayInsert, GatewayAttemptError>;

    /// Inserts one entry only when its key has never been stored.
    ///
    /// # Errors
    /// Returns [`GatewayAttemptError::Replay`] when the key already exists,
    /// including a record left by a crashed claim, and
    /// [`GatewayAttemptError::InvalidTransition`] for a slot in a closed window.
    fn insert(&self, entry: &GatewayRecordEntry) -> Result<(), GatewayAttemptError> {
        match self.insert_all(std::slice::from_ref(entry))? {
            GatewayInsert::Inserted => Ok(()),
            GatewayInsert::Exists { .. } => Err(GatewayAttemptError::Replay),
            GatewayInsert::ClosedWindow { .. } => Err(GatewayAttemptError::InvalidTransition),
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
    /// before `now`, and returns how many were deleted. Durably advances a
    /// shared monotone cutoff before deletion (or atomically with it), even
    /// when `limit` is zero. Claims and the cutoff are never collected.
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

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CollectionFile {
    schema: String,
    collected_through: Option<u64>,
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
    /// batch file, obsolete unmarked state, missing security metadata or
    /// lock state, and I/O errors. It initializes only a fresh empty directory.
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
        store.initialize_collection()?;
        store.recover()?;
        Ok(store)
    }

    fn initialize_collection(&self) -> Result<(), GatewayAttemptError> {
        let (lock, fresh) = if self.root.join(COLLECTION_FILE).exists() {
            (
                Self::lock_options()
                    .open(self.root.join(LOCK_FILE))
                    .map_err(|error| {
                        if error.kind() == std::io::ErrorKind::NotFound {
                            GatewayAttemptError::Corrupt
                        } else {
                            GatewayAttemptError::Unavailable
                        }
                    })?,
                false,
            )
        } else {
            match Self::lock_options()
                .create_new(true)
                .open(self.root.join(LOCK_FILE))
            {
                Ok(lock) => (lock, true),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (
                    Self::lock_options()
                        .open(self.root.join(LOCK_FILE))
                        .map_err(|_| GatewayAttemptError::Unavailable)?,
                    false,
                ),
                Err(_) => return Err(GatewayAttemptError::Unavailable),
            }
        };
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)
            .map_err(|_| GatewayAttemptError::Unavailable)?;
        if self.root.join(COLLECTION_FILE).exists() {
            if fresh {
                return Err(GatewayAttemptError::Corrupt);
            }
            self.collection_cutoff()?;
            return Ok(());
        }
        if !fresh {
            return Err(GatewayAttemptError::Corrupt);
        }
        // An unmarked nonempty store is obsolete or lost security state.
        // Never interpret a missing cutoff as an empty collection history.
        for entry in fs::read_dir(&self.root).map_err(|_| GatewayAttemptError::Unavailable)? {
            let entry = entry.map_err(|_| GatewayAttemptError::Unavailable)?;
            if entry.file_name().to_str() != Some(LOCK_FILE) {
                return Err(GatewayAttemptError::Corrupt);
            }
        }
        let bytes = canonical(&CollectionFile {
            schema: FILE_STORE_SCHEMA.to_owned(),
            collected_through: None,
        })?;
        self.pending(&bytes)?
            .persist_noclobber(self.root.join(COLLECTION_FILE))
            .map_err(|_| GatewayAttemptError::Unavailable)?;
        sync_directory(&self.root)
    }

    fn collection_cutoff(&self) -> Result<Option<u64>, GatewayAttemptError> {
        let bytes = Self::read_file(&self.root.join(COLLECTION_FILE), MAX_COLLECTION_FILE_BYTES)?
            .ok_or(GatewayAttemptError::Corrupt)?;
        let state: CollectionFile =
            serde_json::from_slice(&bytes).map_err(|_| GatewayAttemptError::Corrupt)?;
        if state.schema != FILE_STORE_SCHEMA || canonical(&state)? != bytes {
            return Err(GatewayAttemptError::Corrupt);
        }
        if state
            .collected_through
            .is_some_and(|cutoff| i64::try_from(cutoff).is_err())
        {
            return Err(GatewayAttemptError::Corrupt);
        }
        Ok(state.collected_through)
    }

    fn publish_collection(&self, now: u64) -> Result<(), GatewayAttemptError> {
        i64::try_from(now).map_err(|_| GatewayAttemptError::Corrupt)?;
        let next = advance_gateway_collection(self.collection_cutoff()?, now);
        let bytes = canonical(&CollectionFile {
            schema: FILE_STORE_SCHEMA.to_owned(),
            collected_through: Some(next),
        })?;
        self.pending(&bytes)?
            .persist(self.root.join(COLLECTION_FILE))
            .map_err(|_| GatewayAttemptError::Unavailable)?;
        // No deletion can begin until both the replacement file and its
        // directory entry have been synchronized successfully.
        sync_directory(&self.root)
    }

    fn file_name(kind: GatewayRecordKind, key: &GatewayAttemptKey) -> String {
        let prefix = match kind {
            GatewayRecordKind::Attempt => "claim-",
            GatewayRecordKind::CountSlot => "slot-",
            GatewayRecordKind::SumSlot => "sum-",
            GatewayRecordKind::Connection => "conn-",
            GatewayRecordKind::CommissioningBudget => "commission-",
        };
        format!("{prefix}{}.json", hex::encode(key.as_bytes()))
    }

    fn path_for(&self, kind: GatewayRecordKind, key: &GatewayAttemptKey) -> PathBuf {
        self.root.join(Self::file_name(kind, key))
    }

    fn key_exists(&self, key: &GatewayAttemptKey) -> Result<bool, GatewayAttemptError> {
        for kind in [
            GatewayRecordKind::Attempt,
            GatewayRecordKind::CountSlot,
            GatewayRecordKind::SumSlot,
            GatewayRecordKind::Connection,
            GatewayRecordKind::CommissioningBudget,
        ] {
            match fs::symlink_metadata(self.path_for(kind, key)) {
                Ok(_) => return Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(GatewayAttemptError::Unavailable),
            }
        }
        Ok(false)
    }

    fn read_file(path: &Path, maximum: usize) -> Result<Option<Vec<u8>>, GatewayAttemptError> {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(GatewayAttemptError::Unavailable),
        };
        let maximum = u64::try_from(maximum).map_err(|_| GatewayAttemptError::Corrupt)?;
        let metadata = file
            .metadata()
            .map_err(|_| GatewayAttemptError::Unavailable)?;
        if !metadata.is_file() || metadata.len() > maximum {
            return Err(GatewayAttemptError::Corrupt);
        }
        let read_limit = maximum.checked_add(1).ok_or(GatewayAttemptError::Corrupt)?;
        let mut bytes = Vec::new();
        file.take(read_limit)
            .read_to_end(&mut bytes)
            .map_err(|_| GatewayAttemptError::Unavailable)?;
        if bytes.is_empty() || u64::try_from(bytes.len()).map_or(true, |length| length > maximum) {
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

    fn lock_options() -> OpenOptions {
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        options
    }

    fn lock(&self, operation: rustix::fs::FlockOperation) -> Result<File, GatewayAttemptError> {
        let lock = Self::lock_options()
            .open(self.root.join(LOCK_FILE))
            .map_err(|_| GatewayAttemptError::Unavailable)?;
        rustix::fs::flock(&lock, operation).map_err(|_| GatewayAttemptError::Unavailable)?;
        Ok(lock)
    }

    /// Serializes mutations across every process on this host.
    fn exclusive(&self) -> Result<File, GatewayAttemptError> {
        let lock = self.lock(rustix::fs::FlockOperation::LockExclusive)?;
        self.collection_cutoff()?;
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
            self.collection_cutoff()?;
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
        let files = entries
            .iter()
            .map(|entry| {
                Ok((
                    Self::file_name(entry.kind, &entry.key),
                    Self::file_bytes(entry)?,
                ))
            })
            .collect::<Result<Vec<_>, GatewayAttemptError>>()?;
        let _lock = self.exclusive()?;
        let cutoff = self.collection_cutoff()?;
        for entry in entries {
            if let Some(expiry) = entry.expires_at
                && !gateway_window_open(expiry, cutoff)
            {
                return Ok(GatewayInsert::ClosedWindow {
                    collected_through: cutoff.ok_or(GatewayAttemptError::Corrupt)?,
                });
            }
        }
        for (index, entry) in entries.iter().enumerate() {
            if self.key_exists(&entry.key)? {
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
            self.pending(bytes)?
                .persist_noclobber(self.root.join(name))
                .map_err(|_| GatewayAttemptError::Unavailable)?;
        }
        sync_directory(&self.root)?;
        if crash == Some(BatchCrash::BeforeBatchDelete) {
            return Ok(GatewayInsert::Inserted);
        }
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
    let Some(rest) = ["claim-", "slot-", "sum-", "conn-", "commission-"]
        .iter()
        .find_map(|prefix| name.strip_prefix(prefix))
    else {
        return false;
    };
    rest.strip_suffix(".json").is_some_and(|key| {
        key.len() == 64
            && key
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

impl GatewayAttemptStore for FileGatewayAttemptStore {
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
        if let Some(expiry) = entry.expires_at
            && !gateway_window_open(expiry, self.collection_cutoff()?)
        {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        if self.key_exists(&entry.key)? {
            return Err(GatewayAttemptError::Replay);
        }
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
        let path = self.path_for(kind, key);
        let record = if kind.expires() {
            Self::read_file(&path, MAX_SLOT_FILE_BYTES)?
                .map(|bytes| Self::decode_slot(&bytes).map(|(_, record)| record))
                .transpose()
        } else {
            Self::read_file(&path, MAX_RECORD_BYTES)
        }?;
        if record.is_none() && self.key_exists(key)? {
            return Err(GatewayAttemptError::Corrupt);
        }
        Ok(record)
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
        self.publish_collection(now)?;
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
            Ok(GatewayRecordInsert::ClosedWindow { collected_through }) => {
                Ok(GatewayInsert::ClosedWindow { collected_through })
            }
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

/// The plan a reopened attempt must match: the one a new verified request
/// resolves to, or, for the operator's re-observation, the stored one.
#[derive(Clone, Copy)]
enum ExpectedPlan<'a> {
    Request(Option<&'a ObservationTemplate>),
    Stored,
}

/// A fresh `attempting` claim record for `request`, with a random nonce and
/// no counters.
fn claim_record(
    request: &ClosedProviderRequest,
    recipe_digest: [u8; 32],
    evaluated_at: u64,
) -> Result<Record, GatewayAttemptError> {
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| GatewayAttemptError::Unavailable)?;
    let record = Record {
        schema: SCHEMA.to_owned(),
        namespace: request.namespace().as_str().to_owned(),
        operation_id: request.operation_id().as_str().to_owned(),
        action_commitment: hex::encode(request.action_commitment()),
        recipe_digest: hex::encode(recipe_digest),
        nonce: hex::encode(nonce),
        evaluated_at,
        stage: GatewayAttemptStage::Attempting,
        refusal: None,
        counters: Vec::new(),
        response_status: None,
        response_digest: None,
        response_locator: None,
        observation_plan: request.observation_template().cloned(),
        observation_match: None,
        observation_fact: None,
        provider_evidence: None,
        pre_entry: None,
    };
    record.snapshot(false)?;
    Ok(record)
}

/// Gateway attempt semantics over one durable [`GatewayAttemptStore`].
#[derive(Clone)]
pub struct GatewayAttempts {
    store: Arc<dyn GatewayAttemptStore>,
}

impl GatewayAttempts {
    /// Uses `store` for every claim and stage change.
    #[must_use]
    pub fn new(store: Arc<dyn GatewayAttemptStore>) -> Self {
        Self { store }
    }

    /// Returns the underlying mechanism.
    #[must_use]
    pub fn store(&self) -> Arc<dyn GatewayAttemptStore> {
        Arc::clone(&self.store)
    }

    /// Claims one logical ID before credential access or transport entry. The
    /// record keeps the request's verified action commitment, the gateway
    /// evaluation time, and the observation plan; a later echo token is
    /// always derived from this record.
    ///
    /// # Errors
    /// An existing record, including a crashed claim, is `Replay`.
    pub async fn claim(
        &self,
        request: &ClosedProviderRequest,
        recipe_digest: [u8; 32],
        evaluated_at: u64,
    ) -> Result<ClaimedGatewayAttempt, GatewayAttemptError> {
        let key = GatewayAttemptKey::for_operation(request.namespace(), request.operation_id());
        let record = claim_record(request, recipe_digest, evaluated_at)?;
        let stored = encode(&record)?;
        let store = Arc::clone(&self.store);
        let entry = GatewayRecordEntry {
            kind: GatewayRecordKind::Attempt,
            key,
            record: stored.clone(),
            expires_at: None,
        };
        blocking(move || store.insert(&entry)).await?;
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
    /// keys each one and its conservative stage. Nothing else of an attempt
    /// is returned: no operation identifier, argument, or provider value.
    ///
    /// # Errors
    /// Malformed state is a hard failure.
    pub async fn stages(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, GatewayAttemptStage)>, GatewayAttemptError> {
        let store = Arc::clone(&self.store);
        blocking(move || {
            store
                .attempt_keys(limit)?
                .into_iter()
                .filter_map(|key| {
                    let stage = store
                        .load(GatewayRecordKind::Attempt, &key)
                        .and_then(|bytes| bytes.map(|bytes| decode(&bytes)).transpose())
                        .and_then(|record| record.map(|record| record.snapshot(true)).transpose());
                    match stage {
                        Ok(Some(snapshot)) => {
                            Some(Ok((hex::encode(key.as_bytes()), snapshot.stage())))
                        }
                        // Deleted between the listing and the read.
                        Ok(None) => None,
                        Err(error) => Some(Err(error)),
                    }
                })
                .collect()
        })
        .await
    }

    /// Reads a secret-free durable snapshot. An `attempting` stage is
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

    /// Reopens a stored attempt for one read-only observation from its
    /// stored plan. It returns `None` unless the recipe digest is unchanged,
    /// the new verified request resolves to the same plan, and the stage can
    /// be resolved by a read-back: an `attempting` or `unknown` record only
    /// for a verified-locator link, and a `response-recorded` record for any
    /// declared link whose locator is recorded. A re-observation records only
    /// positive evidence under compare-and-swap, so it may run while the
    /// original attempt is in flight; the in-flight process then loses its
    /// own compare-and-swap, and no second write happens either way.
    ///
    /// # Errors
    /// Malformed state is a hard failure.
    pub async fn resume_observable(
        &self,
        request: &ClosedProviderRequest,
        recipe_digest: [u8; 32],
    ) -> Result<Option<ObservableGatewayAttempt>, GatewayAttemptError> {
        self.resume(
            request.namespace(),
            request.operation_id(),
            recipe_digest,
            ExpectedPlan::Request(request.observation_template()),
        )
        .await
    }

    /// Reopens a stored attempt for the operator's read-only
    /// re-observation, under the rules of
    /// [`Self::resume_observable`] except that the plan comes from the
    /// stored record alone, since the operator supplies no request.
    ///
    /// # Errors
    /// Malformed state is a hard failure.
    pub async fn resume_observable_operation(
        &self,
        namespace: &OperatorNamespace,
        operation_id: &LogicalOperationId,
        recipe_digest: [u8; 32],
    ) -> Result<Option<ObservableGatewayAttempt>, GatewayAttemptError> {
        self.resume(namespace, operation_id, recipe_digest, ExpectedPlan::Stored)
            .await
    }

    async fn resume(
        &self,
        namespace: &OperatorNamespace,
        operation_id: &LogicalOperationId,
        recipe_digest: [u8; 32],
        expected_plan: ExpectedPlan<'_>,
    ) -> Result<Option<ObservableGatewayAttempt>, GatewayAttemptError> {
        let Some((stored, record)) = self.load(namespace, operation_id).await? else {
            return Ok(None);
        };
        record.snapshot(false)?;
        let link = record.link();
        let stage_resolvable = match record.stage {
            GatewayAttemptStage::Attempting | GatewayAttemptStage::Unknown => {
                transition::resolves_unknown(link)
            }
            GatewayAttemptStage::ResponseRecorded => transition::has_link(link),
            GatewayAttemptStage::NotEntered
            | GatewayAttemptStage::Observed
            | GatewayAttemptStage::ObservedByProvider => false,
        };
        let resumable = stage_resolvable
            && record.recipe_digest == hex::encode(recipe_digest)
            && match expected_plan {
                ExpectedPlan::Request(plan) => record.observation_plan.as_ref() == plan,
                ExpectedPlan::Stored => true,
            }
            && record.observation_request().is_some();
        Ok(resumable.then(|| ObservableGatewayAttempt {
            attempt: Attempt {
                store: Arc::clone(&self.store),
                key: GatewayAttemptKey::for_operation(namespace, operation_id),
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
        let key = GatewayAttemptKey::for_operation(namespace, operation_id);
        let store = Arc::clone(&self.store);
        let Some(bytes) = blocking(move || store.load(GatewayRecordKind::Attempt, &key)).await?
        else {
            return Ok(None);
        };
        let record = decode(&bytes)?;
        if record.namespace != namespace.as_str() || record.operation_id != operation_id.as_str() {
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
struct Attempt {
    store: Arc<dyn GatewayAttemptStore>,
    key: GatewayAttemptKey,
    stored: Vec<u8>,
    record: Record,
}

impl Attempt {
    /// Persists `next` only as a valid stage change from the exact stored
    /// record; a concurrent change by another process is a conflict.
    async fn advance(mut self, next: Record) -> Result<Self, GatewayAttemptError> {
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

/// A durable claim token; dropping it without a result leaves `unknown` on
/// restart and never permits another automatic write.
pub struct ClaimedGatewayAttempt {
    attempt: Attempt,
}

impl ClaimedGatewayAttempt {
    /// Records, once and before transport entry, what was read after the
    /// lease: the pre-entry observations and the relative-ceiling basis.
    ///
    /// # Errors
    /// Rejects an empty or repeated checkpoint and persistence failure.
    pub async fn record_checkpoint(
        self,
        pre_entry: &GatewayPreEntry,
    ) -> Result<Self, GatewayAttemptError> {
        let mut next = self.attempt.record.clone();
        next.pre_entry = PreEntryWire::encode(pre_entry)?;
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
        next.stage = GatewayAttemptStage::NotEntered;
        next.refusal = Some(refusal.to_owned());
        if let Some(pre_entry) = pre_entry
            && next.pre_entry.is_none()
        {
            next.pre_entry = PreEntryWire::encode(pre_entry)?;
        }
        self.attempt.advance(next).await?.record.snapshot(false)
    }

    /// Records an ambiguous outcome while retaining replay history.
    ///
    /// # Errors
    /// Persistence failure does not permit a retry.
    pub async fn record_unknown(self) -> Result<GatewayAttemptSnapshot, GatewayAttemptError> {
        let mut next = self.attempt.record.clone();
        next.stage = GatewayAttemptStage::Unknown;
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
        next.stage = GatewayAttemptStage::ResponseRecorded;
        next.response_status = Some(status);
        next.response_digest = Some(hex::encode(digest));
        next.response_locator = locator;
        Ok(ObservableGatewayAttempt {
            attempt: self.attempt.advance(next).await?,
        })
    }
}

/// A stored attempt that may be advanced only by a separate read-only
/// observation, never by another write.
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

    /// Returns this attempt's echo token, derived from the stored verified
    /// commitment, when the recipe declared an echo field.
    #[must_use]
    pub fn echo_token(&self) -> Option<String> {
        self.attempt
            .record
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
    pub async fn record_observation(
        self,
        matched: bool,
    ) -> Result<GatewayAttemptSnapshot, GatewayAttemptError> {
        let mut next = self.attempt.record.clone();
        next.stage = GatewayAttemptStage::Observed;
        next.observation_match = Some(matched);
        self.attempt.advance(next).await?.record.snapshot(false)
    }

    /// Records `observed` with `matched: false` and the `echo-mismatch` fact.
    /// Only a `response-recorded` attempt can take this transition.
    ///
    /// # Errors
    /// Persistence failure retains only the recorded response.
    pub async fn record_echo_mismatch(self) -> Result<GatewayAttemptSnapshot, GatewayAttemptError> {
        let mut next = self.attempt.record.clone();
        next.stage = GatewayAttemptStage::Observed;
        next.observation_match = Some(false);
        next.observation_fact = Some(GatewayObservationFact::EchoMismatch);
        self.attempt.advance(next).await?.record.snapshot(false)
    }

    /// Records terminal `observed-by-provider` with the exact response bytes.
    /// The caller must already have found this attempt's token in them; the
    /// stored token is re-derived from this record, never taken from input.
    ///
    /// # Errors
    /// Rejects a recipe without echo, empty or oversized evidence, and
    /// persistence failure.
    pub async fn record_provider_evidence(
        self,
        evidence: &[u8],
        observed_at: u64,
    ) -> Result<GatewayAttemptSnapshot, GatewayAttemptError> {
        let record = &self.attempt.record;
        let locator = record
            .observation_request()
            .filter(|_| {
                record
                    .observation_plan
                    .as_ref()
                    .is_some_and(|plan| plan.echo_pointer.is_some())
            })
            .ok_or(GatewayAttemptError::InvalidTransition)?;
        if evidence.is_empty() || evidence.len() > MAX_EVIDENCE_BYTES {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        let mut next = record.clone();
        next.provider_evidence = Some(EvidenceWire {
            channel: GatewayEvidenceChannel::ReadBack,
            locator: locator.url().to_owned(),
            echo: record.echo_token()?,
            evidence_digest: hex::encode(Sha256::digest(evidence)),
            evidence_b64: Base64::encode_string(evidence),
            observed_at,
        });
        next.stage = GatewayAttemptStage::ObservedByProvider;
        self.attempt.advance(next).await?.record.snapshot(false)
    }
}

fn encode(record: &Record) -> Result<Vec<u8>, GatewayAttemptError> {
    let bytes = serde_json::to_vec(record).map_err(|_| GatewayAttemptError::Corrupt)?;
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(GatewayAttemptError::Corrupt);
    }
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> Result<Record, GatewayAttemptError> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(GatewayAttemptError::Corrupt);
    }
    serde_json::from_slice(bytes).map_err(|_| GatewayAttemptError::Corrupt)
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
fn valid_transition(old: &Record, new: &Record) -> Result<bool, GatewayAttemptError> {
    Ok(transition::valid_transition(&old.view()?, &new.view()?) && new.snapshot(false).is_ok())
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
/// grants no execution handle. Storage may have committed before reporting
/// an error; retries must retain the same logical operation identity.
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
    let mut search = auths_gateway_kernel::frontier::FrontierSearch::new(bound);
    while let Some(slot) = search.probe() {
        let key = GatewayAttemptKey(slot_key(counter, slot));
        let occupied = store.load(kind, &key)?.is_some();
        search = search.observe(occupied);
    }
    Ok(search.candidate())
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
    auths_gateway_kernel::slot_record::validate_cumulative(
        record.schema.as_bytes(),
        SUM_SLOT_SCHEMA.as_bytes(),
        record.counter.as_bytes(),
        counter,
        slot,
        auths_gateway_kernel::slot_record::SumValues {
            slot: record.slot,
            amount: record.amount,
            cumulative: record.cumulative,
        },
    )
    .ok_or(GatewayAttemptError::Corrupt)
}

/// Stores `base` alone as `not-entered` with `code`.
fn store_exhausted(
    store: &dyn GatewayAttemptStore,
    key: GatewayAttemptKey,
    base: &Record,
    code: &'static str,
) -> Result<Reserved, GatewayAttemptError> {
    let mut record = base.clone();
    record.stage = GatewayAttemptStage::NotEntered;
    record.refusal = Some(code.to_owned());
    record.snapshot(false)?;
    store.insert(&GatewayRecordEntry {
        kind: GatewayRecordKind::Attempt,
        key,
        record: encode(&record)?,
        expires_at: None,
    })?;
    Ok(Reserved::Exhausted(code))
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
    use auths_gateway_kernel::reservation_batch::{SlotEntry, build_batch};
    let batch = build_batch(
        *key.as_bytes(),
        &bound.counts,
        counts,
        &bound.sums,
        sums,
        totals,
        bound.argument,
    )
    .ok_or(GatewayAttemptError::Corrupt)?;
    let mut record = base.clone();
    let mut counters = Vec::new();
    for entry in &batch {
        let (kind, counter, slot) = match entry {
            SlotEntry::Claim { .. } => continue,
            SlotEntry::Count { counter, slot } => (GatewayCounterKind::Count, *counter, *slot),
            SlotEntry::Sum { counter, slot, .. } => (GatewayCounterKind::Sum, *counter, *slot),
        };
        counters.push(GatewayCounterEntry {
            kind,
            counter,
            slot,
        });
    }
    counters.sort_unstable();
    record.counters = counters
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
    let mut entries = Vec::with_capacity(batch.len());
    for entry in batch {
        match entry {
            SlotEntry::Claim { key: claim_key } => entries.push(GatewayRecordEntry {
                kind: GatewayRecordKind::Attempt,
                key: GatewayAttemptKey(claim_key),
                record: stored.clone(),
                expires_at: None,
            }),
            SlotEntry::Count { counter, slot } => {
                let slot_record = CountSlotRecord {
                    schema: COUNT_SLOT_SCHEMA.to_owned(),
                    counter: hex::encode(counter),
                    slot,
                    window_seconds: bound.window_seconds,
                    window_index: bound.window_index,
                    window_end: bound.window_end,
                    namespace: base.namespace.clone(),
                    operation_id: base.operation_id.clone(),
                    claim: claim.clone(),
                };
                entries.push(GatewayRecordEntry {
                    kind: GatewayRecordKind::CountSlot,
                    key: GatewayAttemptKey(count_slot_key(&counter, slot)),
                    record: canonical(&slot_record)?,
                    expires_at: Some(bound.expires_at()),
                });
            }
            SlotEntry::Sum {
                counter,
                slot,
                amount,
                cumulative,
            } => {
                let slot_record = SumSlotRecord {
                    schema: SUM_SLOT_SCHEMA.to_owned(),
                    counter: hex::encode(counter),
                    slot,
                    amount,
                    cumulative,
                    window_seconds: bound.window_seconds,
                    window_index: bound.window_index,
                    window_end: bound.window_end,
                    namespace: base.namespace.clone(),
                    operation_id: base.operation_id.clone(),
                    claim: claim.clone(),
                };
                entries.push(GatewayRecordEntry {
                    kind: GatewayRecordKind::SumSlot,
                    key: GatewayAttemptKey(sum_slot_key(&counter, slot)),
                    record: canonical(&slot_record)?,
                    expires_at: Some(bound.expires_at()),
                });
            }
        }
    }
    Ok((record, stored, entries))
}

/// Finds each counter's frontier, then inserts the claim and one slot per
/// count and sum counter in one all-or-none batch. A full counter stores
/// the claim alone as `not-entered`; a lost race advances that counter and
/// retries, at most [`MAX_CLAIM_ROUNDS`] times. The count and sum checks are
/// the translated leaves `chain_counts_admit` and `chain_sums_admit`.
/// Parallel capacity views for the pure reservation decision. Compute them
/// once per reservation, retaining them across every slot-conflict retry.
struct ReservationLimits {
    counts: Vec<u64>,
    sums: Vec<u64>,
    slots: Vec<u64>,
}

fn reservation_limits(bound: &crate::bounds::BoundAdmission) -> ReservationLimits {
    ReservationLimits {
        counts: bound
            .counts
            .iter()
            .map(|counter| counter.capacity)
            .collect(),
        sums: bound.sums.iter().map(|counter| counter.capacity).collect(),
        slots: bound.sums.iter().map(|counter| counter.slots).collect(),
    }
}

fn reserve_with_claim(
    store: &dyn GatewayAttemptStore,
    key: GatewayAttemptKey,
    base: &Record,
    bound: &crate::bounds::BoundAdmission,
) -> Result<Reserved, GatewayAttemptError> {
    use crate::bounds::{count_slot_key, sum_slot_key};
    use auths_bounded_policy::kernel::{ReservationCode, reservation_admission};
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
    let limits = reservation_limits(bound);
    for _ in 0..MAX_CLAIM_ROUNDS {
        match reservation_admission(
            &counts,
            &limits.counts,
            &sums,
            &limits.slots,
            &totals,
            &limits.sums,
            bound.argument,
        ) {
            ReservationCode::WindowExhausted => {
                return store_exhausted(store, key, base, "gateway.policy.window-exhausted");
            }
            ReservationCode::SumExhausted => {
                return store_exhausted(store, key, base, "gateway.policy.sum-exhausted");
            }
            ReservationCode::Admit => {}
        }
        let (record, stored, entries) = claim_batch(key, base, bound, &counts, &sums, &totals)?;
        match store.insert_all(&entries)? {
            GatewayInsert::ClosedWindow { .. } => {
                return store_exhausted(store, key, base, "gateway.policy.window-exhausted");
            }
            GatewayInsert::Inserted => {
                return Ok(Reserved::Claimed {
                    stored,
                    record: Box::new(record),
                });
            }
            GatewayInsert::Exists { index } => {
                use auths_gateway_kernel::reservation_retry::{RetryTarget, retry_target};
                match retry_target(index, &counts, &sums, totals.len(), bound.sums.len()) {
                    RetryTarget::Replay => return Err(GatewayAttemptError::Replay),
                    RetryTarget::Corrupt => return Err(GatewayAttemptError::Corrupt),
                    RetryTarget::Count { position, next } => {
                        *counts
                            .get_mut(position)
                            .ok_or(GatewayAttemptError::Corrupt)? = next;
                    }
                    RetryTarget::Sum {
                        position,
                        read_slot,
                        next,
                    } => {
                        let counter = bound
                            .sums
                            .get(position)
                            .ok_or(GatewayAttemptError::Corrupt)?;
                        let total = cumulative(store, &counter.key, read_slot)?;
                        *totals
                            .get_mut(position)
                            .ok_or(GatewayAttemptError::Corrupt)? = total;
                        *sums.get_mut(position).ok_or(GatewayAttemptError::Corrupt)? = next;
                    }
                }
            }
        }
    }
    Ok(Reserved::Contended)
}

impl GatewayAttempts {
    /// Claims one logical ID together with one slot of every count and sum
    /// counter `bound` names, in one all-or-none batch, before credential
    /// access or transport entry. Without a bound it is [`Self::claim`].
    /// Slots are never released, and a replay consumes none.
    ///
    /// # Errors
    /// An existing claim is `Replay`. A store error grants no execution
    /// handle and may follow a committed batch with a lost acknowledgement.
    /// Retrying preserves the logical operation identity and cannot reclaim
    /// ownership of a batch that already committed.
    pub(crate) async fn claim_bounded(
        &self,
        request: &ClosedProviderRequest,
        recipe_digest: [u8; 32],
        evaluated_at: u64,
        bound: Option<&crate::bounds::BoundAdmission>,
    ) -> Result<BoundedClaim, GatewayAttemptError> {
        let Some(bound) = bound else {
            return self
                .claim(request, recipe_digest, evaluated_at)
                .await
                .map(|claim| BoundedClaim::Claimed(Box::new(claim)));
        };
        let key = GatewayAttemptKey::for_operation(request.namespace(), request.operation_id());
        let base = claim_record(request, recipe_digest, evaluated_at)?;
        let store = Arc::clone(&self.store);
        let bound = bound.clone();
        let reserved = blocking(move || reserve_with_claim(&*store, key, &base, &bound)).await?;
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
mod logical_identity_framing_tests {
    use super::*;

    #[test]
    fn extracted_preimage_preserves_operation_keys() {
        let maximum_namespace = "n".repeat(64);
        let maximum_operation = "o".repeat(128);
        for namespace in [
            "operator",
            "stripe-receivables-test",
            maximum_namespace.as_str(),
        ] {
            for operation in [
                "payment-1",
                "allocation-pi_example",
                maximum_operation.as_str(),
            ] {
                let parsed_namespace = OperatorNamespace::parse(namespace).unwrap();
                let parsed_operation = LogicalOperationId::parse(operation).unwrap();
                let mut reference = Sha256::new();
                reference.update(b"auths.gateway-logical-operation/1\0");
                reference.update(namespace.as_bytes());
                reference.update([0]);
                reference.update(operation.as_bytes());
                let expected: [u8; 32] = reference.finalize().into();
                assert_eq!(
                    GatewayAttemptKey::for_operation(&parsed_namespace, &parsed_operation),
                    GatewayAttemptKey(expected)
                );
            }
        }
    }
}

#[cfg(test)]
mod complete_batch_parity {
    use super::*;

    fn original_claim_batch(
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
        record.counters = counters
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

    fn base() -> Record {
        Record {
            schema: SCHEMA.to_owned(),
            namespace: "batch-parity".to_owned(),
            operation_id: "operation-1".to_owned(),
            action_commitment: hex::encode([3; 32]),
            recipe_digest: hex::encode([4; 32]),
            nonce: hex::encode([5; 16]),
            evaluated_at: 100,
            stage: GatewayAttemptStage::Attempting,
            refusal: None,
            counters: Vec::new(),
            response_status: None,
            response_digest: None,
            response_locator: None,
            observation_plan: None,
            observation_match: None,
            observation_fact: None,
            provider_evidence: None,
            pre_entry: None,
        }
    }

    #[test]
    fn complete_shipping_batch_preserves_all_records_keys_and_expiries() {
        for count in 0..=crate::bounds::MAX_BOUNDED_LINKS {
            for sum in 0..=crate::bounds::MAX_BOUNDED_LINKS {
                let bound = crate::bounds::BoundAdmission {
                    links: Vec::new(),
                    argument: 5,
                    window_seconds: 60,
                    window_index: 1,
                    window_end: 120,
                    counts: (0..count)
                        .map(|index| crate::bounds::CountCounter {
                            key: [u8::try_from(index).expect("small index"); 32],
                            capacity: u64::MAX,
                        })
                        .collect(),
                    sums: (0..sum)
                        .map(|index| crate::bounds::SumCounter {
                            key: [128 + u8::try_from(index).expect("small index"); 32],
                            capacity: u64::MAX,
                            slots: u64::MAX,
                        })
                        .collect(),
                };
                let counts: Vec<_> = (0..count)
                    .map(|index| u64::try_from(index).expect("small index"))
                    .collect();
                let sums: Vec<_> = (0..sum)
                    .map(|index| u64::try_from(index).expect("small index"))
                    .collect();
                let totals = vec![10; sum];
                let key = GatewayAttemptKey([42; 32]);
                let actual =
                    claim_batch(key, &base(), &bound, &counts, &sums, &totals).expect("batch");
                let expected = original_claim_batch(key, &base(), &bound, &counts, &sums, &totals)
                    .expect("old batch");
                assert_eq!(
                    encode(&actual.0).expect("record"),
                    encode(&expected.0).expect("old record")
                );
                assert_eq!(actual.1, expected.1);
                assert_eq!(actual.2, expected.2);
                assert_eq!(actual.2.len(), 1 + count + sum);
            }
        }
    }

    #[test]
    fn mismatched_vectors_cannot_omit_a_required_slot() {
        let bound = crate::bounds::BoundAdmission {
            links: Vec::new(),
            argument: 1,
            window_seconds: 60,
            window_index: 1,
            window_end: 120,
            counts: vec![crate::bounds::CountCounter {
                key: [1; 32],
                capacity: 2,
            }],
            sums: vec![crate::bounds::SumCounter {
                key: [2; 32],
                capacity: 2,
                slots: 2,
            }],
        };
        for (counts, sums, totals) in [
            (vec![], vec![0], vec![0]),
            (vec![0], vec![], vec![0]),
            (vec![0], vec![0], vec![]),
        ] {
            assert!(matches!(
                claim_batch(
                    GatewayAttemptKey([42; 32]),
                    &base(),
                    &bound,
                    &counts,
                    &sums,
                    &totals
                ),
                Err(GatewayAttemptError::Corrupt)
            ));
        }
    }
}

#[cfg(test)]
mod cumulative_record_parity {
    use super::*;

    fn inject_decoded(store: &FileGatewayAttemptStore, key: GatewayAttemptKey, record: Vec<u8>) {
        let entry = GatewayRecordEntry {
            kind: GatewayRecordKind::SumSlot,
            key,
            record,
            expires_at: Some(60),
        };
        fs::write(
            store.path_for(GatewayRecordKind::SumSlot, &key),
            FileGatewayAttemptStore::file_bytes(&entry).expect("slot expiry envelope"),
        )
        .expect("inject decoded fixture");
    }

    // Frozen pre-cutover reader: includes storage lookup and serde decoding,
    // so parity exercises the shipping adapter as well as the pure predicate.
    fn original_cumulative(
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

    #[test]
    fn shipping_cumulative_reader_preserves_exact_decoded_acceptance() {
        let directory = tempfile::tempdir().expect("temporary state");
        let store = FileGatewayAttemptStore::open(
            fs::canonicalize(directory.path())
                .expect("canonical")
                .join("state"),
        )
        .expect("store");
        let counter = [0xab; 32];
        let canonical = hex::encode(counter);
        let mut accepted = 0;
        let mut refused = 0;
        for expected_slot in [0, 1, u64::MAX] {
            let key = GatewayAttemptKey(crate::bounds::sum_slot_key(&counter, expected_slot));
            for schema in [SUM_SLOT_SCHEMA, "wrong"] {
                for stored_counter in [canonical.as_str(), "wrong", &canonical.to_uppercase()] {
                    for slot in [0, 1, u64::MAX] {
                        for amount in [0, 1, u64::MAX] {
                            for total in [0, 1, u64::MAX] {
                                let record = SumSlotRecord {
                                    schema: schema.to_owned(),
                                    counter: stored_counter.to_owned(),
                                    slot,
                                    amount,
                                    cumulative: total,
                                    window_seconds: 60,
                                    window_index: 0,
                                    window_end: 60,
                                    namespace: "test".to_owned(),
                                    operation_id: "test".to_owned(),
                                    claim: "00".repeat(32),
                                };
                                inject_decoded(
                                    &store,
                                    key,
                                    serde_json::to_vec(&record).expect("encode"),
                                );
                                let expected = if schema == SUM_SLOT_SCHEMA
                                    && stored_counter == canonical
                                    && slot == expected_slot
                                    && amount <= total
                                {
                                    accepted += 1;
                                    Ok(total)
                                } else {
                                    refused += 1;
                                    Err(GatewayAttemptError::Corrupt)
                                };
                                assert_eq!(
                                    original_cumulative(&store, &counter, expected_slot),
                                    expected
                                );
                                assert_eq!(cumulative(&store, &counter, expected_slot), expected);
                            }
                        }
                    }
                }
            }
        }
        assert_eq!((accepted, refused), (18, 468));
    }

    #[test]
    fn shipping_cumulative_reader_refuses_missing_and_malformed_records() {
        let directory = tempfile::tempdir().expect("temporary state");
        let store = FileGatewayAttemptStore::open(
            fs::canonicalize(directory.path())
                .expect("canonical")
                .join("state"),
        )
        .expect("store");
        let counter = [0; 32];
        let key = GatewayAttemptKey(crate::bounds::sum_slot_key(&counter, 0));
        assert_eq!(
            cumulative(&store, &counter, 0),
            Err(GatewayAttemptError::Corrupt)
        );
        let valid = serde_json::to_string(&SumSlotRecord {
            schema: SUM_SLOT_SCHEMA.to_owned(),
            counter: hex::encode(counter),
            slot: 0,
            amount: 3,
            cumulative: 7,
            window_seconds: 60,
            window_index: 0,
            window_end: 60,
            namespace: "test".to_owned(),
            operation_id: "test".to_owned(),
            claim: "00".repeat(32),
        })
        .expect("valid baseline");
        inject_decoded(&store, key, valid.as_bytes().to_vec());
        assert_eq!(cumulative(&store, &counter, 0), Ok(7));
        // Every mutation retains all other required fields, so it must fail
        // for the mutated property rather than for an unrelated missing field.
        for malformed in [
            "not-json".to_owned(),
            valid.replacen("\"schema\":", "\"schema\":\"wrong\",\"schema\":", 1),
            valid.replacen("\"slot\":0", "\"slot\":18446744073709551616", 1),
            valid.replacen("\"amount\":3", "\"amount\":-1", 1),
            valid.replacen('{', "{\"unknown\":true,", 1),
        ] {
            inject_decoded(&store, key, malformed.into_bytes());
            assert_eq!(
                cumulative(&store, &counter, 0),
                Err(GatewayAttemptError::Corrupt)
            );
            assert_eq!(
                cumulative(&store, &counter, 0),
                original_cumulative(&store, &counter, 0)
            );
        }
    }
}
