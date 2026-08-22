//! Crash-persistent common operation journal.
//!
//! The journal owns only common durability, replay, quota, and state/effect
//! projection. Profile-owned state, provider results, observations, errors,
//! results, and portable receipts remain opaque bounded canonical bytes.

// Journal methods all return the same closed transition/storage error family;
// keep the state-machine documentation adjacent to each method without
// duplicating that catalogue across the public journal API.
#![allow(clippy::missing_errors_doc)]

#[cfg(feature = "qualification-evidence")]
use auths_lifecycle::ClientRequestIdV1;
use auths_lifecycle::{
    OperationEffectV1, OperationIdV1, OperationProfileV1, OperationProjectionV1, OperationStateV1,
    PreparationBindingV1,
};
#[cfg(any(feature = "qualification-evidence", test))]
use rustix::fs::openat;
use rustix::fs::{FlockOperation, Mode, OFlags, flock, open};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
#[cfg(any(feature = "qualification-evidence", test))]
use std::io::{Read as _, Seek as _, SeekFrom};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Write as _,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tempfile::NamedTempFile;
use thiserror::Error;

#[cfg(not(feature = "qualification-evidence"))]
const DATABASE_MAGIC: &[u8; 8] = b"AUTHSOJ4";
#[cfg(feature = "qualification-evidence")]
const DATABASE_MAGIC: &[u8; 8] = b"AUTHSQJ1";
#[cfg(not(feature = "qualification-evidence"))]
const DATABASE_VERSION: u8 = 4;
#[cfg(feature = "qualification-evidence")]
const DATABASE_VERSION: u8 = 1;
const MAX_DATABASE_BYTES: usize = 1024 * 1024 * 1024;
#[cfg(any(feature = "qualification-evidence", test))]
const MAX_QUALIFICATION_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
const MAX_PRINCIPAL_PENDING: usize = 256;
const MAX_RECOVERY_HANDLE_BYTES: usize = 16 * 1024;
const MAX_ISSUE_BYTES: usize = 64 * 1024;
const MAX_PROFILE_STATE_BYTES: usize = 32 * 1024 * 1024;
const MAX_SEALED_COMMAND_BYTES: usize = 16 * 1024 * 1024;
const MAX_PROVIDER_RESULT_BYTES: usize = 16 * 1024 * 1024;
const MAX_OBSERVATION_BYTES: usize = 16 * 1024 * 1024;
#[cfg(feature = "qualification-evidence")]
const MAX_QUALIFICATION_BOUNDARIES: usize = 16_384;

/// Store-owned durable boundary vocabulary available only in the qualification
/// build. Callers never select one of these kinds directly.
#[cfg(feature = "qualification-evidence")]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum QualificationJournalBoundaryKindV1 {
    Decision,
    Replay,
    Command,
    ProviderEntry,
    ProviderResult,
    Observation,
    ExecutionReceipt,
    RecoveryRequired,
    Terminal,
    Status,
    Recovery,
}

/// Capability-free public projection committed at one exact journal boundary.
#[cfg(feature = "qualification-evidence")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QualificationJournalBoundaryV1 {
    ordinal: u32,
    operation_id: OperationIdV1,
    profile: OperationProfileV1,
    connection_generation: Option<u64>,
    journal_revision: u64,
    request_id: Option<ClientRequestIdV1>,
    kind: QualificationJournalBoundaryKindV1,
    state: OperationStateV1,
    effect: OperationEffectV1,
    terminal: bool,
    completion: Option<JournalCompletionV1>,
    subject_index: Option<u8>,
    subject_sha256: [u8; 32],
    projection_sha256: [u8; 32],
}

#[cfg(feature = "qualification-evidence")]
impl QualificationJournalBoundaryV1 {
    #[must_use]
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    #[must_use]
    pub const fn operation_id(&self) -> &OperationIdV1 {
        &self.operation_id
    }

    #[must_use]
    pub const fn profile(&self) -> &OperationProfileV1 {
        &self.profile
    }

    #[must_use]
    pub const fn connection_generation(&self) -> Option<u64> {
        self.connection_generation
    }

    #[must_use]
    pub const fn journal_revision(&self) -> u64 {
        self.journal_revision
    }

    #[must_use]
    pub const fn request_id(&self) -> Option<ClientRequestIdV1> {
        self.request_id
    }

    #[must_use]
    pub const fn kind(&self) -> QualificationJournalBoundaryKindV1 {
        self.kind
    }

    #[must_use]
    pub const fn state(&self) -> OperationStateV1 {
        self.state
    }

    #[must_use]
    pub const fn effect(&self) -> OperationEffectV1 {
        self.effect
    }

    #[must_use]
    pub const fn terminal(&self) -> bool {
        self.terminal
    }

    #[must_use]
    pub const fn completion(&self) -> Option<JournalCompletionV1> {
        self.completion
    }

    #[must_use]
    pub const fn subject_index(&self) -> Option<u8> {
        self.subject_index
    }

    #[must_use]
    pub const fn subject_sha256(&self) -> &[u8; 32] {
        &self.subject_sha256
    }

    #[must_use]
    pub const fn projection_sha256(&self) -> &[u8; 32] {
        &self.projection_sha256
    }
}

/// Per-profile hard limits transactionally enforced by the journal.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperationJournalLimitsV1 {
    admissions_per_minute: u32,
    active_per_principal: u16,
    unresolved_per_principal: u16,
    durable_bytes_per_principal: u64,
    tombstones_per_principal: u32,
    terminal_retention_seconds: u64,
    idempotency_retention_seconds: u64,
    maximum_receipts: u8,
    maximum_receipt_bytes: u64,
    maximum_result_bytes: u64,
}

impl OperationJournalLimitsV1 {
    /// Constructs one manifest-derived exact limit set.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        admissions_per_minute: u32,
        active_per_principal: u16,
        unresolved_per_principal: u16,
        durable_bytes_per_principal: u64,
        tombstones_per_principal: u32,
        terminal_retention_seconds: u64,
        idempotency_retention_seconds: u64,
        maximum_receipts: u8,
        maximum_receipt_bytes: u64,
        maximum_result_bytes: u64,
    ) -> Result<Self, OperationJournalConfigurationError> {
        if admissions_per_minute == 0
            || admissions_per_minute > 10_000
            || active_per_principal == 0
            || active_per_principal > 1_024
            || unresolved_per_principal == 0
            || unresolved_per_principal > 256
            || unresolved_per_principal > active_per_principal
            || durable_bytes_per_principal < 1024 * 1024
            || durable_bytes_per_principal > 1024 * 1024 * 1024
            || tombstones_per_principal < 1_024
            || tombstones_per_principal > 1_000_000
            || terminal_retention_seconds < 604_800
            || terminal_retention_seconds > 31_536_000
            || idempotency_retention_seconds < terminal_retention_seconds
            || idempotency_retention_seconds > 315_360_000
            || maximum_receipts == 0
            || maximum_receipts > 16
            || maximum_receipt_bytes == 0
            || maximum_receipt_bytes > 8 * 1024 * 1024
            || maximum_result_bytes == 0
            || maximum_result_bytes > 16 * 1024 * 1024
        {
            return Err(OperationJournalConfigurationError::InvalidLimits);
        }
        Ok(Self {
            admissions_per_minute,
            active_per_principal,
            unresolved_per_principal,
            durable_bytes_per_principal,
            tombstones_per_principal,
            terminal_retention_seconds,
            idempotency_retention_seconds,
            maximum_receipts,
            maximum_receipt_bytes,
            maximum_result_bytes,
        })
    }
}

/// One ordered portable receipt retained with an operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JournalReceiptV1 {
    receipt_id: String,
    bytes: Vec<u8>,
}

impl JournalReceiptV1 {
    /// Constructs one bounded receipt entry.
    pub fn new(
        receipt_id: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Result<Self, OperationJournalError> {
        let receipt_id = receipt_id.into();
        if !bounded_ascii_graphic(&receipt_id, 128) || bytes.is_empty() {
            return Err(OperationJournalError::InvalidRecord);
        }
        Ok(Self { receipt_id, bytes })
    }

    /// Returns the portable receipt ID.
    #[must_use]
    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }

    /// Returns the exact portable receipt bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Terminal completion source exposed by generated clients.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum JournalCompletionV1 {
    /// First terminal projection from ordinary execution.
    Fresh,
    /// Exact replay of a retained terminal operation.
    Replayed,
    /// Concrete reconciliation established the terminal result.
    Reconciled,
}

/// Immutable prepare-time decision class retained for receipt verification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum JournalDecisionClassV1 {
    Authorized,
    Denied,
    Indeterminate,
}

/// Immutable execution-receipt outcome persisted before terminal projection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum JournalExecutionOutcomeV1 {
    Succeeded,
    Failed,
    Indeterminate,
}

/// Immutable mint-time facts used to rebuild one execution receipt's profile claims.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JournalExecutionReceiptBasisV1 {
    profile_state: Vec<u8>,
    provider_result: Option<Vec<u8>>,
    observations: Vec<Vec<u8>>,
}

impl JournalExecutionReceiptBasisV1 {
    #[must_use]
    pub fn profile_state(&self) -> &[u8] {
        &self.profile_state
    }

    #[must_use]
    pub fn provider_result(&self) -> Option<&[u8]> {
        self.provider_result.as_deref()
    }

    #[must_use]
    pub fn observations(&self) -> &[Vec<u8>] {
        &self.observations
    }
}

/// Complete durable operation record with opaque profile-owned payloads.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JournalRecordV1 {
    operation_id: OperationIdV1,
    binding: PreparationBindingV1,
    decision_class: JournalDecisionClassV1,
    receipt_action_commitment: [u8; 32],
    receipt_context_commitment: [u8; 32],
    projection: OperationProjectionV1,
    created_at_unix_seconds: u64,
    updated_at_unix_seconds: u64,
    revision: u64,
    recovery_handle: Vec<u8>,
    issue: Option<Vec<u8>>,
    profile_value: Option<Vec<u8>>,
    profile_progress: Option<Vec<u8>>,
    preparation_profile_state: Vec<u8>,
    profile_state: Vec<u8>,
    sealed_command: Option<Vec<u8>>,
    pre_entry_rechecked: bool,
    provider_entered: bool,
    receipt_integrity_failed: bool,
    provider_result: Option<Vec<u8>>,
    observations: Vec<Vec<u8>>,
    receipts: Vec<JournalReceiptV1>,
    execution_outcome: Option<JournalExecutionOutcomeV1>,
    execution_result_commitment: Option<[u8; 32]>,
    execution_receipt_basis: Option<JournalExecutionReceiptBasisV1>,
    completion: Option<JournalCompletionV1>,
}

impl JournalRecordV1 {
    /// Constructs one initial effect-free record after concrete preparation.
    #[allow(clippy::too_many_arguments)]
    pub fn prepared(
        operation_id: OperationIdV1,
        binding: PreparationBindingV1,
        decision_class: JournalDecisionClassV1,
        receipt_action_commitment: [u8; 32],
        receipt_context_commitment: [u8; 32],
        projection: OperationProjectionV1,
        now_unix_seconds: u64,
        recovery_handle: Vec<u8>,
        issue: Option<Vec<u8>>,
        profile_state: Vec<u8>,
        receipts: Vec<JournalReceiptV1>,
    ) -> Result<Self, OperationJournalError> {
        if !matches!(
            projection.state(),
            OperationStateV1::Ready | OperationStateV1::Denied | OperationStateV1::Unavailable
        ) {
            return Err(OperationJournalError::InvalidTransition);
        }
        let preparation_profile_state = profile_state.clone();
        let value = Self {
            operation_id,
            binding,
            decision_class,
            receipt_action_commitment,
            receipt_context_commitment,
            projection,
            created_at_unix_seconds: now_unix_seconds,
            updated_at_unix_seconds: now_unix_seconds,
            revision: 1,
            recovery_handle,
            issue,
            profile_value: None,
            profile_progress: None,
            preparation_profile_state,
            profile_state,
            sealed_command: None,
            pre_entry_rechecked: false,
            provider_entered: false,
            receipt_integrity_failed: false,
            provider_result: None,
            observations: Vec::new(),
            receipts,
            execution_outcome: None,
            execution_result_commitment: None,
            execution_receipt_basis: None,
            completion: None,
        };
        value.validate_common()?;
        Ok(value)
    }

    /// Requires the exact first durable decision boundary, before any
    /// reservation/command, provider entry, reconciliation, terminal state,
    /// or receipt-integrity transition can have occurred.
    ///
    /// Qualification event sources use this instead of reconstructing a
    /// historical decision event from a later mutable journal snapshot.
    pub fn validate_exact_decision_snapshot(&self) -> Result<(), OperationJournalError> {
        self.validate_common()?;
        if self.revision != 1
            || self.created_at_unix_seconds != self.updated_at_unix_seconds
            || !matches!(
                self.projection.state(),
                OperationStateV1::Ready | OperationStateV1::Denied | OperationStateV1::Unavailable
            )
            || self.receipts.len() != 1
            || self.profile_value.is_some()
            || self.profile_progress.is_some()
            || self.preparation_profile_state != self.profile_state
            || self.sealed_command.is_some()
            || self.pre_entry_rechecked
            || self.provider_entered
            || self.receipt_integrity_failed
            || self.provider_result.is_some()
            || !self.observations.is_empty()
            || self.execution_outcome.is_some()
            || self.execution_result_commitment.is_some()
            || self.execution_receipt_basis.is_some()
            || self.completion.is_some()
        {
            return Err(OperationJournalError::InvalidRecord);
        }
        Ok(())
    }

    /// Returns the operation ID.
    #[must_use]
    pub const fn operation_id(&self) -> &OperationIdV1 {
        &self.operation_id
    }

    /// Returns the complete immutable preparation binding.
    #[must_use]
    pub const fn binding(&self) -> &PreparationBindingV1 {
        &self.binding
    }

    /// Returns the immutable decision class signed at preparation.
    #[must_use]
    pub const fn decision_class(&self) -> JournalDecisionClassV1 {
        self.decision_class
    }

    /// Returns the exact domain-separated action commitment signed by the
    /// decision receipt.
    #[must_use]
    pub const fn receipt_action_commitment(&self) -> &[u8; 32] {
        &self.receipt_action_commitment
    }

    /// Returns the exact domain-separated context commitment signed by the
    /// decision receipt.
    #[must_use]
    pub const fn receipt_context_commitment(&self) -> &[u8; 32] {
        &self.receipt_context_commitment
    }

    /// Returns the common state/effect projection.
    #[must_use]
    pub const fn projection(&self) -> OperationProjectionV1 {
        self.projection
    }

    /// Returns the last durable update time.
    #[must_use]
    pub const fn updated_at_unix_seconds(&self) -> u64 {
        self.updated_at_unix_seconds
    }

    /// Returns the optimistic concurrency revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the sealed recovery capability retained for this operation.
    #[must_use]
    pub fn recovery_handle(&self) -> &[u8] {
        &self.recovery_handle
    }

    /// Returns the canonical error envelope when the projection requires one.
    #[must_use]
    pub fn issue(&self) -> Option<&[u8]> {
        self.issue.as_deref()
    }

    /// Returns terminal profile result or partial bytes.
    #[must_use]
    pub fn profile_value(&self) -> Option<&[u8]> {
        self.profile_value.as_deref()
    }

    /// Returns bounded recovery progress bytes.
    #[must_use]
    pub fn profile_progress(&self) -> Option<&[u8]> {
        self.profile_progress.as_deref()
    }

    /// Returns the concrete vertical's opaque durable state.
    #[must_use]
    pub fn profile_state(&self) -> &[u8] {
        &self.profile_state
    }

    /// Returns the immutable profile state captured before any lifecycle mutation.
    #[must_use]
    pub fn preparation_profile_state(&self) -> &[u8] {
        &self.preparation_profile_state
    }

    /// Returns the exact verifier-sealed provider command once execution begins.
    #[must_use]
    pub fn sealed_command(&self) -> Option<&[u8]> {
        self.sealed_command.as_deref()
    }

    /// Whether the profile's post-command critical reread was durably
    /// committed before any credential lease or provider entry.
    #[must_use]
    pub const fn pre_entry_rechecked(&self) -> bool {
        self.pre_entry_rechecked
    }

    /// Whether the durable provider-entry marker was committed.
    #[must_use]
    pub const fn provider_entered(&self) -> bool {
        self.provider_entered
    }

    /// Whether post-entry receipt construction or inspection was quarantined.
    #[must_use]
    pub const fn receipt_integrity_failed(&self) -> bool {
        self.receipt_integrity_failed
    }

    /// Returns the profile-owned durable provider result, if recorded.
    #[must_use]
    pub fn provider_result(&self) -> Option<&[u8]> {
        self.provider_result.as_deref()
    }

    /// Returns ordered profile-owned provider/reconciliation observations.
    #[must_use]
    pub fn observations(&self) -> &[Vec<u8>] {
        &self.observations
    }

    /// Returns ordered portable receipts.
    #[must_use]
    pub fn receipts(&self) -> &[JournalReceiptV1] {
        &self.receipts
    }

    /// Returns the immutable outcome signed by the linked execution receipt.
    #[must_use]
    pub const fn execution_outcome(&self) -> Option<JournalExecutionOutcomeV1> {
        self.execution_outcome
    }

    /// Returns the exact result commitment signed by the execution receipt.
    #[must_use]
    pub const fn execution_result_commitment(&self) -> Option<&[u8; 32]> {
        self.execution_result_commitment.as_ref()
    }

    /// Returns the immutable exact facts present when the execution receipt was minted.
    #[must_use]
    pub const fn execution_receipt_basis(&self) -> Option<&JournalExecutionReceiptBasisV1> {
        self.execution_receipt_basis.as_ref()
    }

    /// Returns the terminal completion source.
    #[must_use]
    pub const fn completion(&self) -> Option<JournalCompletionV1> {
        self.completion
    }

    #[allow(clippy::too_many_lines)]
    fn apply(
        &self,
        mutation: OperationMutationV1,
        now_unix_seconds: u64,
    ) -> Result<Self, OperationJournalError> {
        if self.projection.is_terminal() || now_unix_seconds < self.updated_at_unix_seconds {
            return Err(OperationJournalError::InvalidTransition);
        }
        let mut next = self.clone();
        next.updated_at_unix_seconds = now_unix_seconds;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(OperationJournalError::Capacity)?;
        match mutation {
            OperationMutationV1::SealPreEntry {
                profile_state,
                sealed_command,
            } => {
                if self.projection.state() != OperationStateV1::Ready
                    || self.sealed_command.is_some()
                    || profile_state.is_empty()
                    || sealed_command.is_empty()
                {
                    return Err(OperationJournalError::InvalidTransition);
                }
                next.profile_state = profile_state;
                next.sealed_command = Some(sealed_command);
                next.pre_entry_rechecked = false;
            }
            OperationMutationV1::BeginExecution {
                profile_state,
                sealed_command,
            } => {
                if self.projection.state() != OperationStateV1::Ready
                    || self.sealed_command.as_deref() != Some(sealed_command.as_slice())
                    || self.profile_state != profile_state
                {
                    return Err(OperationJournalError::InvalidTransition);
                }
                next.projection = projection(
                    OperationStateV1::Executing,
                    OperationEffectV1::NotApplied,
                    false,
                )?;
                next.pre_entry_rechecked = false;
            }
            OperationMutationV1::RecordPreEntryRecheck { profile_state } => {
                if self.projection.state() != OperationStateV1::Executing
                    || self.projection.effect() != OperationEffectV1::NotApplied
                    || self.provider_entered
                    || self.pre_entry_rechecked
                    || self.sealed_command.is_none()
                    || profile_state.is_empty()
                {
                    return Err(OperationJournalError::InvalidTransition);
                }
                next.profile_state = profile_state;
                next.pre_entry_rechecked = true;
            }
            OperationMutationV1::MarkProviderEntered => {
                if self.projection.state() != OperationStateV1::Executing
                    || self.projection.effect() != OperationEffectV1::NotApplied
                    || !self.pre_entry_rechecked
                {
                    return Err(OperationJournalError::InvalidTransition);
                }
                next.projection = projection(
                    OperationStateV1::Executing,
                    OperationEffectV1::Possible,
                    false,
                )?;
                next.provider_entered = true;
            }
            OperationMutationV1::RecordProviderResult { bytes } => {
                if self.projection.state() != OperationStateV1::Executing
                    || self.provider_result.is_some()
                    || !self.observations.is_empty()
                    || bytes.is_empty()
                {
                    return Err(OperationJournalError::InvalidTransition);
                }
                next.provider_result = Some(bytes);
            }
            OperationMutationV1::RecordProviderUncertaintyState { profile_state } => {
                if self.projection.state() != OperationStateV1::Executing
                    || self.projection.effect() != OperationEffectV1::Possible
                    || !self.provider_entered
                    || self.provider_result.is_some()
                    || !self.observations.is_empty()
                    || self.execution_outcome.is_some()
                    || profile_state.is_empty()
                {
                    return Err(OperationJournalError::InvalidTransition);
                }
                next.profile_state = profile_state;
            }
            OperationMutationV1::RecordObservation { bytes } => {
                if !matches!(
                    self.projection.state(),
                    OperationStateV1::Executing | OperationStateV1::RecoveryRequired
                ) || self.receipt_integrity_failed
                    || self.observations.len() >= 32
                    || bytes.is_empty()
                    || (self.projection.state() == OperationStateV1::Executing
                        && self.provider_result.is_none())
                {
                    return Err(OperationJournalError::InvalidTransition);
                }
                next.observations.push(bytes);
            }
            OperationMutationV1::RecordExecutionReceipt {
                receipt,
                outcome,
                result_commitment,
            } => {
                if !matches!(
                    self.projection.state(),
                    OperationStateV1::Executing | OperationStateV1::RecoveryRequired
                ) || self.receipt_integrity_failed
                    || self.projection.effect() != OperationEffectV1::Possible
                    || self.receipts.len() != 1
                    || self.execution_outcome.is_some()
                    || (outcome == JournalExecutionOutcomeV1::Succeeded
                        && result_commitment.is_none())
                    || (outcome != JournalExecutionOutcomeV1::Succeeded
                        && self
                            .provider_result
                            .as_deref()
                            .map(Sha256::digest)
                            .map(Into::into)
                            != result_commitment)
                {
                    return Err(OperationJournalError::InvalidTransition);
                }
                next.receipts.push(receipt);
                next.execution_outcome = Some(outcome);
                next.execution_result_commitment = result_commitment;
                next.execution_receipt_basis = Some(JournalExecutionReceiptBasisV1 {
                    profile_state: self.profile_state.clone(),
                    provider_result: self.provider_result.clone(),
                    observations: self.observations.clone(),
                });
            }
            OperationMutationV1::RequireRecovery {
                issue,
                progress,
                profile_state,
            } => {
                if !matches!(
                    self.projection.state(),
                    OperationStateV1::Executing | OperationStateV1::RecoveryRequired
                ) || self.receipt_integrity_failed
                    || self.projection.effect() != OperationEffectV1::Possible
                    || issue.is_empty()
                    || self.execution_outcome != Some(JournalExecutionOutcomeV1::Indeterminate)
                    || self
                        .provider_result
                        .as_deref()
                        .map(Sha256::digest)
                        .map(Into::into)
                        != self.execution_result_commitment
                {
                    return Err(OperationJournalError::InvalidTransition);
                }
                next.projection = projection(
                    OperationStateV1::RecoveryRequired,
                    OperationEffectV1::Possible,
                    false,
                )?;
                next.issue = Some(issue);
                next.profile_progress = progress;
                next.profile_state = profile_state;
            }
            OperationMutationV1::QuarantineReceiptIntegrity {
                state,
                issue,
                value,
                progress,
                completion,
                profile_state,
            } => {
                if !matches!(
                    self.projection.state(),
                    OperationStateV1::Executing | OperationStateV1::RecoveryRequired
                ) || self.projection.effect() != OperationEffectV1::Possible
                    || !self.provider_entered
                    || self.receipt_integrity_failed
                    || self.receipts.len() != 1
                    || self.execution_outcome.is_some()
                {
                    return Err(OperationJournalError::InvalidTransition);
                }
                let (effect, terminal) = match state {
                    OperationStateV1::RecoveryRequired
                        if issue.is_some()
                            && value.is_none()
                            && completion.is_none()
                            && progress.as_ref().is_none_or(|bytes| !bytes.is_empty()) =>
                    {
                        (OperationEffectV1::Possible, false)
                    }
                    OperationStateV1::Completed
                        if issue.is_none()
                            && value.is_some()
                            && progress.is_none()
                            && completion.is_some()
                            && !self.observations.is_empty() =>
                    {
                        (OperationEffectV1::Applied, true)
                    }
                    OperationStateV1::Partial
                        if issue.is_some()
                            && value.is_some()
                            && progress.is_none()
                            && completion.is_some()
                            && !self.observations.is_empty() =>
                    {
                        (OperationEffectV1::Applied, true)
                    }
                    OperationStateV1::NotApplied
                        if issue.is_some()
                            && value.is_none()
                            && progress.is_none()
                            && completion.is_some()
                            && !self.observations.is_empty() =>
                    {
                        (OperationEffectV1::NotApplied, true)
                    }
                    _ => return Err(OperationJournalError::InvalidTransition),
                };
                next.projection = projection(state, effect, terminal)?;
                next.issue = issue;
                next.profile_value = value;
                next.profile_progress = progress;
                next.completion = completion;
                next.profile_state = profile_state;
                next.receipt_integrity_failed = true;
            }
            OperationMutationV1::Conclude {
                state,
                issue,
                value,
                completion,
                profile_state,
            } => {
                if !matches!(
                    state,
                    OperationStateV1::Completed
                        | OperationStateV1::Partial
                        | OperationStateV1::NotApplied
                ) || self.receipt_integrity_failed
                    || self.observations.is_empty()
                    || !matches!(
                        self.projection.state(),
                        OperationStateV1::Executing | OperationStateV1::RecoveryRequired
                    )
                {
                    return Err(OperationJournalError::InvalidTransition);
                }
                let effect = if state == OperationStateV1::NotApplied {
                    OperationEffectV1::NotApplied
                } else {
                    OperationEffectV1::Applied
                };
                match self.execution_outcome {
                    Some(JournalExecutionOutcomeV1::Succeeded)
                        if state != OperationStateV1::NotApplied =>
                    {
                        if value.as_deref().map(Sha256::digest).map(Into::into)
                            != self.execution_result_commitment
                        {
                            return Err(OperationJournalError::InvalidTransition);
                        }
                    }
                    Some(JournalExecutionOutcomeV1::Failed)
                        if state == OperationStateV1::NotApplied =>
                    {
                        if self
                            .provider_result
                            .as_deref()
                            .map(Sha256::digest)
                            .map(Into::into)
                            != self.execution_result_commitment
                        {
                            return Err(OperationJournalError::InvalidTransition);
                        }
                    }
                    // Reconciliation proves the terminal projection after an
                    // earlier response-loss receipt was durably signed as
                    // indeterminate.  The immutable receipt remains the
                    // evidence of that original boundary.
                    Some(JournalExecutionOutcomeV1::Indeterminate)
                        if completion == JournalCompletionV1::Reconciled => {}
                    _ => return Err(OperationJournalError::InvalidTransition),
                }
                next.projection = projection(state, effect, true)?;
                next.issue = issue;
                next.profile_value = value;
                next.profile_progress = None;
                next.completion = Some(completion);
                next.profile_state = profile_state;
            }
            OperationMutationV1::ConcludePreEntry {
                state,
                issue,
                profile_state,
            } => {
                if !(self.projection.state() == OperationStateV1::Ready
                    || (self.projection.state() == OperationStateV1::Executing
                        && self.projection.effect() == OperationEffectV1::NotApplied))
                    || !matches!(
                        state,
                        OperationStateV1::Unavailable | OperationStateV1::NotApplied
                    )
                    || issue.is_empty()
                {
                    return Err(OperationJournalError::InvalidTransition);
                }
                next.projection = projection(state, OperationEffectV1::NotApplied, true)?;
                next.issue = Some(issue);
                next.completion =
                    (state == OperationStateV1::NotApplied).then_some(JournalCompletionV1::Fresh);
                next.profile_state = profile_state;
            }
        }
        next.validate_common()?;
        Ok(next)
    }

    #[allow(clippy::too_many_lines)]
    fn validate_common(&self) -> Result<(), OperationJournalError> {
        self.binding
            .validate()
            .map_err(|_| OperationJournalError::InvalidRecord)?;
        if self.receipt_action_commitment == [0; 32] || self.receipt_context_commitment == [0; 32] {
            return Err(OperationJournalError::InvalidRecord);
        }
        self.projection
            .validate()
            .map_err(|_| OperationJournalError::InvalidRecord)?;
        if self.created_at_unix_seconds == 0
            || self.updated_at_unix_seconds < self.created_at_unix_seconds
            || self.revision == 0
            || self.recovery_handle.is_empty()
            || self.recovery_handle.len() > MAX_RECOVERY_HANDLE_BYTES
            || self
                .issue
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > MAX_ISSUE_BYTES)
            || self.profile_state.len() > MAX_PROFILE_STATE_BYTES
            || self.preparation_profile_state.is_empty()
            || self.preparation_profile_state.len() > MAX_PROFILE_STATE_BYTES
            || self
                .sealed_command
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > MAX_SEALED_COMMAND_BYTES)
            || self
                .provider_result
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > MAX_PROVIDER_RESULT_BYTES)
            || self.observations.len() > 32
            || self
                .observations
                .iter()
                .any(|value| value.is_empty() || value.len() > MAX_OBSERVATION_BYTES)
        {
            return Err(OperationJournalError::InvalidRecord);
        }
        let mut receipt_ids = BTreeSet::new();
        if self.receipts.iter().any(|receipt| {
            !bounded_ascii_graphic(&receipt.receipt_id, 128)
                || receipt.bytes.is_empty()
                || !receipt_ids.insert(receipt.receipt_id.as_str())
        }) {
            return Err(OperationJournalError::InvalidRecord);
        }
        if self.receipts.len() > 2
            || (self.execution_outcome.is_some()) != (self.receipts.len() == 2)
            || (self.execution_outcome.is_none() && self.execution_result_commitment.is_some())
            || (self.execution_outcome.is_some()) != self.execution_receipt_basis.is_some()
        {
            return Err(OperationJournalError::InvalidRecord);
        }
        if self.pre_entry_rechecked && self.sealed_command.is_none()
            || self.provider_entered && (!self.pre_entry_rechecked || self.sealed_command.is_none())
            || (self.provider_result.is_some() || self.execution_outcome.is_some())
                && !self.provider_entered
            || self.receipt_integrity_failed
                && (!self.provider_entered
                    || self.receipts.len() != 1
                    || self.execution_outcome.is_some()
                    || self.execution_receipt_basis.is_some())
        {
            return Err(OperationJournalError::InvalidRecord);
        }
        if self.execution_receipt_basis.as_ref().is_some_and(|basis| {
            basis.profile_state.is_empty()
                || basis.profile_state.len() > MAX_PROFILE_STATE_BYTES
                || basis.provider_result.as_ref().is_some_and(|value| {
                    value.is_empty() || value.len() > MAX_PROVIDER_RESULT_BYTES
                })
                || basis.observations.len() > 32
                || basis
                    .observations
                    .iter()
                    .any(|value| value.is_empty() || value.len() > MAX_OBSERVATION_BYTES)
        }) {
            return Err(OperationJournalError::InvalidRecord);
        }
        let shape_is_valid = match self.projection.state() {
            OperationStateV1::Preparing => false,
            OperationStateV1::Ready => {
                self.issue.is_none()
                    && self.profile_value.is_none()
                    && self.profile_progress.is_none()
                    && self.completion.is_none()
                    && self.projection.effect() == OperationEffectV1::NotApplied
                    && self.provider_result.is_none()
                    && self.observations.is_empty()
                    && self.receipts.len() == 1
                    && self.execution_outcome.is_none()
            }
            OperationStateV1::Executing => {
                self.issue.is_none()
                    && self.profile_value.is_none()
                    && self.profile_progress.is_none()
                    && self.completion.is_none()
                    && self.sealed_command.is_some()
                    && !self.receipts.is_empty()
                    && (self.projection.effect() != OperationEffectV1::NotApplied
                        || (self.provider_result.is_none()
                            && self.observations.is_empty()
                            && self.receipts.len() == 1
                            && self.execution_outcome.is_none()))
            }
            OperationStateV1::Denied => {
                self.issue.is_some()
                    && self.profile_value.is_none()
                    && self.profile_progress.is_none()
                    && self.completion.is_none()
                    && self.projection.effect() == OperationEffectV1::NotApplied
                    && self.sealed_command.is_none()
                    && self.provider_result.is_none()
                    && self.observations.is_empty()
                    && self.receipts.len() == 1
                    && self.execution_outcome.is_none()
            }
            OperationStateV1::Unavailable => {
                self.issue.is_some()
                    && self.profile_value.is_none()
                    && self.profile_progress.is_none()
                    && self.completion.is_none()
                    && self.projection.effect() == OperationEffectV1::NotApplied
                    && self.provider_result.is_none()
                    && self.observations.is_empty()
                    && self.receipts.len() == 1
                    && self.execution_outcome.is_none()
            }
            OperationStateV1::RecoveryRequired => {
                self.issue.is_some()
                    && self.profile_value.is_none()
                    && self.completion.is_none()
                    && self.projection.effect() == OperationEffectV1::Possible
                    && self.sealed_command.is_some()
                    && ((self.receipt_integrity_failed
                        && self.receipts.len() == 1
                        && self.execution_outcome.is_none())
                        || (!self.receipt_integrity_failed
                            && self.receipts.len() == 2
                            && self.execution_outcome
                                == Some(JournalExecutionOutcomeV1::Indeterminate)))
            }
            OperationStateV1::Completed => {
                self.issue.is_none()
                    && self.profile_value.is_some()
                    && self.profile_progress.is_none()
                    && self.completion.is_some()
                    && self.projection.effect() == OperationEffectV1::Applied
                    && self.sealed_command.is_some()
                    && !self.observations.is_empty()
                    && ((self.receipt_integrity_failed
                        && self.receipts.len() == 1
                        && self.execution_outcome.is_none())
                        || (!self.receipt_integrity_failed
                            && self.receipts.len() == 2
                            && (self.execution_outcome
                                == Some(JournalExecutionOutcomeV1::Succeeded)
                                && self.provider_result.is_some()
                                || self.execution_outcome
                                    == Some(JournalExecutionOutcomeV1::Indeterminate)
                                    && self.completion == Some(JournalCompletionV1::Reconciled))))
            }
            OperationStateV1::Partial => {
                self.issue.is_some()
                    && self.profile_value.is_some()
                    && self.profile_progress.is_none()
                    && self.completion.is_some()
                    && self.projection.effect() == OperationEffectV1::Applied
                    && self.sealed_command.is_some()
                    && !self.observations.is_empty()
                    && ((self.receipt_integrity_failed
                        && self.receipts.len() == 1
                        && self.execution_outcome.is_none())
                        || (!self.receipt_integrity_failed
                            && self.receipts.len() == 2
                            && (self.execution_outcome
                                == Some(JournalExecutionOutcomeV1::Succeeded)
                                && self.provider_result.is_some()
                                || self.execution_outcome
                                    == Some(JournalExecutionOutcomeV1::Indeterminate)
                                    && self.completion == Some(JournalCompletionV1::Reconciled))))
            }
            OperationStateV1::NotApplied => {
                self.issue.is_some()
                    && self.profile_value.is_none()
                    && self.profile_progress.is_none()
                    && self.completion.is_some()
                    && self.projection.effect() == OperationEffectV1::NotApplied
                    && ((self.receipt_integrity_failed
                        && self.receipts.len() == 1
                        && self.execution_outcome.is_none()
                        && !self.observations.is_empty())
                        || (!self.receipt_integrity_failed
                            && self.receipts.len() == 1
                            && self.provider_result.is_none()
                            && self.observations.is_empty()
                            && self.execution_outcome.is_none())
                        || (!self.receipt_integrity_failed
                            && self.receipts.len() == 2
                            && self.sealed_command.is_some()
                            && !self.observations.is_empty()
                            && (self.execution_outcome == Some(JournalExecutionOutcomeV1::Failed)
                                && self.provider_result.is_some()
                                || self.execution_outcome
                                    == Some(JournalExecutionOutcomeV1::Indeterminate)
                                    && self.completion == Some(JournalCompletionV1::Reconciled))))
            }
        };
        if !shape_is_valid {
            return Err(OperationJournalError::InvalidRecord);
        }
        Ok(())
    }

    fn validate_limits(
        &self,
        limits: OperationJournalLimitsV1,
    ) -> Result<(), OperationJournalError> {
        self.validate_common()?;
        let receipt_bytes = self
            .receipts
            .iter()
            .try_fold(0_u64, |total, value| {
                total.checked_add(value.bytes.len() as u64)
            })
            .ok_or(OperationJournalError::Capacity)?;
        if self.receipts.len() > usize::from(limits.maximum_receipts)
            || receipt_bytes > limits.maximum_receipt_bytes
            || self
                .profile_value
                .as_ref()
                .is_some_and(|value| value.len() as u64 > limits.maximum_result_bytes)
            || self
                .profile_progress
                .as_ref()
                .is_some_and(|value| value.len() as u64 > limits.maximum_result_bytes)
        {
            return Err(OperationJournalError::Capacity);
        }
        Ok(())
    }
}

/// One profile-owned mutation applied through common transition guards.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationMutationV1 {
    /// Persist the reserved profile state and exact provider command while the
    /// operation remains safely pre-entry and publicly `ready`.
    SealPreEntry {
        /// Updated opaque profile state containing the durable reservation.
        profile_state: Vec<u8>,
        /// Exact verifier-sealed provider command retained before execute.
        sealed_command: Vec<u8>,
    },
    /// Sealed command and critical pre-entry facts are about to execute.
    BeginExecution {
        /// Updated opaque profile state.
        profile_state: Vec<u8>,
        /// Exact verifier-sealed provider command retained before entry.
        sealed_command: Vec<u8>,
    },
    /// Persist the profile-owned critical reread after command durability and
    /// before any credential lease or provider entry.
    RecordPreEntryRecheck {
        /// Updated opaque profile state containing the exact reread proof.
        profile_state: Vec<u8>,
    },
    /// Provider entry has occurred or can no longer be ruled out.
    MarkProviderEntered,
    /// Persist the bounded provider response/result before observation.
    RecordProviderResult {
        /// Concrete provider-result bytes.
        bytes: Vec<u8>,
    },
    /// Persist an exact domain state transition after provider response loss
    /// and before the immutable indeterminate execution receipt is minted.
    RecordProviderUncertaintyState {
        /// Canonical profile state containing the durable uncertainty truth.
        profile_state: Vec<u8>,
    },
    /// Persist a concrete interpretation/reconciliation observation.
    RecordObservation {
        /// Concrete observation bytes.
        bytes: Vec<u8>,
    },
    /// Persist the linked execution receipt as its own durable boundary.
    RecordExecutionReceipt {
        /// Complete portable linked-execution container.
        receipt: JournalReceiptV1,
        /// Immutable signed outcome used by later terminal verification.
        outcome: JournalExecutionOutcomeV1,
        /// Exact digest signed as the execution result, if present.
        result_commitment: Option<[u8; 32]>,
    },
    /// Preserve possible effect and stop ordinary execution.
    RequireRecovery {
        /// Canonical registered error envelope.
        issue: Vec<u8>,
        /// Optional generated progress bytes.
        progress: Option<Vec<u8>>,
        /// Updated opaque profile state.
        profile_state: Vec<u8>,
    },
    /// Quarantine a receipt-integrity failure without changing proven provider truth.
    QuarantineReceiptIntegrity {
        /// Truthful terminal or recovery-required state.
        state: OperationStateV1,
        /// Original domain issue when the classified state requires one.
        issue: Option<Vec<u8>>,
        /// Original profile value when the classified state requires one.
        value: Option<Vec<u8>>,
        /// Original recovery progress when present.
        progress: Option<Vec<u8>>,
        /// Original terminal completion source when terminal.
        completion: Option<JournalCompletionV1>,
        /// Last durable opaque profile state.
        profile_state: Vec<u8>,
    },
    /// Conclude after a separately durable concrete observation.
    Conclude {
        /// `completed`, `partial`, or `not-applied` only.
        state: OperationStateV1,
        /// Required for partial/not-applied and absent for completed.
        issue: Option<Vec<u8>>,
        /// Required for completed/partial and absent for not-applied.
        value: Option<Vec<u8>>,
        /// Fresh or reconciled terminal source.
        completion: JournalCompletionV1,
        /// Updated opaque profile state.
        profile_state: Vec<u8>,
    },
    /// Conclude a ready or durably pre-entry operation before any provider
    /// attempt.
    ConcludePreEntry {
        /// `unavailable` or `not-applied` only.
        state: OperationStateV1,
        /// Canonical registered error envelope.
        issue: Vec<u8>,
        /// Updated opaque profile state.
        profile_state: Vec<u8>,
    },
}

/// Compact terminal replay tombstone retained after full-record collection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TombstoneV1 {
    operation_id: OperationIdV1,
    principal: String,
    profile: OperationProfileV1,
    request_id: auths_lifecycle::ClientRequestIdV1,
    idempotency_commitment: Option<[u8; 32]>,
    canonical_input_commitment: [u8; 32],
    preparation_evidence_intent_commitment: Option<[u8; 32]>,
    connection_alias: Option<String>,
    preparation_commitment: [u8; 32],
    idempotency_replay_commitment: [u8; 32],
    effect: OperationEffectV1,
    receipt_ids: Vec<String>,
    terminal_at_unix_seconds: u64,
}

impl TombstoneV1 {
    /// Returns the original operation ID.
    #[must_use]
    pub const fn operation_id(&self) -> &OperationIdV1 {
        &self.operation_id
    }

    /// Returns terminal effect truth.
    #[must_use]
    pub const fn effect(&self) -> OperationEffectV1 {
        self.effect
    }

    /// Returns retained ordered receipt IDs without receipt bytes.
    #[must_use]
    pub fn receipt_ids(&self) -> &[String] {
        &self.receipt_ids
    }

    /// Returns the original request identity.
    #[must_use]
    pub const fn request_id(&self) -> auths_lifecycle::ClientRequestIdV1 {
        self.request_id
    }

    /// Returns the caller idempotency commitment when one was supplied.
    #[must_use]
    pub const fn idempotency_commitment(&self) -> Option<&[u8; 32]> {
        self.idempotency_commitment.as_ref()
    }

    /// Returns the exact retained profile identity.
    #[must_use]
    pub const fn profile(&self) -> &OperationProfileV1 {
        &self.profile
    }

    /// Returns the canonical profile-input commitment retained for exact replay.
    #[must_use]
    pub const fn canonical_input_commitment(&self) -> &[u8; 32] {
        &self.canonical_input_commitment
    }

    /// Returns the provider-I/O-independent companion intent commitment.
    #[must_use]
    pub const fn preparation_evidence_intent_commitment(&self) -> Option<&[u8; 32]> {
        self.preparation_evidence_intent_commitment.as_ref()
    }

    /// Returns the resolved original connection alias, if this operation used one.
    #[must_use]
    pub fn connection_alias(&self) -> Option<&str> {
        self.connection_alias.as_deref()
    }
}

/// Lookup result that never crosses a principal boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum JournalStatusV1 {
    /// Full retained operation record.
    Record(JournalRecordV1),
    /// Compact terminal replay tombstone.
    Tombstone(TombstoneV1),
}

/// Atomic preparation insertion/replay result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrepareJournalResult {
    /// The new operation was durably inserted.
    Created(JournalRecordV1),
    /// An exact retained operation was replayed.
    Replayed(JournalRecordV1),
    /// An exact compact terminal tombstone was replayed.
    ReplayedTombstone(TombstoneV1),
    /// The request or idempotency key was already bound differently.
    Conflict {
        /// Original durable operation ID, never a newly allocated ID.
        original_operation_id: OperationIdV1,
    },
}

/// Evidence-independent lookup used before a companion performs provider I/O.
#[derive(Clone, Debug, Eq, PartialEq)]
// This lookup is consumed immediately and infrequently. Keeping the owned
// status inline avoids an otherwise unconditional heap allocation on every
// identity hit.
#[allow(clippy::large_enum_variant)]
pub enum PreparationIdentityLookup {
    /// Neither durable request identity nor caller idempotency identity exists.
    Absent,
    /// One exact durable record or tombstone owns the identity.
    Existing(JournalStatusV1),
    /// The request and idempotency indexes name different original operations.
    Conflict {
        /// Deterministic original operation selected from the request index first.
        original_operation_id: OperationIdV1,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct RequestIndexKey {
    principal: String,
    request_id: auths_lifecycle::ClientRequestIdV1,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct IdempotencyIndexKey {
    principal: String,
    profile_id: String,
    profile_version: u16,
    commitment: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct ProfilePrincipalKey {
    principal: String,
    profile_id: String,
    profile_version: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct AdmissionKey {
    scope: ProfilePrincipalKey,
    minute: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct OperationDatabaseV1 {
    version: u8,
    records: BTreeMap<OperationIdV1, JournalRecordV1>,
    tombstones: BTreeMap<OperationIdV1, TombstoneV1>,
    request_index: BTreeMap<RequestIndexKey, OperationIdV1>,
    idempotency_index: BTreeMap<IdempotencyIndexKey, OperationIdV1>,
    admissions: BTreeMap<AdmissionKey, u32>,
    #[cfg(feature = "qualification-evidence")]
    qualification_boundaries: Vec<QualificationJournalBoundaryV1>,
}

impl Default for OperationDatabaseV1 {
    fn default() -> Self {
        Self {
            version: DATABASE_VERSION,
            records: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            request_index: BTreeMap::new(),
            idempotency_index: BTreeMap::new(),
            admissions: BTreeMap::new(),
            #[cfg(feature = "qualification-evidence")]
            qualification_boundaries: Vec::new(),
        }
    }
}

/// Single-process crash-persistent operation journal.
pub struct PersistentOperationJournal {
    path: PathBuf,
    _process_lock: File,
    limits: BTreeMap<OperationProfileV1, OperationJournalLimitsV1>,
    database: Mutex<OperationDatabaseV1>,
    poisoned: AtomicBool,
}

impl PersistentOperationJournal {
    /// Returns the exact durable qualification-boundary count. The caller
    /// uses this only to decide whether a store transaction must cross the
    /// protected boundary-flush gate; boundary contents remain store-owned.
    #[cfg(feature = "qualification-evidence")]
    pub fn qualification_boundary_count(&self) -> Result<usize, OperationJournalError> {
        let database = self
            .database
            .lock()
            .map_err(|_| OperationJournalError::Unavailable)?;
        self.require_available()?;
        Ok(database.qualification_boundaries.len())
    }

    /// Opens or creates one canonical bounded operation journal.
    pub fn open(
        path: impl Into<PathBuf>,
        limits: impl IntoIterator<Item = (OperationProfileV1, OperationJournalLimitsV1)>,
    ) -> Result<Self, OperationJournalConfigurationError> {
        let path = path.into();
        if path.as_os_str().is_empty() || path.parent().is_none() {
            return Err(OperationJournalConfigurationError::InvalidPath);
        }
        let limits = limits.into_iter().collect::<BTreeMap<_, _>>();
        if limits.is_empty() || limits.len() > 256 {
            return Err(OperationJournalConfigurationError::InvalidLimits);
        }
        let lock_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(OperationJournalConfigurationError::InvalidPath)?;
        let lock_path = path.with_file_name(format!(".{lock_name}.lock"));
        let lock = File::from(
            open(
                &lock_path,
                OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| OperationJournalConfigurationError::Io)?,
        );
        let lock_metadata = lock
            .metadata()
            .map_err(|_| OperationJournalConfigurationError::Io)?;
        if !lock_metadata.is_file()
            || lock_metadata.nlink() != 1
            || lock_metadata.uid() != rustix::process::geteuid().as_raw()
            || lock_metadata.mode() & 0o777 != 0o600
            || lock_metadata.len() != 0
        {
            return Err(OperationJournalConfigurationError::InvalidState);
        }
        flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| OperationJournalConfigurationError::InvalidState)?;
        let database = if path.exists() {
            let metadata =
                fs::symlink_metadata(&path).map_err(|_| OperationJournalConfigurationError::Io)?;
            if !metadata.file_type().is_file()
                || usize::try_from(metadata.len())
                    .map_or(true, |length| length > MAX_DATABASE_BYTES)
            {
                return Err(OperationJournalConfigurationError::InvalidState);
            }
            let bytes = fs::read(&path).map_err(|_| OperationJournalConfigurationError::Io)?;
            decode_database(&bytes, &limits)?
        } else {
            OperationDatabaseV1::default()
        };
        Ok(Self {
            path,
            _process_lock: lock,
            limits,
            database: Mutex::new(database),
            poisoned: AtomicBool::new(false),
        })
    }

    /// Atomically inserts a new prepared operation or returns exact replay/conflict.
    pub fn prepare(
        &self,
        record: JournalRecordV1,
        now_unix_seconds: u64,
    ) -> Result<PrepareJournalResult, OperationJournalError> {
        let limits = self.profile_limits(record.binding.profile())?;
        record.validate_limits(limits)?;
        if record.created_at_unix_seconds != now_unix_seconds {
            return Err(OperationJournalError::InvalidRecord);
        }
        self.mutate(|database| {
            collect_expired(database, &self.limits, now_unix_seconds)?;
            if let Some(result) = replay_for(database, &record)? {
                #[cfg(feature = "qualification-evidence")]
                if matches!(result, PrepareJournalResult::ReplayedTombstone(_)) {
                    return Err(OperationJournalError::InvalidState);
                }
                return Ok(result);
            }
            if database.records.contains_key(record.operation_id())
                || database.tombstones.contains_key(record.operation_id())
            {
                return Err(OperationJournalError::Conflict);
            }
            let scope = binding_scope(record.binding());
            let active = database
                .records
                .values()
                .filter(|value| {
                    binding_scope(value.binding()) == scope && !value.projection.is_terminal()
                })
                .count();
            let unresolved = database
                .records
                .values()
                .filter(|value| {
                    binding_scope(value.binding()) == scope
                        && !value.projection.is_terminal()
                        && value.projection.effect() == OperationEffectV1::Possible
                })
                .count();
            let principal_pending = database
                .records
                .values()
                .filter(|value| {
                    value.binding.principal() == record.binding.principal()
                        && !value.projection.is_terminal()
                })
                .count();
            if active >= usize::from(limits.active_per_principal)
                || unresolved >= usize::from(limits.unresolved_per_principal)
                || principal_pending >= MAX_PRINCIPAL_PENDING
            {
                return Err(OperationJournalError::Capacity);
            }
            let minute = now_unix_seconds / 60;
            let admission_key = AdmissionKey {
                scope: scope.clone(),
                minute,
            };
            let admissions = database
                .admissions
                .get(&admission_key)
                .copied()
                .unwrap_or(0);
            if admissions >= limits.admissions_per_minute {
                return Err(OperationJournalError::Capacity);
            }
            database
                .records
                .insert(record.operation_id.clone(), record.clone());
            database
                .request_index
                .insert(request_key(record.binding()), record.operation_id.clone());
            if let Some(key) = idempotency_key(record.binding()) {
                database
                    .idempotency_index
                    .insert(key, record.operation_id.clone());
            }
            database.admissions.insert(admission_key, admissions + 1);
            #[cfg(feature = "qualification-evidence")]
            {
                push_qualification_boundary(
                    database,
                    &record,
                    QualificationJournalBoundaryKindV1::Decision,
                    None,
                    Some(0),
                    None,
                )?;
                if record.projection().is_terminal() {
                    push_qualification_boundary(
                        database,
                        &record,
                        QualificationJournalBoundaryKindV1::Terminal,
                        None,
                        None,
                        None,
                    )?;
                }
            }
            enforce_scope_capacity(database, &scope, limits)?;
            Ok(PrepareJournalResult::Created(record))
        })
    }

    /// Applies one common-guarded profile mutation at an exact revision.
    pub fn mutate_operation(
        &self,
        principal: &str,
        operation_id: &OperationIdV1,
        expected_revision: u64,
        mutation: OperationMutationV1,
        now_unix_seconds: u64,
    ) -> Result<JournalRecordV1, OperationJournalError> {
        self.mutate(|database| {
            let current = database
                .records
                .get(operation_id)
                .filter(|value| value.binding.principal() == principal)
                .cloned()
                .ok_or(OperationJournalError::NotFound)?;
            if current.revision != expected_revision {
                return Err(OperationJournalError::Conflict);
            }
            let limits = self.profile_limits(current.binding.profile())?;
            #[cfg(feature = "qualification-evidence")]
            let boundary_kind = qualification_boundary_for_mutation(&mutation);
            let next = current.apply(mutation, now_unix_seconds)?;
            next.validate_limits(limits)?;
            database.records.insert(operation_id.clone(), next.clone());
            #[cfg(feature = "qualification-evidence")]
            if let Some(kind) = boundary_kind {
                push_qualification_boundary(database, &next, kind, None, None, None)?;
            }
            enforce_scope_capacity(database, &binding_scope(next.binding()), limits)?;
            Ok(next)
        })
    }

    /// Loads one full record or retained tombstone for the exact principal.
    pub fn status(
        &self,
        principal: &str,
        operation_id: &OperationIdV1,
    ) -> Result<Option<JournalStatusV1>, OperationJournalError> {
        let database = self
            .database
            .lock()
            .map_err(|_| OperationJournalError::Unavailable)?;
        self.require_available()?;
        if let Some(record) = database
            .records
            .get(operation_id)
            .filter(|value| value.binding.principal() == principal)
        {
            return Ok(Some(JournalStatusV1::Record(record.clone())));
        }
        Ok(database
            .tombstones
            .get(operation_id)
            .filter(|value| value.principal == principal)
            .cloned()
            .map(JournalStatusV1::Tombstone))
    }

    /// Looks up durable request/idempotency ownership before a protected
    /// preparation-evidence companion is allowed to perform provider I/O.
    ///
    /// Expiration is collected atomically before either durable identity is
    /// consulted. Before the declared idempotency boundary a caller must
    /// compare the retained intent before projecting a replay; at and after
    /// the boundary a fresh admission may proceed.
    pub fn preparation_identity(
        &self,
        principal: &str,
        profile: &OperationProfileV1,
        request_id: auths_lifecycle::ClientRequestIdV1,
        idempotency_commitment: Option<[u8; 32]>,
        now_unix_seconds: u64,
    ) -> Result<PreparationIdentityLookup, OperationJournalError> {
        if principal.is_empty() || principal.len() > 512 {
            return Err(OperationJournalError::InvalidRecord);
        }
        self.mutate(|database| {
            collect_expired(database, &self.limits, now_unix_seconds)?;
            let request_match = database.request_index.get(&RequestIndexKey {
                principal: principal.to_owned(),
                request_id,
            });
            let idempotency_match = idempotency_commitment.as_ref().and_then(|commitment| {
                database.idempotency_index.get(&IdempotencyIndexKey {
                    principal: principal.to_owned(),
                    profile_id: profile.id().to_owned(),
                    profile_version: profile.version(),
                    commitment: *commitment,
                })
            });
            if request_match.is_some()
                && idempotency_match.is_some()
                && request_match != idempotency_match
            {
                return Ok(PreparationIdentityLookup::Conflict {
                    original_operation_id: request_match
                        .cloned()
                        .ok_or(OperationJournalError::InvalidState)?,
                });
            }
            let Some(operation_id) = request_match.or(idempotency_match) else {
                return Ok(PreparationIdentityLookup::Absent);
            };
            if let Some(record) = database.records.get(operation_id) {
                return Ok(PreparationIdentityLookup::Existing(
                    JournalStatusV1::Record(record.clone()),
                ));
            }
            let tombstone = database
                .tombstones
                .get(operation_id)
                .cloned()
                .ok_or(OperationJournalError::InvalidState)?;
            Ok(PreparationIdentityLookup::Existing(
                JournalStatusV1::Tombstone(tombstone),
            ))
        })
    }

    /// Returns the complete bounded pending set in `(updated-at, operation-id)` order.
    pub fn pending(&self, principal: &str) -> Result<Vec<JournalRecordV1>, OperationJournalError> {
        let database = self
            .database
            .lock()
            .map_err(|_| OperationJournalError::Unavailable)?;
        self.require_available()?;
        let mut records = database
            .records
            .values()
            .filter(|value| {
                value.binding.principal() == principal && !value.projection.is_terminal()
            })
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            (left.updated_at_unix_seconds, left.operation_id.as_str())
                .cmp(&(right.updated_at_unix_seconds, right.operation_id.as_str()))
        });
        if records.len() > MAX_PRINCIPAL_PENDING {
            return Err(OperationJournalError::InvalidState);
        }
        Ok(records)
    }

    /// Atomically records one preparation replay after revalidating the exact
    /// request or idempotency binding against store-owned indexes.
    #[cfg(feature = "qualification-evidence")]
    pub fn record_preparation_replay_for_qualification(
        &self,
        operation_id: &OperationIdV1,
        candidate: &PreparationBindingV1,
    ) -> Result<JournalRecordV1, OperationJournalError> {
        candidate
            .validate()
            .map_err(|_| OperationJournalError::InvalidRecord)?;
        self.mutate(|database| {
            let record = database
                .records
                .get(operation_id)
                .filter(|record| record.binding().principal() == candidate.principal())
                .cloned()
                .ok_or(OperationJournalError::NotFound)?;
            let request_owner = database.request_index.get(&request_key(candidate));
            let idempotency_owner = idempotency_key(candidate)
                .as_ref()
                .and_then(|key| database.idempotency_index.get(key));
            if request_owner.is_some()
                && idempotency_owner.is_some()
                && request_owner != idempotency_owner
                || request_owner.or(idempotency_owner) != Some(operation_id)
                || request_owner.is_some()
                    && record.binding().preparation_commitment()
                        != candidate.preparation_commitment()
                || request_owner.is_none()
                    && record.binding().idempotency_replay_commitment()
                        != candidate.idempotency_replay_commitment()
            {
                return Err(OperationJournalError::Conflict);
            }
            let completion = record
                .completion()
                .is_some()
                .then_some(JournalCompletionV1::Replayed);
            push_qualification_boundary(
                database,
                &record,
                QualificationJournalBoundaryKindV1::Replay,
                Some(candidate.request_id()),
                None,
                completion,
            )?;
            Ok(record)
        })
    }

    /// Atomically records one status projection from the exact durable record.
    #[cfg(feature = "qualification-evidence")]
    pub fn record_status_for_qualification(
        &self,
        principal: &str,
        operation_id: &OperationIdV1,
        request_id: ClientRequestIdV1,
    ) -> Result<JournalRecordV1, OperationJournalError> {
        self.record_projection_for_qualification(
            principal,
            operation_id,
            request_id,
            QualificationJournalBoundaryKindV1::Status,
            None,
        )
    }

    /// Atomically records one recovery projection from the exact durable record.
    #[cfg(feature = "qualification-evidence")]
    pub fn record_recovery_for_qualification(
        &self,
        principal: &str,
        operation_id: &OperationIdV1,
        request_id: ClientRequestIdV1,
        completion: Option<JournalCompletionV1>,
    ) -> Result<JournalRecordV1, OperationJournalError> {
        self.record_projection_for_qualification(
            principal,
            operation_id,
            request_id,
            QualificationJournalBoundaryKindV1::Recovery,
            completion,
        )
    }

    #[cfg(feature = "qualification-evidence")]
    fn record_projection_for_qualification(
        &self,
        principal: &str,
        operation_id: &OperationIdV1,
        request_id: ClientRequestIdV1,
        kind: QualificationJournalBoundaryKindV1,
        completion: Option<JournalCompletionV1>,
    ) -> Result<JournalRecordV1, OperationJournalError> {
        if !matches!(
            kind,
            QualificationJournalBoundaryKindV1::Status
                | QualificationJournalBoundaryKindV1::Recovery
        ) {
            return Err(OperationJournalError::InvalidRecord);
        }
        self.mutate(|database| {
            let record = database
                .records
                .get(operation_id)
                .filter(|record| record.binding().principal() == principal)
                .cloned()
                .ok_or(OperationJournalError::NotFound)?;
            if kind == QualificationJournalBoundaryKindV1::Status
                && request_id != record.binding().request_id()
            {
                return Err(OperationJournalError::InvalidRecord);
            }
            let projected_completion = completion.or(record.completion());
            if projected_completion == Some(JournalCompletionV1::Replayed)
                && !record.projection().is_terminal()
                || !matches!(projected_completion, Some(JournalCompletionV1::Replayed))
                    && completion.is_some()
                    && completion != record.completion()
            {
                return Err(OperationJournalError::InvalidRecord);
            }
            push_qualification_boundary(
                database,
                &record,
                kind,
                Some(request_id),
                None,
                projected_completion,
            )?;
            Ok(record)
        })
    }

    /// Runs profile-aware retention without ever deleting unresolved possible effects.
    pub fn collect(&self, now_unix_seconds: u64) -> Result<(), OperationJournalError> {
        self.mutate(|database| collect_expired(database, &self.limits, now_unix_seconds))
    }

    fn profile_limits(
        &self,
        profile: &OperationProfileV1,
    ) -> Result<OperationJournalLimitsV1, OperationJournalError> {
        self.limits
            .get(profile)
            .copied()
            .ok_or(OperationJournalError::InvalidRecord)
    }

    fn mutate<T>(
        &self,
        mutation: impl FnOnce(&mut OperationDatabaseV1) -> Result<T, OperationJournalError>,
    ) -> Result<T, OperationJournalError> {
        let mut database = self
            .database
            .lock()
            .map_err(|_| OperationJournalError::Unavailable)?;
        self.require_available()?;
        let mut next = database.clone();
        let result = mutation(&mut next)?;
        validate_database(&next, &self.limits).map_err(|_| OperationJournalError::InvalidState)?;
        let persistence = persist_database(&self.path, &next)?;
        *database = next;
        if persistence == DatabasePersistence::PublishedWithoutDirectorySync {
            self.poisoned.store(true, Ordering::Release);
            return Err(OperationJournalError::Unavailable);
        }
        Ok(result)
    }

    fn require_available(&self) -> Result<(), OperationJournalError> {
        if self.poisoned.load(Ordering::Acquire) {
            Err(OperationJournalError::Unavailable)
        } else {
            Ok(())
        }
    }
}

#[cfg(feature = "qualification-evidence")]
fn qualification_boundary_for_mutation(
    mutation: &OperationMutationV1,
) -> Option<QualificationJournalBoundaryKindV1> {
    match mutation {
        OperationMutationV1::SealPreEntry { .. } => {
            Some(QualificationJournalBoundaryKindV1::Command)
        }
        OperationMutationV1::MarkProviderEntered => {
            Some(QualificationJournalBoundaryKindV1::ProviderEntry)
        }
        OperationMutationV1::RecordProviderResult { .. } => {
            Some(QualificationJournalBoundaryKindV1::ProviderResult)
        }
        OperationMutationV1::RecordObservation { .. } => {
            Some(QualificationJournalBoundaryKindV1::Observation)
        }
        OperationMutationV1::RecordExecutionReceipt { .. } => {
            Some(QualificationJournalBoundaryKindV1::ExecutionReceipt)
        }
        OperationMutationV1::Conclude { .. } | OperationMutationV1::ConcludePreEntry { .. } => {
            Some(QualificationJournalBoundaryKindV1::Terminal)
        }
        OperationMutationV1::QuarantineReceiptIntegrity { state, .. }
            if *state != OperationStateV1::RecoveryRequired =>
        {
            Some(QualificationJournalBoundaryKindV1::Terminal)
        }
        OperationMutationV1::RequireRecovery { .. }
        | OperationMutationV1::QuarantineReceiptIntegrity {
            state: OperationStateV1::RecoveryRequired,
            ..
        } => Some(QualificationJournalBoundaryKindV1::RecoveryRequired),
        OperationMutationV1::BeginExecution { .. }
        | OperationMutationV1::RecordPreEntryRecheck { .. }
        | OperationMutationV1::RecordProviderUncertaintyState { .. }
        | OperationMutationV1::QuarantineReceiptIntegrity { .. } => None,
    }
}

#[cfg(feature = "qualification-evidence")]
#[allow(clippy::too_many_lines)]
fn push_qualification_boundary(
    database: &mut OperationDatabaseV1,
    record: &JournalRecordV1,
    kind: QualificationJournalBoundaryKindV1,
    request_id: Option<ClientRequestIdV1>,
    subject_index: Option<u8>,
    completion_override: Option<JournalCompletionV1>,
) -> Result<(), OperationJournalError> {
    let request_kind = matches!(
        kind,
        QualificationJournalBoundaryKindV1::Replay
            | QualificationJournalBoundaryKindV1::Status
            | QualificationJournalBoundaryKindV1::Recovery
    );
    if request_kind != request_id.is_some() {
        return Err(OperationJournalError::InvalidRecord);
    }
    if database.qualification_boundaries.len() >= MAX_QUALIFICATION_BOUNDARIES {
        return Err(OperationJournalError::Capacity);
    }
    let ordinal = u32::try_from(database.qualification_boundaries.len() + 1)
        .map_err(|_| OperationJournalError::Capacity)?;
    let derived_index = match kind {
        QualificationJournalBoundaryKindV1::Decision => Some(0),
        QualificationJournalBoundaryKindV1::Observation => Some(
            u8::try_from(
                record
                    .observations()
                    .len()
                    .checked_sub(1)
                    .ok_or(OperationJournalError::InvalidState)?,
            )
            .map_err(|_| OperationJournalError::Capacity)?,
        ),
        QualificationJournalBoundaryKindV1::ExecutionReceipt => Some(
            u8::try_from(
                record
                    .receipts()
                    .len()
                    .checked_sub(1)
                    .ok_or(OperationJournalError::InvalidState)?,
            )
            .map_err(|_| OperationJournalError::Capacity)?,
        ),
        _ => None,
    };
    if subject_index.is_some() && subject_index != derived_index {
        return Err(OperationJournalError::InvalidRecord);
    }
    let subject_index = derived_index;
    let completion = completion_override.or(record.completion());
    let projection_sha256 =
        qualification_projection_commitment(ordinal, kind, record, request_id, completion)?;
    let subject_sha256 = match kind {
        QualificationJournalBoundaryKindV1::Decision => record
            .receipts()
            .first()
            .map(|receipt| Sha256::digest(receipt.bytes()).into())
            .ok_or(OperationJournalError::InvalidState)?,
        QualificationJournalBoundaryKindV1::Command
        | QualificationJournalBoundaryKindV1::ProviderEntry => record
            .sealed_command()
            .map(|bytes| Sha256::digest(bytes).into())
            .ok_or(OperationJournalError::InvalidState)?,
        QualificationJournalBoundaryKindV1::ProviderResult => record
            .provider_result()
            .map(|bytes| Sha256::digest(bytes).into())
            .ok_or(OperationJournalError::InvalidState)?,
        QualificationJournalBoundaryKindV1::Observation => record
            .observations()
            .get(usize::from(
                subject_index.ok_or(OperationJournalError::InvalidState)?,
            ))
            .map(|bytes| Sha256::digest(bytes).into())
            .ok_or(OperationJournalError::InvalidState)?,
        QualificationJournalBoundaryKindV1::ExecutionReceipt => record
            .receipts()
            .get(usize::from(
                subject_index.ok_or(OperationJournalError::InvalidState)?,
            ))
            .map(|receipt| Sha256::digest(receipt.bytes()).into())
            .ok_or(OperationJournalError::InvalidState)?,
        QualificationJournalBoundaryKindV1::RecoveryRequired
        | QualificationJournalBoundaryKindV1::Terminal
        | QualificationJournalBoundaryKindV1::Replay
        | QualificationJournalBoundaryKindV1::Status
        | QualificationJournalBoundaryKindV1::Recovery => projection_sha256,
    };
    let projection = record.projection();
    database
        .qualification_boundaries
        .push(QualificationJournalBoundaryV1 {
            ordinal,
            operation_id: record.operation_id().clone(),
            profile: record.binding().profile().clone(),
            connection_generation: record
                .binding()
                .connection()
                .map(auths_lifecycle::ConnectionBindingCommitmentsV1::generation),
            journal_revision: record.revision(),
            request_id,
            kind,
            state: projection.state(),
            effect: projection.effect(),
            terminal: projection.is_terminal(),
            completion,
            subject_index,
            subject_sha256,
            projection_sha256,
        });
    Ok(())
}

#[cfg(feature = "qualification-evidence")]
fn qualification_projection_commitment(
    ordinal: u32,
    kind: QualificationJournalBoundaryKindV1,
    record: &JournalRecordV1,
    request_id: Option<ClientRequestIdV1>,
    completion: Option<JournalCompletionV1>,
) -> Result<[u8; 32], OperationJournalError> {
    let projection = record.projection();
    let public = (
        ordinal,
        kind,
        record.operation_id(),
        record.binding().profile(),
        record
            .binding()
            .connection()
            .map(auths_lifecycle::ConnectionBindingCommitmentsV1::generation),
        record.revision(),
        request_id,
        projection.state(),
        projection.effect(),
        projection.is_terminal(),
        completion,
    );
    let encoded =
        postcard::to_allocvec(&public).map_err(|_| OperationJournalError::InvalidState)?;
    let mut digest = Sha256::new();
    digest.update(b"auths.qualification-journal-projection/1\0");
    digest.update(encoded);
    Ok(digest.finalize().into())
}

/// Reads one exact record from the atomically persisted journal without
/// joining the writer process or acquiring its process-lifetime lock.
///
/// This is deliberately narrower than opening a second journal. It is used by
/// the independently built qualification journal reader after a durable
/// acknowledgement. The persisted database is decoded and fully revalidated;
/// the returned record is selected by both authenticated principal and
/// operation ID. Atomic replacement makes the opened descriptor one coherent
/// old-or-new snapshot while the inode checks reject in-place mutation.
#[cfg(all(unix, any(feature = "qualification-evidence", test)))]
pub fn read_persisted_operation_record_for_qualification(
    path: &Path,
    principal: &str,
    operation_id: &OperationIdV1,
) -> Result<JournalRecordV1, OperationJournalConfigurationError> {
    let mut file = open_persisted_operation_snapshot_for_qualification(
        path,
        rustix::process::geteuid().as_raw(),
    )?;
    read_persisted_operation_record_from_qualification_snapshot(
        &mut file,
        rustix::process::geteuid().as_raw(),
        principal,
        operation_id,
    )
}

/// Opens and pins one coherent agent-owned journal snapshot for a protected
/// qualification reader. This does not relax the production journal's 0600
/// ownership contract; a privileged launcher must supply the exact expected
/// agent UID and transfer the resulting read-only descriptor explicitly.
#[cfg(all(unix, any(feature = "qualification-evidence", test)))]
pub fn open_persisted_operation_snapshot_for_qualification(
    path: &Path,
    expected_owner_uid: u32,
) -> Result<File, OperationJournalConfigurationError> {
    if path.as_os_str().is_empty() || path.parent().is_none() {
        return Err(OperationJournalConfigurationError::InvalidPath);
    }
    let file = File::from(
        open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| OperationJournalConfigurationError::Io)?,
    );
    validate_qualification_snapshot_file(&file, expected_owner_uid)?;
    Ok(file)
}

/// Opens the fixed journal member relative to one already pinned state
/// directory. This prevents a mutable or symlinked pathname ancestor from
/// selecting a different journal after the durable acknowledgement.
#[cfg(all(unix, any(feature = "qualification-evidence", test)))]
pub fn open_persisted_operation_snapshot_at_for_qualification(
    state_directory: &File,
    expected_owner_uid: u32,
) -> Result<File, OperationJournalConfigurationError> {
    let access = rustix::fs::fcntl_getfl(state_directory)
        .map_err(|_| OperationJournalConfigurationError::Io)?;
    let directory = state_directory
        .metadata()
        .map_err(|_| OperationJournalConfigurationError::Io)?;
    if access & OFlags::ACCMODE != OFlags::RDONLY
        || !directory.file_type().is_dir()
        || directory.uid() != expected_owner_uid
        || directory.mode() & 0o777 != 0o700
    {
        return Err(OperationJournalConfigurationError::InvalidState);
    }
    let file = File::from(
        openat(
            state_directory,
            "operations.cbor",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| OperationJournalConfigurationError::Io)?,
    );
    validate_qualification_snapshot_file(&file, expected_owner_uid)?;
    Ok(file)
}

#[cfg(all(unix, any(feature = "qualification-evidence", test)))]
fn validate_qualification_snapshot_file(
    file: &File,
    expected_owner_uid: u32,
) -> Result<(), OperationJournalConfigurationError> {
    let metadata = file
        .metadata()
        .map_err(|_| OperationJournalConfigurationError::Io)?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != expected_owner_uid
        || metadata.mode() & 0o777 != 0o600
        || usize::try_from(metadata.len())
            .map_or(true, |length| length > MAX_QUALIFICATION_SNAPSHOT_BYTES)
    {
        return Err(OperationJournalConfigurationError::InvalidState);
    }
    Ok(())
}

/// Decodes one record from a pre-opened coherent journal snapshot. The same
/// descriptor can be checked by the protected controller and then transferred
/// with `SCM_RIGHTS` to a distinct `JournalReader` identity.
#[cfg(all(unix, any(feature = "qualification-evidence", test)))]
pub fn read_persisted_operation_record_from_qualification_snapshot(
    file: &mut File,
    expected_owner_uid: u32,
    principal: &str,
    operation_id: &OperationIdV1,
) -> Result<JournalRecordV1, OperationJournalConfigurationError> {
    if principal.is_empty() {
        return Err(OperationJournalConfigurationError::InvalidPath);
    }
    let database = read_qualification_snapshot_database(file, expected_owner_uid)?;
    database
        .records
        .get(operation_id)
        .filter(|record| record.binding().principal() == principal)
        .cloned()
        .ok_or(OperationJournalConfigurationError::InvalidState)
}

/// Decodes every operation in one pinned qualification snapshot in canonical
/// operation-ID order. The protected reader still independently filters the
/// exact plan phase and rejects any unexpected profile or roster size.
#[cfg(all(unix, any(feature = "qualification-evidence", test)))]
pub fn read_persisted_operation_records_from_qualification_snapshot(
    file: &mut File,
    expected_owner_uid: u32,
) -> Result<Vec<JournalRecordV1>, OperationJournalConfigurationError> {
    Ok(
        read_qualification_snapshot_database(file, expected_owner_uid)?
            .records
            .into_values()
            .collect(),
    )
}

/// Decodes the exact atomically co-persisted qualification boundary roster.
/// Entries contain only public state and fixed commitments; raw capabilities
/// and profile/provider payloads remain in the private journal record.
#[cfg(all(unix, feature = "qualification-evidence"))]
pub fn read_persisted_qualification_boundaries_from_snapshot(
    file: &mut File,
    expected_owner_uid: u32,
) -> Result<Vec<QualificationJournalBoundaryV1>, OperationJournalConfigurationError> {
    Ok(read_qualification_snapshot_database(file, expected_owner_uid)?.qualification_boundaries)
}

#[cfg(all(unix, any(feature = "qualification-evidence", test)))]
fn read_qualification_snapshot_database(
    file: &mut File,
    expected_owner_uid: u32,
) -> Result<OperationDatabaseV1, OperationJournalConfigurationError> {
    let access =
        rustix::fs::fcntl_getfl(&*file).map_err(|_| OperationJournalConfigurationError::Io)?;
    if access & OFlags::ACCMODE != OFlags::RDONLY {
        return Err(OperationJournalConfigurationError::InvalidState);
    }
    let before = file
        .metadata()
        .map_err(|_| OperationJournalConfigurationError::Io)?;
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.uid() != expected_owner_uid
        || before.mode() & 0o777 != 0o600
        || usize::try_from(before.len())
            .map_or(true, |length| length > MAX_QUALIFICATION_SNAPSHOT_BYTES)
    {
        return Err(OperationJournalConfigurationError::InvalidState);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| OperationJournalConfigurationError::Io)?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(file)
        .take(u64::try_from(MAX_QUALIFICATION_SNAPSHOT_BYTES).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| OperationJournalConfigurationError::Io)?;
    let after = file
        .metadata()
        .map_err(|_| OperationJournalConfigurationError::Io)?;
    if bytes.len() > MAX_QUALIFICATION_SNAPSHOT_BYTES
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || after.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
    {
        return Err(OperationJournalConfigurationError::InvalidState);
    }
    decode_qualification_snapshot(&bytes)
}

#[cfg(all(unix, any(feature = "qualification-evidence", test)))]
fn decode_qualification_snapshot(
    bytes: &[u8],
) -> Result<OperationDatabaseV1, OperationJournalConfigurationError> {
    if bytes.len() < DATABASE_MAGIC.len() || !bytes.starts_with(DATABASE_MAGIC) {
        return Err(OperationJournalConfigurationError::InvalidState);
    }
    let database: OperationDatabaseV1 = postcard::from_bytes(&bytes[DATABASE_MAGIC.len()..])
        .map_err(|_| OperationJournalConfigurationError::InvalidState)?;
    let permissive = OperationJournalLimitsV1::new(
        10_000,
        1_024,
        256,
        1024 * 1024 * 1024,
        1_000_000,
        31_536_000,
        315_360_000,
        16,
        8 * 1024 * 1024,
        16 * 1024 * 1024,
    )?;
    let limits = database
        .records
        .values()
        .map(|record| record.binding().profile().clone())
        .chain(
            database
                .tombstones
                .values()
                .map(|value| value.profile.clone()),
        )
        .map(|profile| (profile, permissive))
        .collect::<BTreeMap<_, _>>();
    if limits.is_empty() {
        return Err(OperationJournalConfigurationError::InvalidState);
    }
    validate_database(&database, &limits)?;
    if encode_database(&database).map_err(|_| OperationJournalConfigurationError::InvalidState)?
        != bytes
    {
        return Err(OperationJournalConfigurationError::InvalidState);
    }
    Ok(database)
}

/// Generates a CSPRNG-backed operation identifier.
pub fn generate_operation_id() -> Result<OperationIdV1, OperationJournalError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| OperationJournalError::Unavailable)?;
    OperationIdV1::from_random_bytes(bytes).map_err(|_| OperationJournalError::Unavailable)
}

fn replay_for(
    database: &OperationDatabaseV1,
    candidate: &JournalRecordV1,
) -> Result<Option<PrepareJournalResult>, OperationJournalError> {
    let request_match = database
        .request_index
        .get(&request_key(candidate.binding()));
    let idempotency_match = idempotency_key(candidate.binding())
        .as_ref()
        .and_then(|key| database.idempotency_index.get(key));
    if request_match.is_some() && idempotency_match.is_some() && request_match != idempotency_match
    {
        return Err(OperationJournalError::InvalidState);
    }
    let Some(operation_id) = request_match.or(idempotency_match) else {
        return Ok(None);
    };
    let compare_idempotency = request_match.is_none() && idempotency_match.is_some();
    if let Some(original) = database.records.get(operation_id) {
        let matches = if compare_idempotency {
            original.binding.idempotency_replay_commitment()
                == candidate.binding.idempotency_replay_commitment()
        } else {
            original.binding.preparation_commitment() == candidate.binding.preparation_commitment()
        };
        if matches {
            return Ok(Some(PrepareJournalResult::Replayed(original.clone())));
        }
        return Ok(Some(PrepareJournalResult::Conflict {
            original_operation_id: operation_id.clone(),
        }));
    }
    if let Some(original) = database.tombstones.get(operation_id) {
        let matches = if compare_idempotency {
            original.idempotency_replay_commitment
                == candidate.binding.idempotency_replay_commitment()
        } else {
            &original.preparation_commitment == candidate.binding.preparation_commitment()
        };
        if matches {
            return Ok(Some(PrepareJournalResult::ReplayedTombstone(
                original.clone(),
            )));
        }
        return Ok(Some(PrepareJournalResult::Conflict {
            original_operation_id: operation_id.clone(),
        }));
    }
    Err(OperationJournalError::InvalidState)
}

fn collect_expired(
    database: &mut OperationDatabaseV1,
    limits: &BTreeMap<OperationProfileV1, OperationJournalLimitsV1>,
    now_unix_seconds: u64,
) -> Result<(), OperationJournalError> {
    database
        .admissions
        .retain(|key, _| key.minute >= now_unix_seconds.saturating_div(60));
    let collect = database
        .records
        .values()
        .filter(|record| {
            let Some(limit) = limits.get(record.binding.profile()) else {
                return false;
            };
            record.projection.is_terminal()
                && now_unix_seconds.saturating_sub(record.updated_at_unix_seconds)
                    >= limit.idempotency_retention_seconds
        })
        .map(|record| record.operation_id.clone())
        .collect::<Vec<_>>();
    #[cfg(feature = "qualification-evidence")]
    if !collect.is_empty() {
        return Err(OperationJournalError::InvalidState);
    }
    for operation_id in collect {
        let record = database
            .records
            .remove(&operation_id)
            .ok_or(OperationJournalError::InvalidState)?;
        let tombstone = TombstoneV1 {
            operation_id: operation_id.clone(),
            principal: record.binding.principal().to_owned(),
            profile: record.binding.profile().clone(),
            request_id: record.binding.request_id(),
            idempotency_commitment: record.binding.idempotency_commitment().copied(),
            canonical_input_commitment: *record.binding.canonical_input_commitment(),
            preparation_evidence_intent_commitment: record
                .binding
                .preparation_evidence_intent_commitment()
                .copied(),
            connection_alias: record
                .binding
                .connection()
                .map(|connection| connection.alias().to_owned()),
            preparation_commitment: *record.binding.preparation_commitment(),
            idempotency_replay_commitment: record.binding.idempotency_replay_commitment(),
            effect: record.projection.effect(),
            receipt_ids: record
                .receipts
                .iter()
                .map(|value| value.receipt_id.clone())
                .collect(),
            terminal_at_unix_seconds: record.updated_at_unix_seconds,
        };
        database.tombstones.insert(operation_id, tombstone);
    }
    let expired = database
        .tombstones
        .values()
        .filter(|tombstone| {
            limits.get(&tombstone.profile).is_some_and(|limit| {
                now_unix_seconds.saturating_sub(tombstone.terminal_at_unix_seconds)
                    >= limit.idempotency_retention_seconds
            })
        })
        .map(|value| value.operation_id.clone())
        .collect::<Vec<_>>();
    for operation_id in expired {
        let tombstone = database
            .tombstones
            .remove(&operation_id)
            .ok_or(OperationJournalError::InvalidState)?;
        database.request_index.remove(&RequestIndexKey {
            principal: tombstone.principal.clone(),
            request_id: tombstone.request_id,
        });
        if let Some(commitment) = tombstone.idempotency_commitment {
            database.idempotency_index.remove(&IdempotencyIndexKey {
                principal: tombstone.principal,
                profile_id: tombstone.profile.id().to_owned(),
                profile_version: tombstone.profile.version(),
                commitment,
            });
        }
    }
    for (scope, limit) in limits_by_scope(database, limits) {
        let tombstone_count = database
            .tombstones
            .values()
            .filter(|value| tombstone_scope(value) == scope)
            .count();
        if tombstone_count > limit.tombstones_per_principal as usize {
            return Err(OperationJournalError::Capacity);
        }
    }
    Ok(())
}

fn limits_by_scope(
    database: &OperationDatabaseV1,
    limits: &BTreeMap<OperationProfileV1, OperationJournalLimitsV1>,
) -> Vec<(ProfilePrincipalKey, OperationJournalLimitsV1)> {
    let mut scopes = BTreeSet::new();
    for record in database.records.values() {
        scopes.insert(binding_scope(record.binding()));
    }
    for tombstone in database.tombstones.values() {
        scopes.insert(tombstone_scope(tombstone));
    }
    scopes
        .into_iter()
        .filter_map(|scope| {
            limits
                .iter()
                .find(|(profile, _)| {
                    profile.id() == scope.profile_id && profile.version() == scope.profile_version
                })
                .map(|(_, limit)| (scope, *limit))
        })
        .collect()
}

fn enforce_scope_capacity(
    database: &OperationDatabaseV1,
    scope: &ProfilePrincipalKey,
    limits: OperationJournalLimitsV1,
) -> Result<(), OperationJournalError> {
    let bytes = durable_scope_bytes(database, scope)?;
    let tombstones = database
        .tombstones
        .values()
        .filter(|value| tombstone_scope(value) == *scope)
        .count();
    if bytes > limits.durable_bytes_per_principal
        || tombstones > limits.tombstones_per_principal as usize
    {
        return Err(OperationJournalError::Capacity);
    }
    Ok(())
}

fn durable_scope_bytes(
    database: &OperationDatabaseV1,
    scope: &ProfilePrincipalKey,
) -> Result<u64, OperationJournalError> {
    let mut bytes = 0_u64;
    for record in database
        .records
        .values()
        .filter(|value| binding_scope(value.binding()) == *scope)
    {
        bytes = add_encoded(bytes, record)?;
    }
    for tombstone in database
        .tombstones
        .values()
        .filter(|value| tombstone_scope(value) == *scope)
    {
        bytes = add_encoded(bytes, tombstone)?;
    }
    for (key, operation) in database
        .request_index
        .iter()
        .filter(|(key, _)| key.principal == scope.principal)
    {
        if operation_in_scope(database, operation, scope) {
            bytes = add_encoded(bytes, &(key, operation))?;
        }
    }
    for (key, operation) in database.idempotency_index.iter().filter(|(key, _)| {
        key.principal == scope.principal
            && key.profile_id == scope.profile_id
            && key.profile_version == scope.profile_version
    }) {
        bytes = add_encoded(bytes, &(key, operation))?;
    }
    for (key, count) in database
        .admissions
        .iter()
        .filter(|(key, _)| key.scope == *scope)
    {
        bytes = add_encoded(bytes, &(key, count))?;
    }
    Ok(bytes)
}

fn add_encoded<T: Serialize>(total: u64, value: &T) -> Result<u64, OperationJournalError> {
    let length = postcard::to_allocvec(value)
        .map_err(|_| OperationJournalError::InvalidState)?
        .len() as u64;
    total
        .checked_add(length)
        .ok_or(OperationJournalError::Capacity)
}

fn operation_in_scope(
    database: &OperationDatabaseV1,
    operation: &OperationIdV1,
    expected: &ProfilePrincipalKey,
) -> bool {
    database
        .records
        .get(operation)
        .is_some_and(|value| binding_scope(value.binding()) == *expected)
        || database
            .tombstones
            .get(operation)
            .is_some_and(|value| tombstone_scope(value) == *expected)
}

fn validate_database(
    database: &OperationDatabaseV1,
    limits: &BTreeMap<OperationProfileV1, OperationJournalLimitsV1>,
) -> Result<(), OperationJournalConfigurationError> {
    if database.version != DATABASE_VERSION
        || database.records.len() > 1_000_000
        || database.tombstones.len() > 1_000_000
        || database.request_index.len()
            != database
                .records
                .len()
                .saturating_add(database.tombstones.len())
    {
        return Err(OperationJournalConfigurationError::InvalidState);
    }
    for (operation_id, record) in &database.records {
        if operation_id != record.operation_id()
            || record.binding.validate().is_err()
            || record.projection.validate().is_err()
        {
            return Err(OperationJournalConfigurationError::InvalidState);
        }
        let profile_limits = limits
            .get(record.binding.profile())
            .copied()
            .ok_or(OperationJournalConfigurationError::InvalidState)?;
        record
            .validate_limits(profile_limits)
            .map_err(|_| OperationJournalConfigurationError::InvalidState)?;
        if database.request_index.get(&request_key(record.binding())) != Some(operation_id)
            || idempotency_key(record.binding())
                .is_some_and(|key| database.idempotency_index.get(&key) != Some(operation_id))
        {
            return Err(OperationJournalConfigurationError::InvalidState);
        }
    }
    for (operation_id, tombstone) in &database.tombstones {
        if operation_id != &tombstone.operation_id
            || !limits.contains_key(&tombstone.profile)
            || database.request_index.get(&RequestIndexKey {
                principal: tombstone.principal.clone(),
                request_id: tombstone.request_id,
            }) != Some(operation_id)
        {
            return Err(OperationJournalConfigurationError::InvalidState);
        }
    }
    for (key, operation_id) in &database.idempotency_index {
        let matches = database
            .records
            .get(operation_id)
            .is_some_and(|value| idempotency_key(value.binding()).as_ref() == Some(key))
            || database.tombstones.get(operation_id).is_some_and(|value| {
                value.idempotency_commitment.is_some_and(|commitment| {
                    IdempotencyIndexKey {
                        principal: value.principal.clone(),
                        profile_id: value.profile.id().to_owned(),
                        profile_version: value.profile.version(),
                        commitment,
                    } == *key
                })
            });
        if !matches {
            return Err(OperationJournalConfigurationError::InvalidState);
        }
    }
    let pending = database
        .records
        .values()
        .filter(|value| !value.projection.is_terminal())
        .fold(BTreeMap::<&str, usize>::new(), |mut counts, value| {
            *counts.entry(value.binding.principal()).or_default() += 1;
            counts
        });
    if pending.values().any(|count| *count > MAX_PRINCIPAL_PENDING) {
        return Err(OperationJournalConfigurationError::InvalidState);
    }
    for (scope, limit) in limits_by_scope(database, limits) {
        enforce_scope_capacity(database, &scope, limit)
            .map_err(|_| OperationJournalConfigurationError::InvalidState)?;
    }
    #[cfg(feature = "qualification-evidence")]
    validate_qualification_boundaries(database)?;
    Ok(())
}

#[cfg(feature = "qualification-evidence")]
#[allow(clippy::too_many_lines)]
fn validate_qualification_boundaries(
    database: &OperationDatabaseV1,
) -> Result<(), OperationJournalConfigurationError> {
    if database.qualification_boundaries.len() > MAX_QUALIFICATION_BOUNDARIES {
        return Err(OperationJournalConfigurationError::InvalidState);
    }
    let mut prior = BTreeMap::<&OperationIdV1, (u64, QualificationJournalBoundaryKindV1)>::new();
    let mut revision_projections = BTreeMap::new();
    for (index, boundary) in database.qualification_boundaries.iter().enumerate() {
        let ordinal = u32::try_from(index + 1)
            .map_err(|_| OperationJournalConfigurationError::InvalidState)?;
        let record = database
            .records
            .get(&boundary.operation_id)
            .ok_or(OperationJournalConfigurationError::InvalidState)?;
        let request_kind = matches!(
            boundary.kind,
            QualificationJournalBoundaryKindV1::Replay
                | QualificationJournalBoundaryKindV1::Status
                | QualificationJournalBoundaryKindV1::Recovery
        );
        let projection = qualification_boundary_projection_commitment(boundary)
            .map_err(|_| OperationJournalConfigurationError::InvalidState)?;
        if boundary.ordinal != ordinal
            || boundary.profile != *record.binding().profile()
            || boundary.connection_generation
                != record
                    .binding()
                    .connection()
                    .map(auths_lifecycle::ConnectionBindingCommitmentsV1::generation)
            || boundary.journal_revision == 0
            || boundary.journal_revision > record.revision()
            || request_kind != boundary.request_id.is_some()
            || boundary.projection_sha256 != projection
            || !qualification_boundary_shape_valid(record, boundary)
        {
            return Err(OperationJournalConfigurationError::InvalidState);
        }
        let projection = (boundary.state, boundary.effect, boundary.terminal);
        if revision_projections
            .insert(
                (&boundary.operation_id, boundary.journal_revision),
                projection,
            )
            .is_some_and(|prior| prior != projection)
        {
            return Err(OperationJournalConfigurationError::InvalidState);
        }
        if let Some((prior_revision, prior_kind)) = prior.insert(
            &boundary.operation_id,
            (boundary.journal_revision, boundary.kind),
        ) && (boundary.journal_revision < prior_revision
            || boundary.journal_revision == prior_revision
                && !request_kind
                && !(prior_kind == QualificationJournalBoundaryKindV1::Decision
                    && boundary.kind == QualificationJournalBoundaryKindV1::Terminal))
        {
            return Err(OperationJournalConfigurationError::InvalidState);
        }
        validate_qualification_boundary_subject(record, boundary)?;
    }
    for record in database.records.values() {
        let rows = database
            .qualification_boundaries
            .iter()
            .filter(|boundary| boundary.operation_id == *record.operation_id())
            .collect::<Vec<_>>();
        let count = |kind| rows.iter().filter(|boundary| boundary.kind == kind).count();
        if rows.first().map(|boundary| boundary.kind)
            != Some(QualificationJournalBoundaryKindV1::Decision)
            || count(QualificationJournalBoundaryKindV1::Decision) != 1
            || count(QualificationJournalBoundaryKindV1::Command)
                != usize::from(record.sealed_command().is_some())
            || count(QualificationJournalBoundaryKindV1::ProviderEntry)
                != usize::from(record.provider_entered())
            || count(QualificationJournalBoundaryKindV1::ProviderResult)
                != usize::from(record.provider_result().is_some())
            || count(QualificationJournalBoundaryKindV1::Observation) != record.observations().len()
            || count(QualificationJournalBoundaryKindV1::ExecutionReceipt)
                != usize::from(record.receipts().len() == 2)
            || count(QualificationJournalBoundaryKindV1::Terminal)
                != usize::from(record.projection().is_terminal())
            || !record.projection().is_terminal()
                && match record.projection().state() {
                    OperationStateV1::RecoveryRequired => {
                        count(QualificationJournalBoundaryKindV1::RecoveryRequired) == 0
                    }
                    _ => count(QualificationJournalBoundaryKindV1::RecoveryRequired) != 0,
                }
        {
            return Err(OperationJournalConfigurationError::InvalidState);
        }
        let observation_indexes = rows
            .iter()
            .filter(|boundary| boundary.kind == QualificationJournalBoundaryKindV1::Observation)
            .filter_map(|boundary| boundary.subject_index)
            .collect::<Vec<_>>();
        if observation_indexes
            != (0..record.observations().len())
                .map(|index| u8::try_from(index).unwrap_or(u8::MAX))
                .collect::<Vec<_>>()
        {
            return Err(OperationJournalConfigurationError::InvalidState);
        }
    }
    Ok(())
}

#[cfg(feature = "qualification-evidence")]
fn qualification_boundary_shape_valid(
    record: &JournalRecordV1,
    boundary: &QualificationJournalBoundaryV1,
) -> bool {
    if OperationProjectionV1::new(boundary.state, boundary.effect, boundary.terminal).is_err() {
        return false;
    }
    let completion_valid = match boundary.state {
        OperationStateV1::Completed | OperationStateV1::Partial | OperationStateV1::NotApplied => {
            boundary.completion.is_some()
        }
        OperationStateV1::Denied
        | OperationStateV1::Unavailable
        | OperationStateV1::Preparing
        | OperationStateV1::Ready
        | OperationStateV1::Executing
        | OperationStateV1::RecoveryRequired => boundary.completion.is_none(),
    };
    if !completion_valid {
        return false;
    }
    match boundary.kind {
        QualificationJournalBoundaryKindV1::Decision => {
            boundary.journal_revision == 1
                && boundary.effect == OperationEffectV1::NotApplied
                && boundary.completion.is_none()
                && match record.decision_class() {
                    JournalDecisionClassV1::Authorized => {
                        boundary.state == OperationStateV1::Ready && !boundary.terminal
                    }
                    JournalDecisionClassV1::Denied => {
                        boundary.state == OperationStateV1::Denied && boundary.terminal
                    }
                    JournalDecisionClassV1::Indeterminate => {
                        boundary.state == OperationStateV1::Unavailable && boundary.terminal
                    }
                }
        }
        QualificationJournalBoundaryKindV1::Command => {
            boundary.state == OperationStateV1::Ready
                && boundary.effect == OperationEffectV1::NotApplied
                && !boundary.terminal
        }
        QualificationJournalBoundaryKindV1::ProviderEntry
        | QualificationJournalBoundaryKindV1::ProviderResult => {
            boundary.state == OperationStateV1::Executing
                && boundary.effect == OperationEffectV1::Possible
                && !boundary.terminal
        }
        QualificationJournalBoundaryKindV1::Observation
        | QualificationJournalBoundaryKindV1::ExecutionReceipt => {
            matches!(
                boundary.state,
                OperationStateV1::Executing | OperationStateV1::RecoveryRequired
            ) && boundary.effect == OperationEffectV1::Possible
                && !boundary.terminal
        }
        QualificationJournalBoundaryKindV1::RecoveryRequired => {
            boundary.state == OperationStateV1::RecoveryRequired
                && boundary.effect == OperationEffectV1::Possible
                && !boundary.terminal
                && boundary.completion.is_none()
        }
        QualificationJournalBoundaryKindV1::Terminal => {
            boundary.journal_revision == record.revision()
                && boundary.state == record.projection().state()
                && boundary.effect == record.projection().effect()
                && boundary.terminal == record.projection().is_terminal()
                && boundary.completion == record.completion()
        }
        QualificationJournalBoundaryKindV1::Replay => {
            if boundary.terminal {
                boundary.state == record.projection().state()
                    && boundary.effect == record.projection().effect()
                    && record.projection().is_terminal()
                    && boundary.completion == Some(JournalCompletionV1::Replayed)
            } else {
                boundary.completion.is_none()
            }
        }
        QualificationJournalBoundaryKindV1::Status => {
            boundary.request_id == Some(record.binding().request_id())
                && if boundary.terminal {
                    boundary.state == record.projection().state()
                        && boundary.effect == record.projection().effect()
                        && record.projection().is_terminal()
                        && boundary.completion == record.completion()
                } else {
                    boundary.completion.is_none()
                }
        }
        QualificationJournalBoundaryKindV1::Recovery => {
            if boundary.terminal {
                boundary.state == record.projection().state()
                    && boundary.effect == record.projection().effect()
                    && record.projection().is_terminal()
                    && (boundary.completion == record.completion()
                        || boundary.completion == Some(JournalCompletionV1::Replayed))
            } else {
                boundary.completion.is_none()
            }
        }
    }
}

#[cfg(feature = "qualification-evidence")]
fn validate_qualification_boundary_subject(
    record: &JournalRecordV1,
    boundary: &QualificationJournalBoundaryV1,
) -> Result<(), OperationJournalConfigurationError> {
    let subject = match boundary.kind {
        QualificationJournalBoundaryKindV1::Decision => {
            if boundary.journal_revision != 1 || boundary.subject_index != Some(0) {
                return Err(OperationJournalConfigurationError::InvalidState);
            }
            record.receipts().first().map(JournalReceiptV1::bytes)
        }
        QualificationJournalBoundaryKindV1::Command
        | QualificationJournalBoundaryKindV1::ProviderEntry => {
            if boundary.subject_index.is_some() {
                return Err(OperationJournalConfigurationError::InvalidState);
            }
            record.sealed_command()
        }
        QualificationJournalBoundaryKindV1::ProviderResult => {
            if boundary.subject_index.is_some() {
                return Err(OperationJournalConfigurationError::InvalidState);
            }
            record.provider_result()
        }
        QualificationJournalBoundaryKindV1::Observation => boundary
            .subject_index
            .and_then(|index| record.observations().get(usize::from(index)))
            .map(Vec::as_slice),
        QualificationJournalBoundaryKindV1::ExecutionReceipt => boundary
            .subject_index
            .and_then(|index| record.receipts().get(usize::from(index)))
            .map(JournalReceiptV1::bytes),
        QualificationJournalBoundaryKindV1::RecoveryRequired
        | QualificationJournalBoundaryKindV1::Terminal
        | QualificationJournalBoundaryKindV1::Replay
        | QualificationJournalBoundaryKindV1::Status
        | QualificationJournalBoundaryKindV1::Recovery => {
            if boundary.subject_index.is_some() {
                return Err(OperationJournalConfigurationError::InvalidState);
            }
            if boundary.subject_sha256 != boundary.projection_sha256 {
                return Err(OperationJournalConfigurationError::InvalidState);
            }
            return Ok(());
        }
    }
    .ok_or(OperationJournalConfigurationError::InvalidState)?;
    if boundary.subject_sha256 != <[u8; 32]>::from(Sha256::digest(subject)) {
        return Err(OperationJournalConfigurationError::InvalidState);
    }
    Ok(())
}

#[cfg(feature = "qualification-evidence")]
fn qualification_boundary_projection_commitment(
    boundary: &QualificationJournalBoundaryV1,
) -> Result<[u8; 32], OperationJournalError> {
    let public = (
        boundary.ordinal,
        boundary.kind,
        &boundary.operation_id,
        &boundary.profile,
        boundary.connection_generation,
        boundary.journal_revision,
        boundary.request_id,
        boundary.state,
        boundary.effect,
        boundary.terminal,
        boundary.completion,
    );
    let encoded =
        postcard::to_allocvec(&public).map_err(|_| OperationJournalError::InvalidState)?;
    let mut digest = Sha256::new();
    digest.update(b"auths.qualification-journal-projection/1\0");
    digest.update(encoded);
    Ok(digest.finalize().into())
}

fn decode_database(
    bytes: &[u8],
    limits: &BTreeMap<OperationProfileV1, OperationJournalLimitsV1>,
) -> Result<OperationDatabaseV1, OperationJournalConfigurationError> {
    if bytes.len() < DATABASE_MAGIC.len() || !bytes.starts_with(DATABASE_MAGIC) {
        return Err(OperationJournalConfigurationError::InvalidState);
    }
    let database: OperationDatabaseV1 = postcard::from_bytes(&bytes[DATABASE_MAGIC.len()..])
        .map_err(|_| OperationJournalConfigurationError::InvalidState)?;
    validate_database(&database, limits)?;
    let canonical =
        encode_database(&database).map_err(|_| OperationJournalConfigurationError::InvalidState)?;
    if canonical != bytes {
        return Err(OperationJournalConfigurationError::InvalidState);
    }
    Ok(database)
}

fn encode_database(database: &OperationDatabaseV1) -> Result<Vec<u8>, OperationJournalError> {
    let payload =
        postcard::to_allocvec(database).map_err(|_| OperationJournalError::InvalidState)?;
    let length = DATABASE_MAGIC
        .len()
        .checked_add(payload.len())
        .ok_or(OperationJournalError::Capacity)?;
    if length > MAX_DATABASE_BYTES {
        return Err(OperationJournalError::Capacity);
    }
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(DATABASE_MAGIC);
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DatabasePersistence {
    Durable,
    PublishedWithoutDirectorySync,
}

fn persist_database(
    path: &Path,
    database: &OperationDatabaseV1,
) -> Result<DatabasePersistence, OperationJournalError> {
    let bytes = encode_database(database)?;
    let parent = path.parent().ok_or(OperationJournalError::Unavailable)?;
    fs::create_dir_all(parent).map_err(|_| OperationJournalError::Unavailable)?;
    let mut temporary =
        NamedTempFile::new_in(parent).map_err(|_| OperationJournalError::Unavailable)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| OperationJournalError::Unavailable)?;
    }
    temporary
        .write_all(&bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| OperationJournalError::Unavailable)?;
    temporary
        .persist(path)
        .map_err(|_| OperationJournalError::Unavailable)?;
    if File::open(parent)
        .and_then(|directory| directory.sync_all())
        .is_err()
    {
        return Ok(DatabasePersistence::PublishedWithoutDirectorySync);
    }
    Ok(DatabasePersistence::Durable)
}

fn projection(
    state: OperationStateV1,
    effect: OperationEffectV1,
    terminal: bool,
) -> Result<OperationProjectionV1, OperationJournalError> {
    OperationProjectionV1::new(state, effect, terminal)
        .map_err(|_| OperationJournalError::InvalidTransition)
}

fn request_key(binding: &PreparationBindingV1) -> RequestIndexKey {
    RequestIndexKey {
        principal: binding.principal().to_owned(),
        request_id: binding.request_id(),
    }
}

fn idempotency_key(binding: &PreparationBindingV1) -> Option<IdempotencyIndexKey> {
    binding
        .idempotency_commitment()
        .copied()
        .map(|commitment| IdempotencyIndexKey {
            principal: binding.principal().to_owned(),
            profile_id: binding.profile().id().to_owned(),
            profile_version: binding.profile().version(),
            commitment,
        })
}

fn binding_scope(binding: &PreparationBindingV1) -> ProfilePrincipalKey {
    ProfilePrincipalKey {
        principal: binding.principal().to_owned(),
        profile_id: binding.profile().id().to_owned(),
        profile_version: binding.profile().version(),
    }
}

fn tombstone_scope(value: &TombstoneV1) -> ProfilePrincipalKey {
    ProfilePrincipalKey {
        principal: value.principal.clone(),
        profile_id: value.profile.id().to_owned(),
        profile_version: value.profile.version(),
    }
}

fn bounded_ascii_graphic(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.bytes().all(|byte| byte.is_ascii_graphic())
}

/// Operation journal open/configuration failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OperationJournalConfigurationError {
    /// Path is empty or has no parent.
    #[error("operation journal path is invalid")]
    InvalidPath,
    /// Manifest-derived bounds are invalid.
    #[error("operation journal limits are invalid")]
    InvalidLimits,
    /// Existing durable state is malformed, noncanonical, or inconsistent.
    #[error("operation journal state is invalid")]
    InvalidState,
    /// Durable state could not be opened.
    #[error("operation journal I/O failed")]
    Io,
}

/// Closed journal operation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OperationJournalError {
    /// Record fields or profile identity are invalid.
    #[error("operation journal record is invalid")]
    InvalidRecord,
    /// State/effect transition or durable ordering is invalid.
    #[error("operation journal transition is invalid")]
    InvalidTransition,
    /// Operation is absent or belongs to another principal.
    #[error("operation journal record was not found")]
    NotFound,
    /// Optimistic revision or immutable operation ID conflicted.
    #[error("operation journal operation conflicted")]
    Conflict,
    /// Admission, record, tombstone, or byte capacity is exhausted.
    #[error("operation journal capacity is exhausted")]
    Capacity,
    /// Existing in-memory/durable state is internally inconsistent.
    #[error("operation journal state is invalid")]
    InvalidState,
    /// Lock, randomness, or durable publication is unavailable.
    #[error("operation journal is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use auths_lifecycle::{
        ClientRequestIdV1, OperationProfileV1, OperationProjectionV1, OperationStateV1,
        PreparationBindingV1,
    };
    use sha2::{Digest as _, Sha256};

    use super::*;

    fn profile() -> OperationProfileV1 {
        OperationProfileV1::new("auths.opentofu.saved-plan-apply", 1, [1; 32]).unwrap()
    }

    fn limits() -> OperationJournalLimitsV1 {
        OperationJournalLimitsV1::new(
            120,
            16,
            8,
            256 * 1024 * 1024,
            100_000,
            2_592_000,
            2_592_000,
            4,
            65_536,
            262_144,
        )
        .unwrap()
    }

    fn record(request: [u8; 16], idempotency: Option<[u8; 32]>) -> JournalRecordV1 {
        let binding = PreparationBindingV1::new(
            "did:key:workload",
            profile(),
            ClientRequestIdV1::from_bytes(request),
            idempotency,
            [2; 32],
            None,
            None,
            None,
            [3; 32],
            [4; 32],
            [5; 32],
        )
        .unwrap();
        JournalRecordV1::prepared(
            generate_operation_id().unwrap(),
            binding,
            JournalDecisionClassV1::Authorized,
            [6; 32],
            [7; 32],
            OperationProjectionV1::new(
                OperationStateV1::Ready,
                OperationEffectV1::NotApplied,
                false,
            )
            .unwrap(),
            1_000,
            vec![9; 64],
            None,
            vec![0xa0],
            vec![JournalReceiptV1::new("receipt-decision", vec![0xa0]).unwrap()],
        )
        .unwrap()
    }

    #[test]
    fn exact_request_and_idempotency_replay_without_new_record() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("operations.db");
        let journal = PersistentOperationJournal::open(&path, [(profile(), limits())]).unwrap();
        let first = record([7; 16], Some([8; 32]));
        assert!(matches!(
            journal.prepare(first.clone(), 1_000).unwrap(),
            PrepareJournalResult::Created(_)
        ));
        let replay = JournalRecordV1::prepared(
            generate_operation_id().unwrap(),
            first.binding.clone(),
            first.decision_class,
            first.receipt_action_commitment,
            first.receipt_context_commitment,
            first.projection,
            1_000,
            first.recovery_handle.clone(),
            None,
            first.profile_state.clone(),
            first.receipts.clone(),
        )
        .unwrap();
        assert!(matches!(
            journal.prepare(replay, 1_000).unwrap(),
            PrepareJournalResult::Replayed(_)
        ));
        assert_eq!(journal.pending("did:key:workload").unwrap().len(), 1);
        drop(journal);
        let reopened = PersistentOperationJournal::open(&path, [(profile(), limits())]).unwrap();
        assert_eq!(reopened.pending("did:key:workload").unwrap().len(), 1);
    }

    #[cfg(feature = "qualification-evidence")]
    #[test]
    fn qualification_boundaries_are_atomic_gap_free_and_keep_projection_occurrences() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("operations.db");
        let journal = PersistentOperationJournal::open(&path, [(profile(), limits())]).unwrap();
        let prepared = record([31; 16], Some([32; 32]));
        let operation = prepared.operation_id().clone();
        let PrepareJournalResult::Created(prepared) = journal.prepare(prepared, 1_000).unwrap()
        else {
            panic!("fresh qualification operation replayed");
        };
        let command = journal
            .mutate_operation(
                "did:key:workload",
                &operation,
                prepared.revision(),
                OperationMutationV1::SealPreEntry {
                    profile_state: vec![0xa1],
                    sealed_command: vec![0xa2],
                },
                1_001,
            )
            .unwrap();
        let status_request = prepared.binding().request_id();
        journal
            .record_status_for_qualification("did:key:workload", &operation, status_request)
            .unwrap();
        let terminal = journal
            .mutate_operation(
                "did:key:workload",
                &operation,
                command.revision(),
                OperationMutationV1::ConcludePreEntry {
                    state: OperationStateV1::NotApplied,
                    issue: vec![0xa3],
                    profile_state: vec![0xa1],
                },
                1_002,
            )
            .unwrap();
        journal
            .record_status_for_qualification("did:key:workload", &operation, status_request)
            .unwrap();
        journal
            .record_status_for_qualification("did:key:workload", &operation, status_request)
            .unwrap();

        let database = journal.database.lock().unwrap();
        let kinds = database
            .qualification_boundaries
            .iter()
            .map(|boundary| boundary.kind())
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            vec![
                QualificationJournalBoundaryKindV1::Decision,
                QualificationJournalBoundaryKindV1::Command,
                QualificationJournalBoundaryKindV1::Status,
                QualificationJournalBoundaryKindV1::Terminal,
                QualificationJournalBoundaryKindV1::Status,
                QualificationJournalBoundaryKindV1::Status,
            ]
        );
        assert_eq!(
            database
                .qualification_boundaries
                .iter()
                .map(QualificationJournalBoundaryV1::ordinal)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5, 6]
        );
        assert_eq!(
            database.qualification_boundaries[3].journal_revision(),
            terminal.revision()
        );
        assert_ne!(
            database.qualification_boundaries[4].projection_sha256(),
            database.qualification_boundaries[5].projection_sha256()
        );
        validate_qualification_boundaries(&database).unwrap();
        let mut forged = database.clone();
        drop(database);
        forged.qualification_boundaries[1].state = OperationStateV1::Executing;
        forged.qualification_boundaries[1].effect = OperationEffectV1::Possible;
        forged.qualification_boundaries[1].projection_sha256 =
            qualification_boundary_projection_commitment(&forged.qualification_boundaries[1])
                .unwrap();
        assert!(validate_qualification_boundaries(&forged).is_err());

        let mut forged_status = journal.database.lock().unwrap().clone();
        let status = &mut forged_status.qualification_boundaries[2];
        status.state = OperationStateV1::Executing;
        status.effect = OperationEffectV1::NotApplied;
        status.projection_sha256 = qualification_boundary_projection_commitment(status).unwrap();
        status.subject_sha256 = status.projection_sha256;
        assert!(validate_qualification_boundaries(&forged_status).is_err());
    }

    #[test]
    fn journal_path_has_one_live_process_owner() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("operations.db");
        let journal = PersistentOperationJournal::open(&path, [(profile(), limits())]).unwrap();
        assert!(matches!(
            PersistentOperationJournal::open(&path, [(profile(), limits())]),
            Err(OperationJournalConfigurationError::InvalidState)
        ));
        drop(journal);
        PersistentOperationJournal::open(&path, [(profile(), limits())]).unwrap();
    }

    #[test]
    fn ambiguous_persistence_poison_refuses_reads_and_writes_until_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let journal = PersistentOperationJournal::open(
            directory.path().join("operations.db"),
            [(profile(), limits())],
        )
        .unwrap();
        journal.poisoned.store(true, Ordering::Release);
        let operation = generate_operation_id().unwrap();
        assert_eq!(
            journal.status("did:key:workload", &operation),
            Err(OperationJournalError::Unavailable)
        );
        assert_eq!(
            journal.pending("did:key:workload"),
            Err(OperationJournalError::Unavailable)
        );
        assert_eq!(
            journal.collect(1_000),
            Err(OperationJournalError::Unavailable)
        );
    }

    #[test]
    fn qualification_reader_decodes_one_live_atomic_journal_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("operations.db");
        let journal = PersistentOperationJournal::open(&path, [(profile(), limits())]).unwrap();
        let expected = record([17; 16], Some([18; 32]));
        journal.prepare(expected.clone(), 1_000).unwrap();
        let actual = read_persisted_operation_record_for_qualification(
            &path,
            expected.binding().principal(),
            expected.operation_id(),
        )
        .unwrap();
        assert_eq!(actual, expected);
        actual.validate_exact_decision_snapshot().unwrap();
        journal
            .mutate_operation(
                expected.binding().principal(),
                expected.operation_id(),
                1,
                OperationMutationV1::SealPreEntry {
                    profile_state: vec![0xa1],
                    sealed_command: vec![0xa2],
                },
                1_001,
            )
            .unwrap();
        let advanced = read_persisted_operation_record_for_qualification(
            &path,
            expected.binding().principal(),
            expected.operation_id(),
        )
        .unwrap();
        assert!(advanced.validate_exact_decision_snapshot().is_err());
        assert!(
            read_persisted_operation_record_for_qualification(
                &path,
                "did:key:another-workload",
                expected.operation_id(),
            )
            .is_err()
        );
    }

    #[test]
    fn qualification_reader_opens_the_journal_from_one_pinned_state_directory() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("operations.cbor");
        let journal = PersistentOperationJournal::open(&path, [(profile(), limits())]).unwrap();
        let expected = record([27; 16], Some([28; 32]));
        journal.prepare(expected.clone(), 1_000).unwrap();
        let state = File::open(directory.path()).unwrap();
        let mut snapshot = open_persisted_operation_snapshot_at_for_qualification(
            &state,
            rustix::process::geteuid().as_raw(),
        )
        .unwrap();
        let actual = read_persisted_operation_record_from_qualification_snapshot(
            &mut snapshot,
            rustix::process::geteuid().as_raw(),
            expected.binding().principal(),
            expected.operation_id(),
        )
        .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            read_persisted_operation_records_from_qualification_snapshot(
                &mut snapshot,
                rustix::process::geteuid().as_raw(),
            )
            .unwrap(),
            vec![expected]
        );

        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750)).unwrap();
        assert!(
            open_persisted_operation_snapshot_at_for_qualification(
                &state,
                rustix::process::geteuid().as_raw(),
            )
            .is_err()
        );
    }

    #[test]
    fn caller_idempotency_replays_across_fresh_request_ids() {
        let directory = tempfile::tempdir().unwrap();
        let journal = PersistentOperationJournal::open(
            directory.path().join("operations.db"),
            [(profile(), limits())],
        )
        .unwrap();
        let first = record([7; 16], Some([8; 32]));
        let original = first.operation_id.clone();
        journal.prepare(first.clone(), 1_000).unwrap();
        let binding = PreparationBindingV1::new(
            first.binding.principal(),
            first.binding.profile().clone(),
            auths_lifecycle::ClientRequestIdV1::from_bytes([10; 16]),
            first.binding.idempotency_commitment().copied(),
            *first.binding.canonical_input_commitment(),
            first.binding.preparation_evidence_commitment().copied(),
            first
                .binding
                .preparation_evidence_intent_commitment()
                .copied(),
            first.binding.connection().cloned(),
            *first.binding.canonical_action_commitment(),
            *first.binding.authority_commitment(),
            *first.binding.configuration_commitment(),
        )
        .unwrap();
        let replay = JournalRecordV1::prepared(
            generate_operation_id().unwrap(),
            binding,
            first.decision_class,
            first.receipt_action_commitment,
            first.receipt_context_commitment,
            first.projection,
            1_000,
            first.recovery_handle,
            None,
            first.profile_state,
            first.receipts,
        )
        .unwrap();
        match journal.prepare(replay, 1_000).unwrap() {
            PrepareJournalResult::Replayed(record) => assert_eq!(record.operation_id, original),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn preparation_identity_expires_exactly_at_the_idempotency_boundary() {
        let directory = tempfile::tempdir().unwrap();
        let journal = PersistentOperationJournal::open(
            directory.path().join("operations.db"),
            [(profile(), limits())],
        )
        .unwrap();
        let first = record([21; 16], Some([22; 32]));
        let operation_id = first.operation_id.clone();
        let terminal = journal.prepare(first, 1_000).unwrap();
        let PrepareJournalResult::Created(terminal) = terminal else {
            panic!("unexpected replay");
        };
        let terminal = journal
            .mutate_operation(
                "did:key:workload",
                &operation_id,
                terminal.revision(),
                OperationMutationV1::ConcludePreEntry {
                    state: OperationStateV1::NotApplied,
                    issue: vec![0xa0],
                    profile_state: vec![0xa0],
                },
                1_001,
            )
            .unwrap();
        let retained_until = terminal
            .updated_at_unix_seconds()
            .checked_add(limits().idempotency_retention_seconds)
            .unwrap();
        assert!(matches!(
            journal
                .preparation_identity(
                    "did:key:workload",
                    &profile(),
                    ClientRequestIdV1::from_bytes([21; 16]),
                    Some([22; 32]),
                    retained_until - 1,
                )
                .unwrap(),
            PreparationIdentityLookup::Existing(JournalStatusV1::Record(_))
        ));
        #[cfg(feature = "qualification-evidence")]
        {
            assert_eq!(
                journal
                    .preparation_identity(
                        "did:key:workload",
                        &profile(),
                        ClientRequestIdV1::from_bytes([21; 16]),
                        Some([22; 32]),
                        retained_until,
                    )
                    .unwrap_err(),
                OperationJournalError::InvalidState
            );
            assert!(
                journal
                    .status("did:key:workload", &operation_id)
                    .unwrap()
                    .is_some()
            );
            return;
        }
        #[cfg(not(feature = "qualification-evidence"))]
        assert_eq!(
            journal
                .preparation_identity(
                    "did:key:workload",
                    &profile(),
                    ClientRequestIdV1::from_bytes([21; 16]),
                    Some([22; 32]),
                    retained_until,
                )
                .unwrap(),
            PreparationIdentityLookup::Absent
        );
        #[cfg(not(feature = "qualification-evidence"))]
        assert!(
            journal
                .status("did:key:workload", &operation_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn changed_commitment_returns_original_conflict() {
        let directory = tempfile::tempdir().unwrap();
        let journal = PersistentOperationJournal::open(
            directory.path().join("operations.db"),
            [(profile(), limits())],
        )
        .unwrap();
        let first = record([7; 16], Some([8; 32]));
        let original = first.operation_id.clone();
        journal.prepare(first.clone(), 1_000).unwrap();
        let changed_binding = PreparationBindingV1::new(
            first.binding.principal(),
            first.binding.profile().clone(),
            ClientRequestIdV1::from_bytes([10; 16]),
            first.binding.idempotency_commitment().copied(),
            [12; 32],
            first.binding.preparation_evidence_commitment().copied(),
            first
                .binding
                .preparation_evidence_intent_commitment()
                .copied(),
            first.binding.connection().cloned(),
            *first.binding.canonical_action_commitment(),
            *first.binding.authority_commitment(),
            *first.binding.configuration_commitment(),
        )
        .unwrap();
        let changed = JournalRecordV1::prepared(
            generate_operation_id().unwrap(),
            changed_binding,
            first.decision_class,
            first.receipt_action_commitment,
            first.receipt_context_commitment,
            first.projection,
            1_000,
            first.recovery_handle,
            None,
            first.profile_state,
            first.receipts,
        )
        .unwrap();
        match journal.prepare(changed, 1_000).unwrap() {
            PrepareJournalResult::Conflict {
                original_operation_id,
            } => assert_eq!(original_operation_id, original),
            other => panic!("unexpected {other:?}"),
        }
        #[cfg(feature = "qualification-evidence")]
        assert!(
            journal
                .database
                .lock()
                .unwrap()
                .qualification_boundaries
                .iter()
                .all(|boundary| boundary.kind() != QualificationJournalBoundaryKindV1::Replay)
        );
    }

    #[test]
    fn provider_result_must_be_durable_before_observation_and_terminal_state() {
        let directory = tempfile::tempdir().unwrap();
        let journal = PersistentOperationJournal::open(
            directory.path().join("operations.db"),
            [(profile(), limits())],
        )
        .unwrap();
        let record = record([7; 16], None);
        let id = record.operation_id.clone();
        journal.prepare(record, 1_000).unwrap();
        let sealed = journal
            .mutate_operation(
                "did:key:workload",
                &id,
                1,
                OperationMutationV1::SealPreEntry {
                    profile_state: vec![1],
                    sealed_command: vec![9],
                },
                1_001,
            )
            .unwrap();
        let executing = journal
            .mutate_operation(
                "did:key:workload",
                &id,
                sealed.revision(),
                OperationMutationV1::BeginExecution {
                    profile_state: vec![1],
                    sealed_command: vec![9],
                },
                1_001,
            )
            .unwrap();
        assert!(
            journal
                .mutate_operation(
                    "did:key:workload",
                    &id,
                    executing.revision(),
                    OperationMutationV1::RecordObservation { bytes: vec![2] },
                    1_002,
                )
                .is_err()
        );
        let entered = journal
            .mutate_operation(
                "did:key:workload",
                &id,
                journal
                    .mutate_operation(
                        "did:key:workload",
                        &id,
                        executing.revision(),
                        OperationMutationV1::RecordPreEntryRecheck {
                            profile_state: vec![1],
                        },
                        1_001,
                    )
                    .unwrap()
                    .revision(),
                OperationMutationV1::MarkProviderEntered,
                1_002,
            )
            .unwrap();
        let provider = journal
            .mutate_operation(
                "did:key:workload",
                &id,
                entered.revision(),
                OperationMutationV1::RecordProviderResult { bytes: vec![3] },
                1_003,
            )
            .unwrap();
        let observed = journal
            .mutate_operation(
                "did:key:workload",
                &id,
                provider.revision(),
                OperationMutationV1::RecordObservation { bytes: vec![4] },
                1_004,
            )
            .unwrap();
        let receipted = journal
            .mutate_operation(
                "did:key:workload",
                &id,
                observed.revision(),
                OperationMutationV1::RecordExecutionReceipt {
                    receipt: JournalReceiptV1::new("receipt-execution", vec![0xa1, 1, 1]).unwrap(),
                    outcome: JournalExecutionOutcomeV1::Succeeded,
                    result_commitment: Some(Sha256::digest([0xa0]).into()),
                },
                1_005,
            )
            .unwrap();
        let completed = journal
            .mutate_operation(
                "did:key:workload",
                &id,
                receipted.revision(),
                OperationMutationV1::Conclude {
                    state: OperationStateV1::Completed,
                    issue: None,
                    value: Some(vec![0xa0]),
                    completion: JournalCompletionV1::Fresh,
                    profile_state: vec![5],
                },
                1_006,
            )
            .unwrap();
        assert!(completed.projection().is_terminal());
        assert_eq!(completed.projection().effect(), OperationEffectV1::Applied);
    }

    #[test]
    fn post_entry_receipt_failure_is_durable_and_cannot_resume_transitions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("operations.db");
        let journal = PersistentOperationJournal::open(&path, [(profile(), limits())]).unwrap();
        let initial = record([11; 16], None);
        let id = initial.operation_id.clone();
        journal.prepare(initial, 1_000).unwrap();
        let sealed = journal
            .mutate_operation(
                "did:key:workload",
                &id,
                1,
                OperationMutationV1::SealPreEntry {
                    profile_state: vec![1],
                    sealed_command: vec![2],
                },
                1_001,
            )
            .unwrap();
        let executing = journal
            .mutate_operation(
                "did:key:workload",
                &id,
                sealed.revision(),
                OperationMutationV1::BeginExecution {
                    profile_state: vec![1],
                    sealed_command: vec![2],
                },
                1_001,
            )
            .unwrap();
        let entered = journal
            .mutate_operation(
                "did:key:workload",
                &id,
                journal
                    .mutate_operation(
                        "did:key:workload",
                        &id,
                        executing.revision(),
                        OperationMutationV1::RecordPreEntryRecheck {
                            profile_state: vec![1],
                        },
                        1_001,
                    )
                    .unwrap()
                    .revision(),
                OperationMutationV1::MarkProviderEntered,
                1_002,
            )
            .unwrap();
        let quarantined = journal
            .mutate_operation(
                "did:key:workload",
                &id,
                entered.revision(),
                OperationMutationV1::QuarantineReceiptIntegrity {
                    state: OperationStateV1::RecoveryRequired,
                    issue: Some(vec![0xa0]),
                    value: None,
                    progress: None,
                    completion: None,
                    profile_state: vec![3],
                },
                1_003,
            )
            .unwrap();
        assert!(quarantined.receipt_integrity_failed());
        assert!(quarantined.provider_entered());
        assert_eq!(quarantined.receipts().len(), 1);
        assert_eq!(
            quarantined.projection().state(),
            OperationStateV1::RecoveryRequired
        );
        assert_eq!(
            quarantined.projection().effect(),
            OperationEffectV1::Possible
        );
        assert!(
            journal
                .mutate_operation(
                    "did:key:workload",
                    &id,
                    quarantined.revision(),
                    OperationMutationV1::RecordObservation { bytes: vec![4] },
                    1_004,
                )
                .is_err()
        );
        drop(journal);
        let reopened = PersistentOperationJournal::open(&path, [(profile(), limits())]).unwrap();
        let Some(JournalStatusV1::Record(restored)) =
            reopened.status("did:key:workload", &id).unwrap()
        else {
            panic!("quarantined record was not restored");
        };
        assert!(restored.receipt_integrity_failed());
        assert!(restored.provider_entered());
    }

    #[test]
    fn receipt_quarantine_preserves_every_provider_truth_classification() {
        let cases = [
            (
                OperationStateV1::Completed,
                None,
                Some(vec![7]),
                None,
                Some(JournalCompletionV1::Fresh),
                OperationEffectV1::Applied,
                true,
            ),
            (
                OperationStateV1::Partial,
                Some(vec![8]),
                Some(vec![7]),
                None,
                Some(JournalCompletionV1::Reconciled),
                OperationEffectV1::Applied,
                true,
            ),
            (
                OperationStateV1::NotApplied,
                Some(vec![8]),
                None,
                None,
                Some(JournalCompletionV1::Fresh),
                OperationEffectV1::NotApplied,
                true,
            ),
            (
                OperationStateV1::RecoveryRequired,
                Some(vec![8]),
                None,
                Some(vec![9]),
                None,
                OperationEffectV1::Possible,
                false,
            ),
        ];
        for (index, (state, issue, value, progress, completion, effect, terminal)) in
            cases.into_iter().enumerate()
        {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("operations.db");
            let journal = PersistentOperationJournal::open(&path, [(profile(), limits())]).unwrap();
            let initial = record([index as u8 + 20; 16], None);
            let id = initial.operation_id.clone();
            journal.prepare(initial, 1_000).unwrap();
            let sealed = journal
                .mutate_operation(
                    "did:key:workload",
                    &id,
                    1,
                    OperationMutationV1::SealPreEntry {
                        profile_state: vec![1],
                        sealed_command: vec![2],
                    },
                    1_001,
                )
                .unwrap();
            let executing = journal
                .mutate_operation(
                    "did:key:workload",
                    &id,
                    sealed.revision(),
                    OperationMutationV1::BeginExecution {
                        profile_state: vec![1],
                        sealed_command: vec![2],
                    },
                    1_001,
                )
                .unwrap();
            let entered = journal
                .mutate_operation(
                    "did:key:workload",
                    &id,
                    journal
                        .mutate_operation(
                            "did:key:workload",
                            &id,
                            executing.revision(),
                            OperationMutationV1::RecordPreEntryRecheck {
                                profile_state: vec![1],
                            },
                            1_001,
                        )
                        .unwrap()
                        .revision(),
                    OperationMutationV1::MarkProviderEntered,
                    1_002,
                )
                .unwrap();
            let provider = journal
                .mutate_operation(
                    "did:key:workload",
                    &id,
                    entered.revision(),
                    OperationMutationV1::RecordProviderResult { bytes: vec![3] },
                    1_003,
                )
                .unwrap();
            let observed = journal
                .mutate_operation(
                    "did:key:workload",
                    &id,
                    provider.revision(),
                    OperationMutationV1::RecordObservation { bytes: vec![4] },
                    1_004,
                )
                .unwrap();
            let quarantined = journal
                .mutate_operation(
                    "did:key:workload",
                    &id,
                    observed.revision(),
                    OperationMutationV1::QuarantineReceiptIntegrity {
                        state,
                        issue: issue.clone(),
                        value: value.clone(),
                        progress: progress.clone(),
                        completion,
                        profile_state: vec![5],
                    },
                    1_005,
                )
                .unwrap();
            assert!(quarantined.receipt_integrity_failed());
            assert_eq!(quarantined.projection().state(), state);
            assert_eq!(quarantined.projection().effect(), effect);
            assert_eq!(quarantined.projection().is_terminal(), terminal);
            assert_eq!(quarantined.issue(), issue.as_deref());
            assert_eq!(quarantined.profile_value(), value.as_deref());
            assert_eq!(quarantined.profile_progress(), progress.as_deref());
            drop(journal);
            let reopened =
                PersistentOperationJournal::open(&path, [(profile(), limits())]).unwrap();
            let Some(JournalStatusV1::Record(restored)) =
                reopened.status("did:key:workload", &id).unwrap()
            else {
                panic!("quarantined record was not restored");
            };
            assert!(restored.receipt_integrity_failed());
            assert_eq!(restored.projection(), quarantined.projection());
            assert_eq!(restored.issue(), issue.as_deref());
            assert_eq!(restored.profile_value(), value.as_deref());
            assert_eq!(restored.profile_progress(), progress.as_deref());
        }
    }

    #[test]
    fn commitment_helper_is_not_content_idempotency() {
        let same_input = Sha256::digest(b"same business input");
        let first = record([1; 16], None);
        let second = record([2; 16], None);
        assert_eq!(same_input.as_slice(), same_input.as_slice());
        assert_ne!(
            first.binding.preparation_commitment(),
            second.binding.preparation_commitment()
        );
    }
}
