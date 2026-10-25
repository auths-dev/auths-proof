//! Task-scoped release accounting transitions. The installed release engine
//! must persist each returned state with an atomic compare-and-swap before it
//! performs the corresponding provider or agent-channel I/O. This model alone
//! neither verifies a grant nor sends content.

#[cfg(test)]
use crate::ClosedReleaseRequest;
use crate::release_verify::VerifiedReleaseRequest;
use crate::task_activation::TaskWriteScope;
use crate::task_activation::{AgentTaskDescriptor, ApprovedAgentTask, TaskActivationPins};
use crate::task_write::ApprovedTaskWrite;
use crate::{ReleaseCommitmentContext, ReleaseCommitmentError, ReleaseCommitmentKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Component, Path, PathBuf},
};
use subtle::ConstantTimeEq as _;
use tempfile::NamedTempFile;
use thiserror::Error;

const SCHEMA: &str = "auths.gateway-agent-task-state/3";
const MAX_RESOURCES: usize = 16;
const MAX_OPERATIONS: usize = 64;
const MAX_TASK_RELEASE_BYTES: u64 = 16 * 1_048_576;
const MAX_STATE_BYTES: usize = 262_144;
const KEY_DOMAIN: &[u8] = b"auths.gateway-release-task/1\0";
const LOCK_FILE: &str = ".release.lock";

/// One exact task-listed source, its approved recipe and connected credential
/// generation. The handle is opaque to this shared state machine.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseResourceScope {
    pub(crate) handle: String,
    pub(crate) recipe_digest: String,
    pub(crate) connection_id: String,
    pub(crate) connection_generation: u64,
}

/// Task facts whose signature and company policy must be checked by the
/// enclosing admission engine before constructing a state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReleaseTaskPolicy {
    pub(crate) task_id: String,
    pub(crate) task_commitment: [u8; 32],
    pub(crate) company_id: String,
    pub(crate) human_principal: String,
    pub(crate) agent_principal: String,
    pub(crate) not_before: u64,
    pub(crate) expires_at: u64,
    pub(crate) max_provider_calls: u32,
    pub(crate) max_releases: u32,
    pub(crate) max_release_bytes: u64,
    pub(crate) resources: Vec<ReleaseResourceScope>,
    pub(crate) max_writes: u32,
    pub(crate) write_scopes: Vec<TaskWriteScope>,
    pub(crate) connection_id: String,
    pub(crate) connection_generation: u64,
    pub(crate) connection_subject: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteOperation {
    resource_handle: String,
    recipe_digest: String,
    verb: crate::task_activation::TaskWriteVerb,
    connection_id: String,
    connection_generation: u64,
    connection_subject: String,
    action_commitment: String,
    request_commitment: String,
}

/// An exact native-verified agent action, projected by the future admission
/// engine. The receipt never accepts a runtime URL or response selector.
#[derive(Clone, Copy)]
struct ReleaseCall<'a> {
    task_id: &'a str,
    operation_id: &'a str,
    resource_handle: &'a str,
    recipe_digest: &'a str,
    connection_id: &'a str,
    connection_generation: u64,
    recipient: &'a str,
    action_commitment: [u8; 32],
}

/// Stages are claims about this gateway's order of work, not about provider
/// permission, content truth or the agent's comprehension.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ReleaseStage {
    /// One provider call was charged before transport entry.
    ProviderCallReserved,
    /// No complete projectable provider result was available.
    ProviderUnavailable,
    /// Bytes and one release were durably charged before channel entry. On
    /// restart, this is delivery-unknown without verified terminal evidence.
    ReleaseEntered,
    /// The channel supplied durable proof that no byte was sent after the
    /// charge. The conservative charge is never refunded.
    NotDelivered,
    /// An authenticated acknowledgement of the exact delivery was verified
    /// by the channel before this transition was persisted.
    AgentAcknowledged,
}

/// Minted only by a future agent-channel verifier after it authenticates the
/// recipient and checks the acknowledgement against the exact delivered bytes.
/// No production constructor exists until that verifier is installed.
pub(crate) struct VerifiedAgentAcknowledgement {
    task_id: String,
    operation_id: String,
    recipient: String,
    released_bytes: u64,
    commitment_key_version: u32,
    content_commitment: String,
}

/// Minted only by a future channel executor with durable evidence that the
/// transport did not begin. A missing acknowledgement is not this evidence.
pub(crate) struct ProvenNoSend {
    task_id: String,
    operation_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseOperation {
    resource_handle: String,
    recipe_digest: String,
    connection_id: String,
    connection_generation: u64,
    recipient: String,
    action_commitment: String,
    stage: ReleaseStage,
    released_bytes: Option<u64>,
    commitment_key_version: Option<u32>,
    content_commitment: Option<String>,
}

/// One task's release accounting. A single CAS record keeps replay claims,
/// call count, release count and byte sum atomic even under competing agents.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseTaskState {
    schema: String,
    task_id: String,
    task_commitment: String,
    company_id: String,
    human_principal: String,
    agent_principal: String,
    not_before: u64,
    expires_at: u64,
    max_provider_calls: u32,
    max_releases: u32,
    max_release_bytes: u64,
    resources: Vec<ReleaseResourceScope>,
    max_writes: u32,
    write_scopes: Vec<TaskWriteScope>,
    connection_id: String,
    connection_generation: u64,
    connection_subject: String,
    /// Production activation writes the verified card. Policy-only synthetic
    /// states use null and cannot authorize a task submission.
    activated_card: Option<AgentTaskDescriptor>,
    revoked: bool,
    provider_calls: u32,
    releases: u32,
    released_bytes: u64,
    operations: BTreeMap<String, ReleaseOperation>,
    writes: BTreeMap<String, WriteOperation>,
}

/// A refusal before any content delivery. No variant authorizes a retry of
/// an operation whose provider call has already been reserved.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum ReleaseStateError {
    #[error("release task or action binding is invalid")]
    Binding,
    #[error("release task is expired or revoked")]
    Inactive,
    #[error("release operation has already been claimed")]
    Replay,
    #[error("release task budget is exhausted")]
    Exhausted,
    #[error("release operation is in the wrong stage")]
    Stage,
    #[error("release content commitment is unavailable")]
    Commitment,
    #[error("release state already exists")]
    Exists,
    #[error("release state is missing or corrupt")]
    Corrupt,
    #[error("release state store is unavailable")]
    Unavailable,
}

impl ReleaseStateError {
    pub(crate) const fn write_code(self) -> &'static str {
        match self {
            Self::Binding | Self::Stage | Self::Commitment => "gateway.task.write-binding",
            Self::Inactive => "gateway.task.inactive",
            Self::Replay => "gateway.task.write-replay",
            Self::Exhausted => "gateway.task.write-budget",
            Self::Exists | Self::Corrupt | Self::Unavailable => "gateway.task.store-unavailable",
        }
    }
}

fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn same_commitment(expected: &str, presented: &str) -> bool {
    if !valid_digest(expected) || !valid_digest(presented) {
        return false;
    }
    let (Ok(expected), Ok(presented)) = (hex::decode(expected), hex::decode(presented)) else {
        return false;
    };
    bool::from(expected.ct_eq(&presented))
}

impl ReleaseTaskState {
    fn new(policy: ReleaseTaskPolicy) -> Result<Self, ReleaseStateError> {
        if !bounded_text(&policy.task_id, 128)
            || !bounded_text(&policy.company_id, 128)
            || !bounded_text(&policy.human_principal, 256)
            || !bounded_text(&policy.agent_principal, 256)
            || !bounded_text(&policy.connection_id, 128)
            || policy.connection_generation == 0
            || !bounded_text(&policy.connection_subject, 256)
            || policy.task_commitment == [0; 32]
            || policy.not_before >= policy.expires_at
            || policy.max_provider_calls as usize > MAX_OPERATIONS
            || policy.max_releases > policy.max_provider_calls
            || policy.max_release_bytes > MAX_TASK_RELEASE_BYTES
            || policy.resources.len() > MAX_RESOURCES
            || (policy.resources.is_empty()
                != (policy.max_provider_calls == 0
                    && policy.max_releases == 0
                    && policy.max_release_bytes == 0))
            || (!policy.resources.is_empty()
                && (policy.max_releases == 0 || policy.max_release_bytes == 0))
            || policy.max_writes > 32
            || policy.write_scopes.len() > MAX_RESOURCES
            || (policy.write_scopes.is_empty() != (policy.max_writes == 0))
            || (policy.resources.is_empty() && policy.write_scopes.is_empty())
        {
            return Err(ReleaseStateError::Binding);
        }
        let mut distinct = BTreeSet::new();
        for resource in &policy.resources {
            if !bounded_text(&resource.handle, 256)
                || !valid_digest(&resource.recipe_digest)
                || resource.connection_id != policy.connection_id
                || resource.connection_generation != policy.connection_generation
                || !distinct.insert(&resource.handle)
            {
                return Err(ReleaseStateError::Binding);
            }
        }
        let mut distinct_writes = BTreeSet::new();
        for scope in &policy.write_scopes {
            if !bounded_text(&scope.handle, 256)
                || !valid_digest(&scope.recipe_digest)
                || !distinct_writes.insert((&scope.handle, &scope.verb))
            {
                return Err(ReleaseStateError::Binding);
            }
        }
        Ok(Self {
            schema: SCHEMA.to_owned(),
            task_id: policy.task_id,
            task_commitment: hex::encode(policy.task_commitment),
            company_id: policy.company_id,
            human_principal: policy.human_principal,
            agent_principal: policy.agent_principal,
            not_before: policy.not_before,
            expires_at: policy.expires_at,
            max_provider_calls: policy.max_provider_calls,
            max_releases: policy.max_releases,
            max_release_bytes: policy.max_release_bytes,
            resources: policy.resources,
            max_writes: policy.max_writes,
            write_scopes: policy.write_scopes,
            connection_id: policy.connection_id,
            connection_generation: policy.connection_generation,
            connection_subject: policy.connection_subject,
            activated_card: None,
            revoked: false,
            provider_calls: 0,
            releases: 0,
            released_bytes: 0,
            operations: BTreeMap::new(),
            writes: BTreeMap::new(),
        })
    }

    #[cfg(test)]
    pub(crate) fn from_test_policy(policy: ReleaseTaskPolicy) -> Result<Self, ReleaseStateError> {
        Self::new(policy)
    }

    fn active(&self, now: u64) -> Result<(), ReleaseStateError> {
        if self.revoked || now < self.not_before || now >= self.expires_at {
            Err(ReleaseStateError::Inactive)
        } else {
            Ok(())
        }
    }

    fn policy(&self) -> Result<ReleaseTaskPolicy, ReleaseStateError> {
        let raw = hex::decode(&self.task_commitment).map_err(|_| ReleaseStateError::Corrupt)?;
        let task_commitment: [u8; 32] = raw.try_into().map_err(|_| ReleaseStateError::Corrupt)?;
        Ok(ReleaseTaskPolicy {
            task_id: self.task_id.clone(),
            task_commitment,
            company_id: self.company_id.clone(),
            human_principal: self.human_principal.clone(),
            agent_principal: self.agent_principal.clone(),
            not_before: self.not_before,
            expires_at: self.expires_at,
            max_provider_calls: self.max_provider_calls,
            max_releases: self.max_releases,
            max_release_bytes: self.max_release_bytes,
            resources: self.resources.clone(),
            max_writes: self.max_writes,
            write_scopes: self.write_scopes.clone(),
            connection_id: self.connection_id.clone(),
            connection_generation: self.connection_generation,
            connection_subject: self.connection_subject.clone(),
        })
    }

    pub(crate) fn activated_task(
        &self,
        pins: &TaskActivationPins,
        now: u64,
    ) -> Result<ApprovedAgentTask, ReleaseStateError> {
        self.active(now)?;
        let card = self
            .activated_card
            .clone()
            .ok_or(ReleaseStateError::Corrupt)?;
        let policy = self.policy()?;
        let approved =
            ApprovedAgentTask::from_activated_card(card, policy.task_commitment, pins, now)
                .map_err(|_| ReleaseStateError::Binding)?;
        if approved.task_policy() != policy {
            return Err(ReleaseStateError::Corrupt);
        }
        Ok(approved)
    }

    /// Spend one provider call and consume the logical operation ID before
    /// request entry. Persist the returned state before leasing or sending.
    fn reserve_provider_call(
        &mut self,
        call: ReleaseCall<'_>,
        now: u64,
    ) -> Result<(), ReleaseStateError> {
        self.active(now)?;
        if call.task_id != self.task_id
            || call.recipient != self.agent_principal
            || !bounded_text(call.operation_id, 128)
            || call.action_commitment == [0; 32]
            || !self.resources.iter().any(|resource| {
                resource.handle == call.resource_handle
                    && resource.recipe_digest == call.recipe_digest
                    && resource.connection_id == call.connection_id
                    && resource.connection_generation == call.connection_generation
            })
        {
            return Err(ReleaseStateError::Binding);
        }
        if self.operations.contains_key(call.operation_id)
            || self.writes.contains_key(call.operation_id)
        {
            return Err(ReleaseStateError::Replay);
        }
        if self.provider_calls >= self.max_provider_calls || self.operations.len() >= MAX_OPERATIONS
        {
            return Err(ReleaseStateError::Exhausted);
        }
        self.provider_calls += 1;
        self.operations.insert(
            call.operation_id.to_owned(),
            ReleaseOperation {
                resource_handle: call.resource_handle.to_owned(),
                recipe_digest: call.recipe_digest.to_owned(),
                connection_id: call.connection_id.to_owned(),
                connection_generation: call.connection_generation,
                recipient: call.recipient.to_owned(),
                action_commitment: hex::encode(call.action_commitment),
                stage: ReleaseStage::ProviderCallReserved,
                released_bytes: None,
                commitment_key_version: None,
                content_commitment: None,
            },
        );
        Ok(())
    }

    /// Durably charge a task write before gateway claim or credential lease.
    /// An unknown transport result never refunds this count or reopens its ID.
    fn reserve_write(
        &mut self,
        approved: &ApprovedTaskWrite,
        now: u64,
    ) -> Result<(), ReleaseStateError> {
        self.active(now)?;
        let intent = approved.intent();
        if intent.task_id != self.task_id
            || !same_commitment(&self.task_commitment, &intent.task_commitment)
            || !bounded_text(&intent.operation_id, 128)
            || !valid_digest(&intent.action_commitment)
            || intent.action_commitment == "0".repeat(64)
            || !valid_digest(&intent.request_commitment)
            || intent.request_commitment == "0".repeat(64)
            || !valid_digest(&intent.recipe_digest)
            || intent.connection_id != self.connection_id
            || intent.connection_generation != self.connection_generation
            || intent.connection_subject != self.connection_subject
            || !self.write_scopes.iter().any(|scope| {
                scope.handle == intent.resource_handle
                    && scope.recipe_digest == intent.recipe_digest
                    && scope.verb == intent.verb
            })
        {
            return Err(ReleaseStateError::Binding);
        }
        if self.operations.contains_key(&intent.operation_id)
            || self.writes.contains_key(&intent.operation_id)
        {
            return Err(ReleaseStateError::Replay);
        }
        if self.writes.len() >= self.max_writes as usize {
            return Err(ReleaseStateError::Exhausted);
        }
        self.writes.insert(
            intent.operation_id.clone(),
            WriteOperation {
                resource_handle: intent.resource_handle.clone(),
                recipe_digest: intent.recipe_digest.clone(),
                verb: intent.verb.clone(),
                connection_id: intent.connection_id.clone(),
                connection_generation: intent.connection_generation,
                connection_subject: intent.connection_subject.clone(),
                action_commitment: intent.action_commitment.clone(),
                request_commitment: intent.request_commitment.clone(),
            },
        );
        Ok(())
    }

    /// Admit a compiled request only with a native-verified sole actor and
    /// exact human-issued grant. The connection ID and generation must come
    /// from the loaded, subject-bound credential record.
    pub(crate) fn reserve_verified_request(
        &mut self,
        verified: &VerifiedReleaseRequest,
        connection_id: &str,
        connection_generation: u64,
        now: u64,
    ) -> Result<(), ReleaseStateError> {
        let request = verified.request();
        if verified.actor().as_str() != request.recipient()
            || verified.human_issuer().as_str() != self.human_principal
            || !same_commitment(
                &self.task_commitment,
                &hex::encode(request.task_commitment()),
            )
        {
            return Err(ReleaseStateError::Binding);
        }
        self.reserve_provider_call(
            ReleaseCall {
                task_id: request.task_id(),
                operation_id: request.operation_id().as_str(),
                resource_handle: request.resource_handle(),
                recipe_digest: &hex::encode(request.recipe_digest()),
                connection_id,
                connection_generation,
                recipient: request.recipient(),
                action_commitment: *request.action_commitment(),
            },
            now,
        )
    }

    /// Test-only construction check for a closed request. Production callers
    /// must use `reserve_verified_request` so actor and issuer are sealed.
    #[cfg(test)]
    pub(crate) fn reserve_closed_request(
        &mut self,
        request: &ClosedReleaseRequest,
        verified_actors: &[String],
        connection_id: &str,
        connection_generation: u64,
        now: u64,
    ) -> Result<(), ReleaseStateError> {
        if verified_actors.len() != 1 || verified_actors[0] != request.recipient() {
            return Err(ReleaseStateError::Binding);
        }
        if !same_commitment(
            &self.task_commitment,
            &hex::encode(request.task_commitment()),
        ) {
            return Err(ReleaseStateError::Binding);
        }
        self.reserve_provider_call(
            ReleaseCall {
                task_id: request.task_id(),
                operation_id: request.operation_id().as_str(),
                resource_handle: request.resource_handle(),
                recipe_digest: &hex::encode(request.recipe_digest()),
                connection_id,
                connection_generation,
                recipient: request.recipient(),
                action_commitment: *request.action_commitment(),
            },
            now,
        )
    }

    /// A failed/incomplete provider response consumes the call but no content
    /// release or released-byte allowance.
    pub(crate) fn provider_unavailable(
        &mut self,
        operation_id: &str,
    ) -> Result<(), ReleaseStateError> {
        let operation = self
            .operations
            .get_mut(operation_id)
            .ok_or(ReleaseStateError::Binding)?;
        if operation.stage != ReleaseStage::ProviderCallReserved {
            return Err(ReleaseStateError::Stage);
        }
        operation.stage = ReleaseStage::ProviderUnavailable;
        Ok(())
    }

    /// Commit exact projected bytes and charge one release before the first
    /// agent-channel byte. The key remains in custody; only its version and
    /// context-separated MAC enter this state. Persist the state before send.
    pub(crate) fn enter_release(
        &mut self,
        operation_id: &str,
        content: &[u8],
        key: &ReleaseCommitmentKey,
        now: u64,
    ) -> Result<(), ReleaseStateError> {
        self.active(now)?;
        let operation = self
            .operations
            .get(operation_id)
            .ok_or(ReleaseStateError::Binding)?;
        if operation.stage != ReleaseStage::ProviderCallReserved {
            return Err(ReleaseStateError::Stage);
        }
        let bytes = u64::try_from(content.len()).map_err(|_| ReleaseStateError::Exhausted)?;
        if content.is_empty()
            || self.releases >= self.max_releases
            || self
                .released_bytes
                .checked_add(bytes)
                .is_none_or(|total| total > self.max_release_bytes)
        {
            return Err(ReleaseStateError::Exhausted);
        }
        let receipt_scope = ReleaseCommitmentContext::new(
            &self.task_id,
            &operation.resource_handle,
            operation_id,
            "released",
        )
        .map_err(|_: ReleaseCommitmentError| ReleaseStateError::Commitment)?;
        let commitment = key.commit(&receipt_scope, content);
        let operation = self
            .operations
            .get_mut(operation_id)
            .ok_or(ReleaseStateError::Binding)?;
        operation.stage = ReleaseStage::ReleaseEntered;
        operation.released_bytes = Some(bytes);
        operation.commitment_key_version = Some(commitment.key_version());
        operation.content_commitment = Some(commitment.hex());
        self.releases += 1;
        self.released_bytes += bytes;
        Ok(())
    }

    /// Finalize a charged release only after the channel has authenticated an
    /// acknowledgement bound to the operation, recipient and exact content.
    /// A lost acknowledgement deliberately leaves `ReleaseEntered` unknown.
    pub(crate) fn acknowledge(
        &mut self,
        evidence: &VerifiedAgentAcknowledgement,
    ) -> Result<(), ReleaseStateError> {
        if evidence.task_id != self.task_id {
            return Err(ReleaseStateError::Binding);
        }
        let operation = self
            .operations
            .get_mut(&evidence.operation_id)
            .ok_or(ReleaseStateError::Binding)?;
        if operation.stage != ReleaseStage::ReleaseEntered {
            return Err(ReleaseStateError::Stage);
        }
        if operation.recipient != evidence.recipient
            || operation.released_bytes != Some(evidence.released_bytes)
            || operation.commitment_key_version != Some(evidence.commitment_key_version)
            || !operation
                .content_commitment
                .as_deref()
                .is_some_and(|commitment| same_commitment(commitment, &evidence.content_commitment))
        {
            return Err(ReleaseStateError::Binding);
        }
        operation.stage = ReleaseStage::AgentAcknowledged;
        Ok(())
    }

    /// Finalize a charged release only with durable proof that channel send
    /// never began. A crash or timeout is insufficient and remains unknown.
    pub(crate) fn not_delivered(
        &mut self,
        evidence: &ProvenNoSend,
    ) -> Result<(), ReleaseStateError> {
        if evidence.task_id != self.task_id {
            return Err(ReleaseStateError::Binding);
        }
        let operation = self
            .operations
            .get_mut(&evidence.operation_id)
            .ok_or(ReleaseStateError::Binding)?;
        if operation.stage != ReleaseStage::ReleaseEntered {
            return Err(ReleaseStateError::Stage);
        }
        operation.stage = ReleaseStage::NotDelivered;
        Ok(())
    }

    /// Revocation excludes later call reservations and release commitments;
    /// it cannot undo a prior entered release.
    pub(crate) fn revoke(&mut self) {
        self.revoked = true;
    }

    pub(crate) fn stage(&self, operation_id: &str) -> Option<ReleaseStage> {
        self.operations
            .get(operation_id)
            .map(|operation| operation.stage)
    }

    pub(crate) const fn counts(&self) -> (u32, u32, u64) {
        (self.provider_calls, self.releases, self.released_bytes)
    }

    pub(crate) fn write_count(&self) -> usize {
        self.writes.len()
    }

    /// A replay can inspect this state but may never send content again.
    pub(crate) fn delivery_unknown(&self, operation_id: &str) -> bool {
        self.stage(operation_id) == Some(ReleaseStage::ReleaseEntered)
    }

    pub(crate) fn commitment(&self, operation_id: &str) -> Option<(u32, &str)> {
        let operation = self.operations.get(operation_id)?;
        Some((
            operation.commitment_key_version?,
            operation.content_commitment.as_deref()?,
        ))
    }

    /// Digest of canonical task state for an operator's private CAS journal.
    pub(crate) fn digest(&self) -> Result<[u8; 32], ReleaseStateError> {
        let bytes =
            serde_json_canonicalizer::to_vec(self).map_err(|_| ReleaseStateError::Binding)?;
        Ok(Sha256::digest(bytes).into())
    }

    fn encode(&self) -> Result<Vec<u8>, ReleaseStateError> {
        let bytes =
            serde_json_canonicalizer::to_vec(self).map_err(|_| ReleaseStateError::Corrupt)?;
        if bytes.is_empty() || bytes.len() > MAX_STATE_BYTES {
            return Err(ReleaseStateError::Corrupt);
        }
        Ok(bytes)
    }

    fn validate_writes(&self) -> Result<(), ReleaseStateError> {
        if self.writes.len() > self.max_writes as usize {
            return Err(ReleaseStateError::Corrupt);
        }
        for (operation_id, write) in &self.writes {
            if !bounded_text(operation_id, 128)
                || self.operations.contains_key(operation_id)
                || !valid_digest(&write.action_commitment)
                || write.action_commitment == "0".repeat(64)
                || !valid_digest(&write.request_commitment)
                || write.request_commitment == "0".repeat(64)
                || write.connection_id != self.connection_id
                || write.connection_generation != self.connection_generation
                || write.connection_subject != self.connection_subject
                || !self.write_scopes.iter().any(|scope| {
                    scope.handle == write.resource_handle
                        && scope.recipe_digest == write.recipe_digest
                        && scope.verb == write.verb
                })
            {
                return Err(ReleaseStateError::Corrupt);
            }
        }
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self, ReleaseStateError> {
        if bytes.is_empty() || bytes.len() > MAX_STATE_BYTES {
            return Err(ReleaseStateError::Corrupt);
        }
        let state: Self = serde_json::from_slice(bytes).map_err(|_| ReleaseStateError::Corrupt)?;
        if state.schema != SCHEMA || state.encode()?.as_slice() != bytes {
            return Err(ReleaseStateError::Corrupt);
        }
        Self::new(state.policy()?).map_err(|_| ReleaseStateError::Corrupt)?;
        let mut releases = 0_u32;
        let mut released_bytes = 0_u64;
        state.validate_writes()?;
        for (operation_id, operation) in &state.operations {
            if !bounded_text(operation_id, 128)
                || operation.recipient != state.agent_principal
                || !valid_digest(&operation.action_commitment)
                || operation.action_commitment == "0".repeat(64)
                || !state.resources.iter().any(|resource| {
                    resource.handle == operation.resource_handle
                        && resource.recipe_digest == operation.recipe_digest
                        && resource.connection_id == operation.connection_id
                        && resource.connection_generation == operation.connection_generation
                })
            {
                return Err(ReleaseStateError::Corrupt);
            }
            let charged = matches!(
                operation.stage,
                ReleaseStage::ReleaseEntered
                    | ReleaseStage::NotDelivered
                    | ReleaseStage::AgentAcknowledged
            );
            if charged {
                let bytes = operation.released_bytes.ok_or(ReleaseStateError::Corrupt)?;
                if bytes == 0
                    || operation
                        .commitment_key_version
                        .is_none_or(|version| version == 0)
                    || !operation
                        .content_commitment
                        .as_deref()
                        .is_some_and(valid_digest)
                {
                    return Err(ReleaseStateError::Corrupt);
                }
                releases = releases.checked_add(1).ok_or(ReleaseStateError::Corrupt)?;
                released_bytes = released_bytes
                    .checked_add(bytes)
                    .ok_or(ReleaseStateError::Corrupt)?;
            } else if operation.released_bytes.is_some()
                || operation.commitment_key_version.is_some()
                || operation.content_commitment.is_some()
            {
                return Err(ReleaseStateError::Corrupt);
            }
        }
        if state.provider_calls as usize != state.operations.len()
            || state.provider_calls > state.max_provider_calls
            || releases != state.releases
            || state.releases > state.max_releases
            || released_bytes != state.released_bytes
            || state.released_bytes > state.max_release_bytes
        {
            return Err(ReleaseStateError::Corrupt);
        }
        Ok(state)
    }
}

/// One-host durable task journal for early release-engine integration. It
/// does not supply protected multi-host custody or installed qualification.
pub(crate) struct FileReleaseTaskLedger {
    root: PathBuf,
}

impl FileReleaseTaskLedger {
    pub(crate) fn open(root: impl Into<PathBuf>) -> Result<Self, ReleaseStateError> {
        let root = root.into();
        if !root.is_absolute()
            || root
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        {
            return Err(ReleaseStateError::Unavailable);
        }
        if !root.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&root)
                    .map_err(|_| ReleaseStateError::Unavailable)?;
            }
            #[cfg(not(unix))]
            return Err(ReleaseStateError::Unavailable);
        }
        crate::check_private_directory(&root).map_err(|_| ReleaseStateError::Unavailable)?;
        Ok(Self { root })
    }

    fn key_path(&self, task_id: &str) -> Result<PathBuf, ReleaseStateError> {
        if !bounded_text(task_id, 128) {
            return Err(ReleaseStateError::Binding);
        }
        let mut hash = Sha256::new();
        hash.update(KEY_DOMAIN);
        hash.update(task_id.as_bytes());
        Ok(self
            .root
            .join(format!("release-{}.json", hex::encode(hash.finalize()))))
    }

    fn lock(&self, operation: rustix::fs::FlockOperation) -> Result<File, ReleaseStateError> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let lock = options
            .open(self.root.join(LOCK_FILE))
            .map_err(|_| ReleaseStateError::Unavailable)?;
        rustix::fs::flock(&lock, operation).map_err(|_| ReleaseStateError::Unavailable)?;
        Ok(lock)
    }

    fn read(path: &Path) -> Result<Option<ReleaseTaskState>, ReleaseStateError> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ReleaseStateError::Unavailable),
        };
        if !metadata.is_file() || metadata.len() > MAX_STATE_BYTES as u64 {
            return Err(ReleaseStateError::Corrupt);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(ReleaseStateError::Corrupt);
            }
        }
        let file = File::open(path).map_err(|_| ReleaseStateError::Unavailable)?;
        let mut bytes = Vec::new();
        file.take((MAX_STATE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ReleaseStateError::Unavailable)?;
        ReleaseTaskState::decode(&bytes).map(Some)
    }

    fn write(
        &self,
        path: &Path,
        state: &ReleaseTaskState,
        create: bool,
    ) -> Result<(), ReleaseStateError> {
        let bytes = state.encode()?;
        let mut pending =
            NamedTempFile::new_in(&self.root).map_err(|_| ReleaseStateError::Unavailable)?;
        pending
            .write_all(&bytes)
            .and_then(|()| pending.as_file().sync_all())
            .map_err(|_| ReleaseStateError::Unavailable)?;
        if create {
            pending.persist_noclobber(path).map_err(|error| {
                if error.error.kind() == std::io::ErrorKind::AlreadyExists {
                    ReleaseStateError::Exists
                } else {
                    ReleaseStateError::Unavailable
                }
            })?;
        } else {
            pending
                .persist(path)
                .map_err(|_| ReleaseStateError::Unavailable)?;
        }
        File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ReleaseStateError::Unavailable)
    }

    pub(crate) fn initialize(
        &self,
        approved: &ApprovedAgentTask,
    ) -> Result<ReleaseTaskState, ReleaseStateError> {
        let mut state = ReleaseTaskState::new(approved.task_policy())?;
        state.activated_card = Some(approved.descriptor().clone());
        self.initialize_state(state)
    }

    #[cfg(test)]
    fn initialize_policy(
        &self,
        policy: ReleaseTaskPolicy,
    ) -> Result<ReleaseTaskState, ReleaseStateError> {
        let state = ReleaseTaskState::new(policy)?;
        self.initialize_state(state)
    }

    fn initialize_state(
        &self,
        state: ReleaseTaskState,
    ) -> Result<ReleaseTaskState, ReleaseStateError> {
        let path = self.key_path(&state.task_id)?;
        let _lock = self.lock(rustix::fs::FlockOperation::LockExclusive)?;
        self.write(&path, &state, true)?;
        Ok(state)
    }

    pub(crate) fn load(
        &self,
        task_id: &str,
    ) -> Result<Option<ReleaseTaskState>, ReleaseStateError> {
        let path = self.key_path(task_id)?;
        let _lock = self.lock(rustix::fs::FlockOperation::LockShared)?;
        let state = Self::read(&path)?;
        if state.as_ref().is_some_and(|state| state.task_id != task_id) {
            return Err(ReleaseStateError::Corrupt);
        }
        Ok(state)
    }

    fn update(
        &self,
        task_id: &str,
        change: impl FnOnce(&mut ReleaseTaskState) -> Result<(), ReleaseStateError>,
    ) -> Result<ReleaseTaskState, ReleaseStateError> {
        let path = self.key_path(task_id)?;
        let _lock = self.lock(rustix::fs::FlockOperation::LockExclusive)?;
        let mut state = Self::read(&path)?.ok_or(ReleaseStateError::Corrupt)?;
        if state.task_id != task_id {
            return Err(ReleaseStateError::Corrupt);
        }
        change(&mut state)?;
        self.write(&path, &state, false)?;
        Ok(state)
    }

    #[cfg(test)]
    fn reserve_provider_call(
        &self,
        call: ReleaseCall<'_>,
        now: u64,
    ) -> Result<ReleaseTaskState, ReleaseStateError> {
        self.update(call.task_id, |state| state.reserve_provider_call(call, now))
    }

    pub(crate) fn reserve_verified_request(
        &self,
        verified: &VerifiedReleaseRequest,
        connection_id: &str,
        connection_generation: u64,
        now: u64,
    ) -> Result<ReleaseTaskState, ReleaseStateError> {
        self.update(verified.request().task_id(), |state| {
            state.reserve_verified_request(verified, connection_id, connection_generation, now)
        })
    }

    pub(crate) fn reserve_write(
        &self,
        approved: &ApprovedTaskWrite,
        now: u64,
    ) -> Result<ReleaseTaskState, ReleaseStateError> {
        self.update(&approved.intent().task_id, |state| {
            state.reserve_write(approved, now)
        })
    }

    #[cfg(test)]
    pub(crate) fn reserve_closed_request(
        &self,
        request: &ClosedReleaseRequest,
        verified_actors: &[String],
        connection_id: &str,
        connection_generation: u64,
        now: u64,
    ) -> Result<ReleaseTaskState, ReleaseStateError> {
        self.update(request.task_id(), |state| {
            state.reserve_closed_request(
                request,
                verified_actors,
                connection_id,
                connection_generation,
                now,
            )
        })
    }

    pub(crate) fn provider_unavailable(
        &self,
        task_id: &str,
        operation_id: &str,
    ) -> Result<ReleaseTaskState, ReleaseStateError> {
        self.update(task_id, |state| state.provider_unavailable(operation_id))
    }

    pub(crate) fn enter_release(
        &self,
        task_id: &str,
        operation_id: &str,
        content: &[u8],
        key: &ReleaseCommitmentKey,
        now: u64,
    ) -> Result<ReleaseTaskState, ReleaseStateError> {
        self.update(task_id, |state| {
            state.enter_release(operation_id, content, key, now)
        })
    }

    pub(crate) fn acknowledge(
        &self,
        evidence: &VerifiedAgentAcknowledgement,
    ) -> Result<ReleaseTaskState, ReleaseStateError> {
        self.update(&evidence.task_id, |state| state.acknowledge(evidence))
    }

    pub(crate) fn not_delivered(
        &self,
        evidence: &ProvenNoSend,
    ) -> Result<ReleaseTaskState, ReleaseStateError> {
        self.update(&evidence.task_id, |state| state.not_delivered(evidence))
    }

    pub(crate) fn revoke(&self, task_id: &str) -> Result<ReleaseTaskState, ReleaseStateError> {
        self.update(task_id, |state| {
            state.revoke();
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task_activation::TaskWriteVerb;
    use crate::task_write::ExactWriteIntent;
    use std::sync::{Arc, Barrier};
    use zeroize::Zeroizing;

    fn policy() -> ReleaseTaskPolicy {
        ReleaseTaskPolicy {
            task_id: "task-1".to_owned(),
            task_commitment: [0x11; 32],
            company_id: "atlas".to_owned(),
            human_principal: "jules-principal".to_owned(),
            agent_principal: "agent-principal".to_owned(),
            not_before: 100,
            expires_at: 200,
            max_provider_calls: 2,
            max_releases: 1,
            max_release_bytes: 8,
            max_writes: 0,
            write_scopes: vec![],
            connection_id: "jules-google".to_owned(),
            connection_generation: 3,
            connection_subject: "jules-subject".to_owned(),
            resources: vec![ReleaseResourceScope {
                handle: "source-1".to_owned(),
                recipe_digest: "a".repeat(64),
                connection_id: "jules-google".to_owned(),
                connection_generation: 3,
            }],
        }
    }

    #[test]
    fn obsolete_or_cardless_journal_shape_is_refused() {
        let state = ReleaseTaskState::new(policy()).expect("state");
        let mut value: serde_json::Value =
            serde_json::from_slice(&state.encode().expect("canonical state")).expect("state JSON");
        value["schema"] = serde_json::json!("auths.gateway-agent-task-state/2");
        let obsolete = serde_json_canonicalizer::to_vec(&value).expect("canonical obsolete");
        assert!(matches!(
            ReleaseTaskState::decode(&obsolete),
            Err(ReleaseStateError::Corrupt)
        ));
        value["schema"] = serde_json::json!(SCHEMA);
        value
            .as_object_mut()
            .expect("object")
            .remove("activated_card");
        let missing = serde_json_canonicalizer::to_vec(&value).expect("canonical missing");
        assert!(matches!(
            ReleaseTaskState::decode(&missing),
            Err(ReleaseStateError::Corrupt)
        ));
    }

    fn call(operation_id: &str) -> ReleaseCall<'_> {
        ReleaseCall {
            task_id: "task-1",
            operation_id,
            resource_handle: "source-1",
            recipe_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            connection_id: "jules-google",
            connection_generation: 3,
            recipient: "agent-principal",
            action_commitment: [0x22; 32],
        }
    }

    fn write_policy() -> ReleaseTaskPolicy {
        let mut task = policy();
        task.resources.clear();
        task.max_provider_calls = 0;
        task.max_releases = 0;
        task.max_release_bytes = 0;
        task.max_writes = 1;
        task.write_scopes = vec![TaskWriteScope {
            handle: "working-doc".to_owned(),
            recipe_digest: "b".repeat(64),
            verb: TaskWriteVerb::Edit,
        }];
        task
    }

    fn write_intent(operation_id: &str) -> ApprovedTaskWrite {
        ApprovedTaskWrite::from_test_intent(ExactWriteIntent {
            task_id: "task-1".to_owned(),
            task_commitment: "11".repeat(32),
            operation_id: operation_id.to_owned(),
            action_commitment: "c".repeat(64),
            request_commitment: "d".repeat(64),
            recipe_digest: "b".repeat(64),
            resource_handle: "working-doc".to_owned(),
            verb: TaskWriteVerb::Edit,
            connection_id: "jules-google".to_owned(),
            connection_generation: 3,
            connection_subject: "jules-subject".to_owned(),
        })
    }

    fn acknowledgement(
        state: &ReleaseTaskState,
        operation_id: &str,
    ) -> VerifiedAgentAcknowledgement {
        let (version, commitment) = state.commitment(operation_id).expect("commitment");
        VerifiedAgentAcknowledgement {
            task_id: "task-1".to_owned(),
            operation_id: operation_id.to_owned(),
            recipient: "agent-principal".to_owned(),
            released_bytes: 8,
            commitment_key_version: version,
            content_commitment: commitment.to_owned(),
        }
    }

    #[test]
    fn lost_ack_consumes_budget_and_cannot_redeliver() {
        let key = ReleaseCommitmentKey::new(2, Zeroizing::new([0x93; 32])).expect("key");
        let mut state = ReleaseTaskState::new(policy()).expect("policy");
        state
            .reserve_provider_call(call("read-1"), 101)
            .expect("claim");
        state
            .enter_release("read-1", b"Approved", &key, 102)
            .expect("release");
        assert_eq!(state.counts(), (1, 1, 8));
        assert_eq!(state.stage("read-1"), Some(ReleaseStage::ReleaseEntered));
        assert!(state.delivery_unknown("read-1"));
        assert_eq!(
            state.reserve_provider_call(call("read-1"), 103),
            Err(ReleaseStateError::Replay)
        );
        assert_eq!(
            state.enter_release("read-1", b"Approved", &key, 103),
            Err(ReleaseStateError::Stage)
        );
        let (version, mac) = state.commitment("read-1").expect("keyed receipt");
        assert_eq!(version, 2);
        assert_ne!(mac, hex::encode(Sha256::digest(b"Approved")));
    }

    #[test]
    fn authenticated_acknowledgement_is_exact_and_durable() {
        let root = tempfile::tempdir().expect("private directory");
        let path = fs::canonicalize(root.path())
            .expect("canonical directory")
            .join("release");
        let ledger = FileReleaseTaskLedger::open(&path).expect("open");
        ledger.initialize_policy(policy()).expect("task");
        ledger
            .reserve_provider_call(call("read-1"), 101)
            .expect("claim");
        let key = ReleaseCommitmentKey::new(2, Zeroizing::new([0x93; 32])).expect("key");
        let entered = ledger
            .enter_release("task-1", "read-1", b"Approved", &key, 102)
            .expect("charge");
        let mut wrong = acknowledgement(&entered, "read-1");
        wrong.recipient = "other-agent".to_owned();
        assert_eq!(
            ledger.acknowledge(&wrong).err(),
            Some(ReleaseStateError::Binding)
        );
        let mut wrong = acknowledgement(&entered, "read-1");
        wrong.content_commitment = "0".repeat(64);
        assert_eq!(
            ledger.acknowledge(&wrong).err(),
            Some(ReleaseStateError::Binding)
        );
        let mut wrong = acknowledgement(&entered, "read-1");
        wrong.released_bytes = 7;
        assert_eq!(
            ledger.acknowledge(&wrong).err(),
            Some(ReleaseStateError::Binding)
        );
        let ack = acknowledgement(&entered, "read-1");
        let acknowledged = ledger.acknowledge(&ack).expect("verified acknowledgement");
        assert_eq!(
            acknowledged.stage("read-1"),
            Some(ReleaseStage::AgentAcknowledged)
        );
        assert!(!acknowledged.delivery_unknown("read-1"));
        assert_eq!(acknowledged.counts(), (1, 1, 8));
        drop(ledger);

        let restarted = FileReleaseTaskLedger::open(&path).expect("restart");
        let loaded = restarted.load("task-1").expect("load").expect("task");
        assert_eq!(
            loaded.stage("read-1"),
            Some(ReleaseStage::AgentAcknowledged)
        );
        assert_eq!(loaded.counts(), (1, 1, 8));
        assert_eq!(
            restarted.acknowledge(&ack).err(),
            Some(ReleaseStateError::Stage)
        );
        assert_eq!(
            restarted.reserve_provider_call(call("read-1"), 103).err(),
            Some(ReleaseStateError::Replay)
        );
    }

    #[test]
    fn proven_no_send_keeps_charge_but_timeout_stays_unknown() {
        let key = ReleaseCommitmentKey::new(2, Zeroizing::new([0x93; 32])).expect("key");
        let mut state = ReleaseTaskState::new(policy()).expect("policy");
        state
            .reserve_provider_call(call("read-1"), 101)
            .expect("claim");
        state
            .enter_release("read-1", b"Approved", &key, 102)
            .expect("charge");
        assert!(state.delivery_unknown("read-1"));
        let evidence = ProvenNoSend {
            task_id: "task-1".to_owned(),
            operation_id: "read-1".to_owned(),
        };
        state
            .not_delivered(&evidence)
            .expect("durable no-send proof");
        assert_eq!(state.stage("read-1"), Some(ReleaseStage::NotDelivered));
        assert!(!state.delivery_unknown("read-1"));
        assert_eq!(state.counts(), (1, 1, 8));
        assert_eq!(
            state.not_delivered(&evidence),
            Err(ReleaseStateError::Stage)
        );
        assert_eq!(
            state.acknowledge(&acknowledgement(&state, "read-1")),
            Err(ReleaseStateError::Stage)
        );
    }

    #[test]
    fn provider_failure_spends_call_only_and_binding_denials_spend_nothing() {
        let mut state = ReleaseTaskState::new(policy()).expect("policy");
        let mut wrong = call("read-1");
        wrong.connection_generation = 4;
        assert_eq!(
            state.reserve_provider_call(wrong, 101),
            Err(ReleaseStateError::Binding)
        );
        assert_eq!(state.counts(), (0, 0, 0));
        state
            .reserve_provider_call(call("read-1"), 101)
            .expect("claim");
        state
            .provider_unavailable("read-1")
            .expect("provider denial");
        assert_eq!(state.counts(), (1, 0, 0));
        assert_eq!(
            state.reserve_provider_call(call("read-1"), 102),
            Err(ReleaseStateError::Replay)
        );
        state
            .reserve_provider_call(call("read-2"), 102)
            .expect("new action");
        assert_eq!(
            state.reserve_provider_call(call("read-3"), 103),
            Err(ReleaseStateError::Exhausted)
        );
    }

    #[test]
    fn revocation_and_expiry_stop_new_release_commitments() {
        let key = ReleaseCommitmentKey::new(1, Zeroizing::new([1; 32])).expect("key");
        let mut state = ReleaseTaskState::new(policy()).expect("policy");
        state
            .reserve_provider_call(call("read-1"), 101)
            .expect("claim");
        assert_eq!(
            state.enter_release("read-1", b"123456789", &key, 102),
            Err(ReleaseStateError::Exhausted)
        );
        assert_eq!(state.counts(), (1, 0, 0));
        state.revoke();
        assert_eq!(
            state.enter_release("read-1", b"ok", &key, 103),
            Err(ReleaseStateError::Inactive)
        );
        assert_eq!(
            state.reserve_provider_call(call("read-2"), 103),
            Err(ReleaseStateError::Inactive)
        );
        let mut expired = ReleaseTaskState::new(policy()).expect("policy");
        assert_eq!(
            expired.reserve_provider_call(call("read-1"), 200),
            Err(ReleaseStateError::Inactive)
        );
    }

    #[test]
    fn durable_restart_keeps_charge_and_refuses_same_operation() {
        let root = tempfile::tempdir().expect("private directory");
        let path = fs::canonicalize(root.path())
            .expect("canonical directory")
            .join("release");
        let ledger = FileReleaseTaskLedger::open(&path).expect("open");
        ledger.initialize_policy(policy()).expect("task");
        ledger
            .reserve_provider_call(call("read-1"), 101)
            .expect("call claim");
        let key = ReleaseCommitmentKey::new(1, Zeroizing::new([7; 32])).expect("key");
        let entered = ledger
            .enter_release("task-1", "read-1", b"Approved", &key, 102)
            .expect("durable charge");
        let digest = entered.digest().expect("canonical digest");
        drop(ledger);

        let restarted = FileReleaseTaskLedger::open(&path).expect("reopen");
        let loaded = restarted.load("task-1").expect("load").expect("task");
        assert_eq!(loaded.digest().expect("digest"), digest);
        assert_eq!(loaded.counts(), (1, 1, 8));
        assert!(loaded.delivery_unknown("read-1"));
        let stored = fs::read(restarted.key_path("task-1").expect("path")).expect("stored state");
        assert!(
            !stored
                .windows(b"Approved".len())
                .any(|part| part == b"Approved")
        );
        assert_eq!(
            restarted.reserve_provider_call(call("read-1"), 103).err(),
            Some(ReleaseStateError::Replay)
        );
        assert_eq!(
            restarted
                .enter_release("task-1", "read-1", b"Approved", &key, 103)
                .err(),
            Some(ReleaseStateError::Stage)
        );
        let loaded = restarted.load("task-1").expect("load").expect("task");
        assert_eq!(loaded.counts(), (1, 1, 8));
        restarted.revoke("task-1").expect("revoke");
        assert_eq!(
            restarted.reserve_provider_call(call("read-2"), 104).err(),
            Some(ReleaseStateError::Inactive)
        );
    }

    #[test]
    fn simultaneous_claim_has_one_winner_and_corruption_fails_closed() {
        let root = tempfile::tempdir().expect("private directory");
        let path = fs::canonicalize(root.path())
            .expect("canonical directory")
            .join("release");
        FileReleaseTaskLedger::open(&path)
            .expect("open")
            .initialize_policy(policy())
            .expect("task");
        let barrier = Arc::new(Barrier::new(2));
        let outcomes = std::thread::scope(|scope| {
            let mut jobs = Vec::new();
            for _ in 0..2 {
                let barrier = Arc::clone(&barrier);
                let path = path.clone();
                jobs.push(scope.spawn(move || {
                    let ledger = FileReleaseTaskLedger::open(path).expect("open");
                    barrier.wait();
                    ledger
                        .reserve_provider_call(call("read-1"), 101)
                        .map(|_| ())
                }));
            }
            jobs.into_iter()
                .map(|job| job.join().expect("worker"))
                .collect::<Vec<_>>()
        });
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| **result == Err(ReleaseStateError::Replay))
                .count(),
            1
        );
        let ledger = FileReleaseTaskLedger::open(&path).expect("open");
        assert_eq!(
            ledger.load("task-1").expect("load").expect("task").counts(),
            (1, 0, 0)
        );
        ledger
            .provider_unavailable("task-1", "read-1")
            .expect("provider failed");
        assert_eq!(
            ledger
                .load("task-1")
                .expect("load")
                .expect("task")
                .stage("read-1"),
            Some(ReleaseStage::ProviderUnavailable)
        );
        fs::write(ledger.key_path("task-1").expect("path"), b"{}").expect("tamper");
        assert_eq!(
            ledger.load("task-1").err(),
            Some(ReleaseStateError::Corrupt)
        );
    }

    #[test]
    fn competing_release_entries_charge_only_one_budget_slot() {
        let root = tempfile::tempdir().expect("private directory");
        let path = fs::canonicalize(root.path())
            .expect("canonical directory")
            .join("release");
        let ledger = FileReleaseTaskLedger::open(&path).expect("open");
        ledger.initialize_policy(policy()).expect("task");
        ledger
            .reserve_provider_call(call("read-1"), 101)
            .expect("first call");
        ledger
            .reserve_provider_call(call("read-2"), 101)
            .expect("second call");
        let barrier = Arc::new(Barrier::new(2));
        let outcomes = std::thread::scope(|scope| {
            let mut jobs = Vec::new();
            for operation in ["read-1", "read-2"] {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                jobs.push(scope.spawn(move || {
                    let ledger = FileReleaseTaskLedger::open(path).expect("open");
                    let key = ReleaseCommitmentKey::new(1, Zeroizing::new([7; 32])).expect("key");
                    barrier.wait();
                    ledger
                        .enter_release("task-1", operation, b"Approved", &key, 102)
                        .map(|_| ())
                }));
            }
            jobs.into_iter()
                .map(|job| job.join().expect("worker"))
                .collect::<Vec<_>>()
        });
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| **result == Err(ReleaseStateError::Exhausted))
                .count(),
            1
        );
        assert_eq!(
            ledger.load("task-1").expect("load").expect("task").counts(),
            (2, 1, 8)
        );
    }

    #[test]
    fn exact_write_claim_spends_once_and_rejects_changed_task_or_connection() {
        let mut state = ReleaseTaskState::from_test_policy(write_policy()).expect("write task");
        let first = write_intent("edit-1");
        state.reserve_write(&first, 101).expect("first write claim");
        assert_eq!(state.write_count(), 1);
        assert_eq!(
            state.reserve_write(&first, 101),
            Err(ReleaseStateError::Replay)
        );
        assert_eq!(
            state.reserve_write(&write_intent("edit-2"), 101),
            Err(ReleaseStateError::Exhausted)
        );
        let mut wrong = write_intent("edit-2").intent().clone();
        wrong.connection_generation = 4;
        assert_eq!(
            state.reserve_write(&ApprovedTaskWrite::from_test_intent(wrong), 101),
            Err(ReleaseStateError::Binding)
        );
        let mut wrong = write_intent("edit-2").intent().clone();
        wrong.task_commitment = "12".repeat(32);
        assert_eq!(
            state.reserve_write(&ApprovedTaskWrite::from_test_intent(wrong), 101),
            Err(ReleaseStateError::Binding)
        );
        state.revoke();
        assert_eq!(
            state.reserve_write(&write_intent("edit-3"), 101),
            Err(ReleaseStateError::Inactive)
        );
    }

    #[test]
    fn read_and_write_share_task_replay_and_revocation() {
        let mut policy = policy();
        policy.max_writes = 1;
        policy.write_scopes = write_policy().write_scopes;
        let mut state = ReleaseTaskState::from_test_policy(policy).expect("combined task");
        state
            .reserve_write(&write_intent("same-operation"), 101)
            .expect("write claim");
        assert_eq!(
            state.reserve_provider_call(call("same-operation"), 101),
            Err(ReleaseStateError::Replay)
        );
        state.revoke();
        assert_eq!(
            state.reserve_provider_call(call("new-read"), 101),
            Err(ReleaseStateError::Inactive)
        );
    }

    #[test]
    fn competing_last_write_claims_remain_spent_after_restart() {
        let root = tempfile::tempdir().expect("private directory");
        let path = fs::canonicalize(root.path())
            .expect("canonical directory")
            .join("task");
        let ledger = FileReleaseTaskLedger::open(&path).expect("open");
        ledger.initialize_policy(write_policy()).expect("task");
        let barrier = Arc::new(Barrier::new(2));
        let outcomes = std::thread::scope(|scope| {
            let mut jobs = Vec::new();
            for operation in ["edit-1", "edit-2"] {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                jobs.push(scope.spawn(move || {
                    let ledger = FileReleaseTaskLedger::open(path).expect("open");
                    barrier.wait();
                    ledger
                        .reserve_write(&write_intent(operation), 101)
                        .map(|_| ())
                }));
            }
            jobs.into_iter()
                .map(|job| job.join().expect("worker"))
                .collect::<Vec<_>>()
        });
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| **result == Err(ReleaseStateError::Exhausted))
                .count(),
            1
        );
        let reopened = FileReleaseTaskLedger::open(path).expect("reopen");
        assert_eq!(
            reopened
                .load("task-1")
                .expect("load")
                .expect("task")
                .write_count(),
            1
        );
    }
}
