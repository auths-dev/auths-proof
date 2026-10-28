//! Task-scoped release accounting transitions. The installed release engine
//! must persist each returned state with an atomic compare-and-swap before it
//! performs the corresponding provider or agent-channel I/O. This model alone
//! neither verifies a grant nor sends content.

#[cfg(test)]
use crate::ClosedReleaseRequest;
use crate::participant_enrollment::{
    EnrollmentTree, EnrollmentTreeError, ParticipantEnrollmentProofs, RootEnrollmentProofs,
};
use crate::recipe::VerifiedCreatedChild;
use crate::release_verify::VerifiedReleaseRequest;
use crate::task_activation::TaskWriteScope;
use crate::task_activation::{AgentTaskDescriptor, ApprovedAgentTask, TaskActivationPins};
use crate::task_effect_plan::VerifiedEffectPlan;
use crate::task_enrollment::{TaskEnrollmentRecipes, TaskRootAuthority};
use crate::task_populate_attestation::{ExpectedPopulatePreflight, VerifiedPopulatePreflight};
use crate::task_recovery_attestation::VerifiedRecoveryAttestation;
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

mod delivery;
mod participants;
mod write_entry;
pub(crate) use delivery::{EnteredRelease, ReleaseDeliveryBinding};
pub(crate) use write_entry::EnteredTaskWrite;

const SCHEMA: &str = "auths.gateway-agent-task-state/13";
const MAX_RESOURCES: usize = 16;
const MAX_OPERATIONS: usize = 64;
const MAX_TASK_RELEASE_BYTES: u64 = 16 * 1_048_576;
// Includes the bounded 192 KiB participant tree and existing operation/card records.
const MAX_STATE_BYTES: usize = 524_288;
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
    pub(crate) connection_subject: String,
}

/// Task facts whose signature and company policy must be checked by the
/// enclosing admission engine before constructing a state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReleaseTaskPolicy {
    pub(crate) task_id: String,
    pub(crate) task_commitment: [u8; 32],
    pub(crate) company_id: String,
    pub(crate) initiator_principal: String,
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
    entry: write_entry::WriteEntry,
    writer: crate::participant_enrollment::EnrolledParticipant,
    /// Recorded at reservation so activity can find the exact attempt even
    /// when one task uses recipes with different replay namespaces.
    operator_namespace: String,
    resource_handle: String,
    recipe_digest: String,
    verb: crate::task_activation::TaskWriteVerb,
    connection_id: String,
    connection_generation: u64,
    connection_subject: String,
    action_commitment: String,
    request_commitment: String,
}

pub(crate) struct WriteAttemptPin {
    pub(crate) operation_id: String,
    pub(crate) operator_namespace: String,
    pub(crate) recipe_digest: String,
    pub(crate) action_commitment: String,
}

/// Immutable child authority derived from one reserved task create and a
/// credential-bearing metadata observation. Its ID is not agent input.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundChild {
    create_operation_id: String,
    create_recipe_digest: String,
    populate_recipe_digest: String,
    action_commitment: String,
    request_commitment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery: Option<RecoveredChildEvidence>,
    metadata_digest: String,
    id: String,
    connection_generation: u64,
    connection_subject: String,
}

/// A response-less binding has its own human signature and two independently
/// checked observations. It deliberately has no provider response digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveredChildEvidence {
    attestation_commitment: String,
    human_action_commitment: String,
    search_report_sha256: String,
    producer_observation_sha256: String,
    baseline_sha256: String,
    search_metadata_sha256: String,
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
    connection_subject: &'a str,
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
    /// Provider call was spent, but current policy, connection or release
    /// budget refused any agent-channel entry.
    ReleaseRefused,
    /// Bytes and one release were durably charged before channel entry. On
    /// restart, this is delivery-unknown without verified terminal evidence.
    ReleaseEntered,
    /// The channel proved no content byte was sent after the charge; length
    /// framing may have been observed. The charge is not refunded.
    NotDelivered,
    /// An authenticated acknowledgement of the exact delivery was verified
    /// by the channel before this transition was persisted.
    AgentAcknowledged,
}

/// Minted by the agent acknowledgement verifier after it authenticates the
/// registered recipient key and exact delivered bytes. The installed channel
/// must still send those bytes before it requests the signature.
pub(crate) struct VerifiedAgentAcknowledgement {
    pub(crate) task_id: String,
    pub(crate) task_commitment: String,
    pub(crate) operation_id: String,
    pub(crate) recipient: String,
    pub(crate) released_bytes: u64,
    pub(crate) commitment_key_version: u32,
    pub(crate) content_commitment: String,
}

/// Minted by the channel only before attempting to send any private content.
/// A missing acknowledgement or an error after content sending begins is not
/// this evidence.
#[derive(Debug)]
pub(crate) struct ProvenNoSend {
    task_id: String,
    operation_id: String,
}

impl ProvenNoSend {
    /// The channel may call this only before its first content-byte send.
    pub(crate) fn before_content(task_id: &str, operation_id: &str) -> Self {
        Self {
            task_id: task_id.to_owned(),
            operation_id: operation_id.to_owned(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseOperation {
    resource_handle: String,
    recipe_digest: String,
    connection_id: String,
    connection_generation: u64,
    connection_subject: String,
    recipient: String,
    action_commitment: String,
    stage: ReleaseStage,
    released_bytes: Option<u64>,
    commitment_key_version: Option<u32>,
    content_commitment: Option<String>,
}

/// A task activation precedes native root possession. There is no legacy tree
/// decoder; absence of this explicit lifecycle field is a corrupt state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
enum TaskParticipants {
    Pending,
    Active {
        #[serde(deserialize_with = "EnrollmentTree::deserialize_stored")]
        tree: Box<EnrollmentTree>,
    },
}

impl TaskParticipants {
    fn tree(&self) -> Result<&EnrollmentTree, ReleaseStateError> {
        match self {
            Self::Active { tree } => Ok(tree),
            Self::Pending => Err(ReleaseStateError::Inactive),
        }
    }

    fn tree_mut(&mut self) -> Result<&mut EnrollmentTree, ReleaseStateError> {
        match self {
            Self::Active { tree } => Ok(tree),
            Self::Pending => Err(ReleaseStateError::Inactive),
        }
    }
}

/// Installed trust and time, sampled within the existing exclusive transaction.
pub(crate) struct EnrollmentTransaction<'a> {
    pub(crate) context: &'a auths_model::TrustedContext,
    pub(crate) pins: &'a TaskActivationPins,
    pub(crate) time: &'a crate::QualificationGate,
}

impl EnrollmentTransaction<'_> {
    fn now(&self) -> Result<u64, ReleaseStateError> {
        transaction_time(self.time)
    }
}

/// Sample the installed execution clock only after acquiring the journal lock.
fn transaction_time(time: &crate::QualificationGate) -> Result<u64, ReleaseStateError> {
    time.execution_time()
        .map(crate::DeploymentTime::unix_seconds)
        .ok_or(ReleaseStateError::Inactive)
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
    initiator_principal: String,
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
    participants: TaskParticipants,
    revoked: bool,
    provider_calls: u32,
    releases: u32,
    released_bytes: u64,
    operations: BTreeMap<String, ReleaseOperation>,
    writes: BTreeMap<String, WriteOperation>,
    child_binding: Option<BoundChild>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    effect_plan: Option<VerifiedEffectPlan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    populate_preflight: Option<VerifiedPopulatePreflight>,
}

/// Owner-visible accounting only. No provider bytes, account subject,
/// connection reference, content digest or keyed commitment is exported.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TaskStatus {
    schema: &'static str,
    task_id: String,
    expires_at: u64,
    revoked: bool,
    provider_calls: u32,
    max_provider_calls: u32,
    releases: u32,
    max_releases: u32,
    released_bytes: u64,
    max_release_bytes: u64,
    writes: usize,
    max_writes: u32,
    reads: Vec<ReadOperationStatus>,
    write_operations: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ReadOperationStatus {
    operation_id: String,
    stage: &'static str,
    released_bytes: Option<u64>,
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

impl From<EnrollmentTreeError> for ReleaseStateError {
    fn from(error: EnrollmentTreeError) -> Self {
        match error {
            EnrollmentTreeError::Binding | EnrollmentTreeError::Verification(_) => Self::Binding,
            EnrollmentTreeError::Inactive => Self::Inactive,
            EnrollmentTreeError::Full => Self::Exhausted,
            EnrollmentTreeError::Replay => Self::Replay,
            EnrollmentTreeError::Corrupt => Self::Corrupt,
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
    pub(crate) fn write_attempt_pins(&self) -> Vec<WriteAttemptPin> {
        self.writes
            .iter()
            .map(|(operation_id, write)| WriteAttemptPin {
                operation_id: operation_id.clone(),
                operator_namespace: write.operator_namespace.clone(),
                recipe_digest: write.recipe_digest.clone(),
                action_commitment: write.action_commitment.clone(),
            })
            .collect()
    }

    pub(crate) fn status(&self) -> TaskStatus {
        let reads = self
            .operations
            .iter()
            .map(|(operation_id, operation)| ReadOperationStatus {
                operation_id: operation_id.clone(),
                stage: match operation.stage {
                    ReleaseStage::ProviderCallReserved => "provider-call-reserved",
                    ReleaseStage::ProviderUnavailable => "provider-unavailable",
                    ReleaseStage::ReleaseRefused => "release-refused",
                    ReleaseStage::ReleaseEntered => "delivery-unknown",
                    ReleaseStage::NotDelivered => "not-delivered",
                    ReleaseStage::AgentAcknowledged => "agent-acknowledged",
                },
                released_bytes: operation.released_bytes,
            })
            .collect();
        TaskStatus {
            schema: "auths.gateway-agent-task-status/1",
            task_id: self.task_id.clone(),
            expires_at: self.expires_at,
            revoked: self.revoked,
            provider_calls: self.provider_calls,
            max_provider_calls: self.max_provider_calls,
            releases: self.releases,
            max_releases: self.max_releases,
            released_bytes: self.released_bytes,
            max_release_bytes: self.max_release_bytes,
            writes: self.writes.len(),
            max_writes: self.max_writes,
            reads,
            write_operations: self.writes.keys().cloned().collect(),
        }
    }
    fn new(policy: ReleaseTaskPolicy) -> Result<Self, ReleaseStateError> {
        if !bounded_text(&policy.task_id, 128)
            || !bounded_text(&policy.company_id, 128)
            || !bounded_text(&policy.initiator_principal, 256)
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
                || !bounded_text(&resource.connection_id, 128)
                || resource.connection_generation == 0
                || !bounded_text(&resource.connection_subject, 256)
                || !distinct.insert((&resource.handle, &resource.recipe_digest))
            {
                return Err(ReleaseStateError::Binding);
            }
        }
        let mut distinct_writes = BTreeSet::new();
        for scope in &policy.write_scopes {
            if !bounded_text(&scope.handle, 256)
                || !valid_digest(&scope.recipe_digest)
                || scope.connection_id != policy.connection_id
                || scope.connection_generation != policy.connection_generation
                || scope.connection_subject != policy.connection_subject
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
            initiator_principal: policy.initiator_principal,
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
            participants: TaskParticipants::Pending,
            revoked: false,
            provider_calls: 0,
            releases: 0,
            released_bytes: 0,
            operations: BTreeMap::new(),
            writes: BTreeMap::new(),
            child_binding: None,
            effect_plan: None,
            populate_preflight: None,
        })
    }

    /// Commit a native-verified two-effect plan before the first write
    /// reservation. Re-presenting identical evidence is idempotent; a changed
    /// plan or one first seen after entry is refused.
    fn record_effect_plan(
        &mut self,
        plan: &VerifiedEffectPlan,
        now: u64,
    ) -> Result<(), ReleaseStateError> {
        self.active(now)?;
        if now >= plan.expires_at {
            return Err(ReleaseStateError::Inactive);
        }
        if !self.valid_effect_plan(plan) {
            return Err(ReleaseStateError::Binding);
        }
        if let Some(existing) = &self.effect_plan {
            return if existing == plan {
                Ok(())
            } else {
                Err(ReleaseStateError::Replay)
            };
        }
        if !self.writes.is_empty() || self.child_binding.is_some() {
            return Err(ReleaseStateError::Replay);
        }
        self.effect_plan = Some(plan.clone());
        Ok(())
    }

    fn valid_effect_plan(&self, plan: &VerifiedEffectPlan) -> bool {
        let Some(card) = &self.activated_card else {
            return false;
        };
        let Some(pending) = &card.pending_child else {
            return false;
        };
        let create = &plan.create;
        self.participants
            .tree()
            .and_then(|tree| {
                tree.retained_identity(create.writer.principal())
                    .map_err(Into::into)
            })
            .is_ok_and(|writer| writer == create.writer)
            && valid_digest(&plan.plan_commitment)
            && valid_digest(&plan.content_commitment)
            && (1..=192).contains(&plan.content_length)
            && plan.expires_at > card.not_before
            && plan.expires_at <= self.expires_at
            && match (&plan.preflight_rule_digest, &plan.preflight_key_sha256) {
                (None, None) => true,
                (Some(rule), Some(key)) => valid_digest(rule) && valid_digest(key),
                _ => false,
            }
            && plan.populate_recipe_digest == pending.populate_recipe_digest
            && bounded_text(&plan.populate_operation_id, 128)
            && plan.populate_operation_id != create.operation_id
            && create.task_id == self.task_id
            && same_commitment(&self.task_commitment, &create.task_commitment)
            && create.operation_id == pending.create_operation_id
            && create.recipe_digest == pending.create_recipe_digest
            && create.resource_handle == pending.parent_handle
            && create.verb == crate::task_activation::TaskWriteVerb::Create
            && create.connection_id == self.connection_id
            && create.connection_generation == self.connection_generation
            && create.connection_subject == self.connection_subject
            && valid_digest(&create.action_commitment)
            && valid_digest(&create.request_commitment)
            && self.scope_matches(
                &create.resource_handle,
                &create.recipe_digest,
                &create.verb,
                &create.connection_id,
                create.connection_generation,
                &create.connection_subject,
            )
    }

    fn valid_populate_preflight(&self, preflight: &VerifiedPopulatePreflight) -> bool {
        let (Some(plan), Some(child)) = (&self.effect_plan, &self.child_binding) else {
            return false;
        };
        let Some(rule_digest) = plan.preflight_rule_digest.as_deref() else {
            return false;
        };
        preflight.matches_expected(&ExpectedPopulatePreflight {
            task_id: &self.task_id,
            task_commitment: &self.task_commitment,
            child_id: &child.id,
            rule_digest,
            plan,
        })
    }

    fn record_populate_preflight(
        &mut self,
        preflight: &VerifiedPopulatePreflight,
        now: u64,
    ) -> Result<(), ReleaseStateError> {
        self.active(now)?;
        if !preflight.valid_at(now) {
            return Err(ReleaseStateError::Inactive);
        }
        if !self.valid_populate_preflight(preflight) {
            return Err(ReleaseStateError::Binding);
        }
        let Some(child) = &self.child_binding else {
            return Err(ReleaseStateError::Binding);
        };
        if self.writes.values().any(|write| {
            write.resource_handle == child.id && write.recipe_digest == child.populate_recipe_digest
        }) {
            return Err(ReleaseStateError::Replay);
        }
        if let Some(existing) = &self.populate_preflight {
            if existing == preflight {
                return Ok(());
            }
            if preflight.checked_at() <= existing.checked_at() {
                return Err(ReleaseStateError::Replay);
            }
        }
        self.populate_preflight = Some(preflight.clone());
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn from_test_policy(policy: ReleaseTaskPolicy) -> Result<Self, ReleaseStateError> {
        Self::new(policy)
    }

    fn operation_count(&self) -> Option<usize> {
        self.operations.len().checked_add(self.writes.len())
    }

    fn active(&self, now: u64) -> Result<(), ReleaseStateError> {
        if self.revoked
            || now < self.not_before
            || now >= self.expires_at
            || matches!(&self.participants, TaskParticipants::Active { tree } if !tree.root().active)
        {
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
            initiator_principal: self.initiator_principal.clone(),
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
        if let TaskParticipants::Active { tree } = &self.participants
            && !crate::task_enrollment::root_matches_task(tree.root(), &approved)
        {
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
            || !bounded_text(call.operation_id, 128)
            || call.action_commitment == [0; 32]
            || !self.resources.iter().any(|resource| {
                resource.handle == call.resource_handle
                    && resource.recipe_digest == call.recipe_digest
                    && resource.connection_id == call.connection_id
                    && resource.connection_generation == call.connection_generation
                    && resource.connection_subject == call.connection_subject
            })
        {
            return Err(ReleaseStateError::Binding);
        }
        if self.operations.contains_key(call.operation_id)
            || self.writes.contains_key(call.operation_id)
        {
            return Err(ReleaseStateError::Replay);
        }
        if self.provider_calls >= self.max_provider_calls
            || self
                .operation_count()
                .is_none_or(|count| count >= MAX_OPERATIONS)
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
                connection_subject: call.connection_subject.to_owned(),
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
    #[cfg(test)]
    fn reserve_write(
        &mut self,
        approved: &ApprovedTaskWrite,
        now: u64,
    ) -> Result<(), ReleaseStateError> {
        self.reserve_write_with_namespace(approved, "test-only", now)
    }

    fn reserve_write_with_namespace(
        &mut self,
        approved: &ApprovedTaskWrite,
        operator_namespace: &str,
        now: u64,
    ) -> Result<(), ReleaseStateError> {
        self.active(now)?;
        if crate::OperatorNamespace::parse(operator_namespace).is_err() {
            return Err(ReleaseStateError::Binding);
        }
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
            || !self.scope_matches(
                &intent.resource_handle,
                &intent.recipe_digest,
                &intent.verb,
                &intent.connection_id,
                intent.connection_generation,
                &intent.connection_subject,
            )
        {
            return Err(ReleaseStateError::Binding);
        }
        if self.effect_plan.as_ref().is_some_and(|plan| {
            intent.verb == crate::task_activation::TaskWriteVerb::Create
                && (now >= plan.expires_at || &plan.create != intent)
        }) {
            return Err(ReleaseStateError::Binding);
        }
        if self.operations.contains_key(&intent.operation_id)
            || self.writes.contains_key(&intent.operation_id)
        {
            return Err(ReleaseStateError::Replay);
        }
        if self.is_second_child_populate(
            &intent.resource_handle,
            &intent.recipe_digest,
            &intent.verb,
        ) {
            return Err(ReleaseStateError::Replay);
        }
        if self.writes.len() >= self.max_writes as usize
            || self
                .operation_count()
                .is_none_or(|count| count >= MAX_OPERATIONS)
        {
            return Err(ReleaseStateError::Exhausted);
        }
        self.writes.insert(
            intent.operation_id.clone(),
            WriteOperation {
                entry: write_entry::WriteEntry::Reserved,
                writer: intent.writer.clone(),
                operator_namespace: operator_namespace.to_owned(),
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

    fn bind_created_child(
        &mut self,
        approved: &ApprovedTaskWrite,
        child: &VerifiedCreatedChild,
        response_digest: &[u8; 32],
        now: u64,
    ) -> Result<(), ReleaseStateError> {
        self.active(now)?;
        if self.child_binding.is_some() {
            return Err(ReleaseStateError::Replay);
        }
        let intent = approved.intent();
        let pending = self
            .activated_card
            .as_ref()
            .and_then(|card| card.pending_child.as_ref())
            .ok_or(ReleaseStateError::Binding)?;
        let binding = BoundChild {
            create_operation_id: intent.operation_id.clone(),
            create_recipe_digest: intent.recipe_digest.clone(),
            populate_recipe_digest: pending.populate_recipe_digest.clone(),
            action_commitment: intent.action_commitment.clone(),
            request_commitment: intent.request_commitment.clone(),
            response_digest: Some(hex::encode(response_digest)),
            recovery: None,
            metadata_digest: child.metadata_digest().to_owned(),
            id: child.id().to_owned(),
            connection_generation: intent.connection_generation,
            connection_subject: intent.connection_subject.clone(),
        };
        if intent.task_id != self.task_id
            || !same_commitment(&self.task_commitment, &intent.task_commitment)
            || self
                .writes
                .get(&intent.operation_id)
                .is_none_or(|write| write.writer != intent.writer)
            || !self.valid_child_binding(&binding)
        {
            return Err(ReleaseStateError::Binding);
        }
        self.child_binding = Some(binding);
        Ok(())
    }

    fn bind_recovered_child(
        &mut self,
        approved: &ApprovedTaskWrite,
        plan: &VerifiedEffectPlan,
        child: &VerifiedCreatedChild,
        attestation: &VerifiedRecoveryAttestation,
        human_action_commitment: &str,
        now: u64,
    ) -> Result<(), ReleaseStateError> {
        self.active(now)?;
        if !attestation.valid_at(now) {
            return Err(ReleaseStateError::Inactive);
        }
        if !self.recovery_create_reserved(plan) {
            return Err(ReleaseStateError::Replay);
        }
        let intent = approved.intent();
        let pending = self
            .activated_card
            .as_ref()
            .and_then(|card| card.pending_child.as_ref())
            .ok_or(ReleaseStateError::Binding)?;
        let binding = BoundChild {
            create_operation_id: intent.operation_id.clone(),
            create_recipe_digest: intent.recipe_digest.clone(),
            populate_recipe_digest: pending.populate_recipe_digest.clone(),
            action_commitment: intent.action_commitment.clone(),
            request_commitment: intent.request_commitment.clone(),
            response_digest: None,
            recovery: Some(RecoveredChildEvidence {
                attestation_commitment: attestation.commitment().to_owned(),
                human_action_commitment: human_action_commitment.to_owned(),
                search_report_sha256: attestation.search_report_sha256().to_owned(),
                producer_observation_sha256: attestation.producer_observation_sha256().to_owned(),
                baseline_sha256: attestation.baseline_sha256().to_owned(),
                search_metadata_sha256: attestation.candidate_metadata_sha256().to_owned(),
            }),
            metadata_digest: child.metadata_digest().to_owned(),
            id: child.id().to_owned(),
            connection_generation: intent.connection_generation,
            connection_subject: intent.connection_subject.clone(),
        };
        if intent.task_id != self.task_id
            || !same_commitment(&self.task_commitment, &intent.task_commitment)
            || &plan.create != intent
            || child.id() != attestation.candidate_id()
            || self
                .writes
                .get(&intent.operation_id)
                .is_none_or(|write| write.writer != intent.writer)
            || !self.valid_child_binding(&binding)
        {
            return Err(ReleaseStateError::Binding);
        }
        self.child_binding = Some(binding);
        Ok(())
    }

    fn valid_child_binding(&self, binding: &BoundChild) -> bool {
        let Some(pending) = self
            .activated_card
            .as_ref()
            .and_then(|card| card.pending_child.as_ref())
        else {
            return false;
        };
        let Some(write) = self.writes.get(&binding.create_operation_id) else {
            return false;
        };
        pending.create_operation_id == binding.create_operation_id
            && pending.create_recipe_digest == binding.create_recipe_digest
            && pending.populate_recipe_digest == binding.populate_recipe_digest
            && pending.parent_handle == write.resource_handle
            && write.verb == crate::task_activation::TaskWriteVerb::Create
            && write.recipe_digest == binding.create_recipe_digest
            && write.action_commitment == binding.action_commitment
            && write.request_commitment == binding.request_commitment
            && match (&binding.response_digest, &binding.recovery) {
                (Some(response), None) => valid_digest(response),
                (None, Some(recovery)) => [
                    &recovery.attestation_commitment,
                    &recovery.human_action_commitment,
                    &recovery.search_report_sha256,
                    &recovery.producer_observation_sha256,
                    &recovery.baseline_sha256,
                    &recovery.search_metadata_sha256,
                ]
                .into_iter()
                .all(|value| valid_digest(value)),
                _ => false,
            }
            && valid_digest(&binding.metadata_digest)
            && !binding.id.is_empty()
            && binding.id.len() <= 128
            && binding
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            && !self
                .write_scopes
                .iter()
                .any(|scope| scope.handle == binding.id)
            && binding.connection_generation == self.connection_generation
            && binding.connection_subject == self.connection_subject
    }

    pub(crate) fn bound_child_scope(&self) -> Option<TaskWriteScope> {
        let child = self.child_binding.as_ref()?;
        Some(TaskWriteScope {
            handle: child.id.clone(),
            recipe_digest: child.populate_recipe_digest.clone(),
            verb: crate::task_activation::TaskWriteVerb::Edit,
            connection_id: self.connection_id.clone(),
            connection_generation: child.connection_generation,
            connection_subject: child.connection_subject.clone(),
        })
    }

    pub(crate) fn effect_plan(&self) -> Option<&VerifiedEffectPlan> {
        self.effect_plan.as_ref()
    }

    /// A response-less recovery search may begin only for the one create
    /// already reserved under the immutable human plan. This does not infer
    /// provider entry or bind any candidate.
    pub(crate) fn recovery_create_reserved(&self, plan: &VerifiedEffectPlan) -> bool {
        if self.child_binding.is_some() || self.writes.len() != 1 {
            return false;
        }
        let create = &plan.create;
        let Some(write) = self.writes.get(&create.operation_id) else {
            return false;
        };
        let Some(pending) = self
            .activated_card
            .as_ref()
            .and_then(|card| card.pending_child.as_ref())
        else {
            return false;
        };
        pending.create_operation_id == create.operation_id
            && pending.create_recipe_digest == create.recipe_digest
            && pending.populate_recipe_digest == plan.populate_recipe_digest
            && pending.parent_handle == create.resource_handle
            && write.verb == crate::task_activation::TaskWriteVerb::Create
            && write.resource_handle == create.resource_handle
            && write.recipe_digest == create.recipe_digest
            && write.connection_id == create.connection_id
            && write.connection_generation == create.connection_generation
            && write.connection_subject == create.connection_subject
            && write.writer == create.writer
            && write.action_commitment == create.action_commitment
            && write.request_commitment == create.request_commitment
    }

    pub(crate) fn populate_preflight(&self) -> Option<&VerifiedPopulatePreflight> {
        self.populate_preflight.as_ref()
    }

    pub(crate) fn recorded_populate_preflight_is_valid(&self) -> bool {
        self.populate_preflight
            .as_ref()
            .is_some_and(|preflight| self.valid_populate_preflight(preflight))
    }

    fn scope_matches(
        &self,
        handle: &str,
        recipe_digest: &str,
        verb: &crate::task_activation::TaskWriteVerb,
        connection_id: &str,
        connection_generation: u64,
        connection_subject: &str,
    ) -> bool {
        self.write_scopes
            .iter()
            .chain(self.bound_child_scope().iter())
            .any(|scope| {
                scope.handle == handle
                    && scope.recipe_digest == recipe_digest
                    && &scope.verb == verb
                    && scope.connection_id == connection_id
                    && scope.connection_generation == connection_generation
                    && scope.connection_subject == connection_subject
            })
    }

    fn is_second_child_populate(
        &self,
        handle: &str,
        recipe_digest: &str,
        verb: &crate::task_activation::TaskWriteVerb,
    ) -> bool {
        self.bound_child_scope().is_some_and(|scope| {
            scope.handle == handle
                && scope.recipe_digest == recipe_digest
                && &scope.verb == verb
                && self.writes.values().any(|write| {
                    write.resource_handle == handle
                        && write.recipe_digest == recipe_digest
                        && &write.verb == verb
                })
        })
    }

    /// Admit a compiled request only with a native-verified sole actor and
    /// exact enrolled resource-grant ancestry. The connection reference must come from the
    /// loaded, subject-bound credential record for this read recipe.
    pub(crate) fn reserve_verified_request(
        &mut self,
        verified: &VerifiedReleaseRequest,
        connection_id: &str,
        connection_generation: u64,
        connection_subject: &str,
        now: u64,
    ) -> Result<(), ReleaseStateError> {
        let request = verified.request();
        if verified.actor().as_str() != request.recipient()
            || !same_commitment(
                &self.task_commitment,
                &hex::encode(request.task_commitment()),
            )
        {
            return Err(ReleaseStateError::Binding);
        }
        let scope = ReleaseResourceScope {
            handle: request.resource_handle().to_owned(),
            recipe_digest: hex::encode(request.recipe_digest()),
            connection_id: connection_id.to_owned(),
            connection_generation,
            connection_subject: connection_subject.to_owned(),
        };
        self.admit_read_participant(
            verified.authority(),
            &scope,
            request.operation_id().as_str(),
            now,
        )?;
        self.reserve_provider_call(
            ReleaseCall {
                task_id: request.task_id(),
                operation_id: request.operation_id().as_str(),
                resource_handle: request.resource_handle(),
                recipe_digest: &hex::encode(request.recipe_digest()),
                connection_id,
                connection_generation,
                connection_subject,
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
        connection_subject: &str,
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
                connection_subject,
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

    /// A complete result was held back before release entry because current
    /// authority, connection or release budget no longer admitted it.
    pub(crate) fn release_refused(&mut self, operation_id: &str) -> Result<(), ReleaseStateError> {
        let operation = self
            .operations
            .get_mut(operation_id)
            .ok_or(ReleaseStateError::Binding)?;
        if operation.stage != ReleaseStage::ProviderCallReserved {
            return Err(ReleaseStateError::Stage);
        }
        operation.stage = ReleaseStage::ReleaseRefused;
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
        if evidence.task_id != self.task_id
            || !same_commitment(&self.task_commitment, &evidence.task_commitment)
        {
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
        if let TaskParticipants::Active { tree } = &mut self.participants {
            tree.revoke_root();
        }
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

    #[cfg(test)]
    pub(crate) fn bound_child_id(&self) -> Option<&str> {
        self.child_binding
            .as_ref()
            .map(|binding| binding.id.as_str())
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

    /// Select the retained audit-key version only for an acknowledged release
    /// of this exact resource. The commitment and content stay private.
    pub(crate) fn acknowledged_key_version(
        &self,
        operation_id: &str,
        resource_handle: &str,
    ) -> Option<u32> {
        let operation = self.operations.get(operation_id)?;
        (operation.stage == ReleaseStage::AgentAcknowledged
            && operation.resource_handle == resource_handle)
            .then(|| self.commitment(operation_id).map(|(version, _)| version))
            .flatten()
    }

    /// Compare operator-presented bytes with an acknowledged release without
    /// exporting the keyed commitment or a guessable content digest.
    pub(crate) fn acknowledged_content_matches(
        &self,
        operation_id: &str,
        resource_handle: &str,
        content: &[u8],
        key: &ReleaseCommitmentKey,
    ) -> bool {
        let Some(operation) = self.operations.get(operation_id) else {
            return false;
        };
        if operation.stage != ReleaseStage::AgentAcknowledged
            || operation.resource_handle != resource_handle
            || operation.released_bytes != u64::try_from(content.len()).ok()
        {
            return false;
        }
        let Some((version, expected)) = self.commitment(operation_id) else {
            return false;
        };
        let Ok(commitment_scope) =
            ReleaseCommitmentContext::new(&self.task_id, resource_handle, operation_id, "released")
        else {
            return false;
        };
        let presented = key.commit(&commitment_scope, content);
        version == presented.key_version() && same_commitment(expected, &presented.hex())
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
            if !write.entry.valid_for(self.not_before, self.expires_at)
                || !bounded_text(operation_id, 128)
                || crate::OperatorNamespace::parse(&write.operator_namespace).is_err()
                || self.operations.contains_key(operation_id)
                || !valid_digest(&write.action_commitment)
                || write.action_commitment == "0".repeat(64)
                || !valid_digest(&write.request_commitment)
                || write.request_commitment == "0".repeat(64)
                || !self.matches_child_writer(
                    &write.resource_handle,
                    &write.recipe_digest,
                    &write.writer,
                )
                || write.connection_id != self.connection_id
                || write.connection_generation != self.connection_generation
                || write.connection_subject != self.connection_subject
                || !self.scope_matches(
                    &write.resource_handle,
                    &write.recipe_digest,
                    &write.verb,
                    &write.connection_id,
                    write.connection_generation,
                    &write.connection_subject,
                )
            {
                return Err(ReleaseStateError::Corrupt);
            }
        }
        if self
            .child_binding
            .as_ref()
            .is_some_and(|binding| !self.valid_child_binding(binding))
        {
            return Err(ReleaseStateError::Corrupt);
        }
        if let Some(scope) = self.bound_child_scope()
            && self
                .writes
                .values()
                .filter(|write| {
                    write.resource_handle == scope.handle
                        && write.recipe_digest == scope.recipe_digest
                        && write.verb == scope.verb
                })
                .count()
                > 1
        {
            return Err(ReleaseStateError::Corrupt);
        }
        Ok(())
    }

    fn validate_participant_root(
        &self,
        policy: &ReleaseTaskPolicy,
    ) -> Result<(), ReleaseStateError> {
        if let TaskParticipants::Active { tree } = &self.participants {
            let card = self
                .activated_card
                .as_ref()
                .ok_or(ReleaseStateError::Corrupt)?;
            if card.canonical_commitment().ok() != Some(policy.task_commitment)
                || !crate::task_enrollment::root_matches_card(
                    tree.root(),
                    card,
                    &policy.task_commitment,
                )
                || (self.revoked && tree.root().active)
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
        if state.schema != SCHEMA
            || state.encode()?.as_slice() != bytes
            || state
                .operation_count()
                .is_none_or(|count| count > MAX_OPERATIONS)
        {
            return Err(ReleaseStateError::Corrupt);
        }
        let policy = state.policy()?;
        Self::new(policy.clone()).map_err(|_| ReleaseStateError::Corrupt)?;
        state.validate_participant_root(&policy)?;
        if state.activated_card.is_some() {
            state
                .validate_participant_accounting()
                .map_err(|_| ReleaseStateError::Corrupt)?;
        }
        let mut releases = 0_u32;
        let mut released_bytes = 0_u64;
        state.validate_writes()?;
        if state
            .effect_plan
            .as_ref()
            .is_some_and(|plan| !state.valid_effect_plan(plan))
        {
            return Err(ReleaseStateError::Corrupt);
        }
        if state
            .populate_preflight
            .as_ref()
            .is_some_and(|preflight| !state.valid_populate_preflight(preflight))
        {
            return Err(ReleaseStateError::Corrupt);
        }
        for (operation_id, operation) in &state.operations {
            if !bounded_text(operation_id, 128)
                || !valid_digest(&operation.action_commitment)
                || operation.action_commitment == "0".repeat(64)
                || !state.resources.iter().any(|resource| {
                    resource.handle == operation.resource_handle
                        && resource.recipe_digest == operation.recipe_digest
                        && resource.connection_id == operation.connection_id
                        && resource.connection_generation == operation.connection_generation
                        && resource.connection_subject == operation.connection_subject
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

    pub(crate) fn bootstrap_participants(
        &self,
        task_id: &str,
        transaction: &EnrollmentTransaction<'_>,
        recipes: &TaskEnrollmentRecipes<'_>,
        authority: &TaskRootAuthority,
        proofs: &RootEnrollmentProofs<'_>,
    ) -> Result<[u8; 32], ReleaseStateError> {
        let state = self.update(task_id, |state| {
            let now = transaction.now()?;
            let task = state.activated_task(transaction.pins, now)?;
            if !matches!(state.participants, TaskParticipants::Pending)
                || !state.operations.is_empty()
                || !state.writes.is_empty()
            {
                return Err(ReleaseStateError::Replay);
            }
            let root = crate::task_enrollment::root_pins(&task, recipes, authority)?;
            let tree = EnrollmentTree::bootstrap(transaction.context, &root, now, proofs)?;
            tree.parent_pins(root.enrollment_commitment, transaction.now()?)?;
            state.participants = TaskParticipants::Active {
                tree: Box::new(tree),
            };
            Ok(())
        })?;
        Ok(state.participants.tree()?.root().enrollment_commitment)
    }

    pub(crate) fn enroll_participant(
        &self,
        task_id: &str,
        transaction: &EnrollmentTransaction<'_>,
        parent: [u8; 32],
        proofs: &ParticipantEnrollmentProofs<'_>,
    ) -> Result<[u8; 32], ReleaseStateError> {
        let mut enrolled = None;
        self.update(task_id, |state| {
            let now = transaction.now()?;
            state.activated_task(transaction.pins, now)?;
            let tree = state.participants.tree_mut()?;
            let commitment = tree.enroll(transaction.context, parent, now, proofs)?;
            tree.parent_pins(commitment, transaction.now()?)?;
            enrolled = Some(commitment);
            Ok(())
        })?;
        enrolled.ok_or(ReleaseStateError::Corrupt)
    }

    /// Authenticated operator revocation; no proof, clock or provider I/O is
    /// needed to remove eligibility. Records and all charges remain retained.
    pub(crate) fn revoke_participant(
        &self,
        task_id: &str,
        participant: [u8; 32],
    ) -> Result<(), ReleaseStateError> {
        self.update(task_id, |state| {
            let tree = state.participants.tree_mut()?;
            tree.revoke(participant)?;
            if participant == tree.root().enrollment_commitment {
                state.revoked = true;
            }
            Ok(())
        })?;
        Ok(())
    }

    pub(crate) fn participant_pins(
        &self,
        task_id: &str,
        transaction: &EnrollmentTransaction<'_>,
        participant: [u8; 32],
    ) -> Result<crate::participant_enrollment::ParentEnrollmentPins, ReleaseStateError> {
        let path = self.key_path(task_id)?;
        let _lock = self.lock(rustix::fs::FlockOperation::LockShared)?;
        let state = Self::read(&path)?.ok_or(ReleaseStateError::Corrupt)?;
        if state.task_id != task_id {
            return Err(ReleaseStateError::Corrupt);
        }
        let now = transaction.now()?;
        state.activated_task(transaction.pins, now)?;
        state
            .participants
            .tree()?
            .parent_pins(participant, now)
            .map_err(Into::into)
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

    /// Every live timed transition obtains its own time under the same lock
    /// as replay, revocation and accounting. Pure state transitions still take
    /// explicit time; no provider/custody I/O runs inside this helper.
    fn update_timed(
        &self,
        task_id: &str,
        time: &crate::QualificationGate,
        change: impl FnOnce(&mut ReleaseTaskState, u64) -> Result<(), ReleaseStateError>,
    ) -> Result<ReleaseTaskState, ReleaseStateError> {
        self.update(task_id, |state| change(state, transaction_time(time)?))
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
        connection_subject: &str,
        time: &crate::QualificationGate,
    ) -> Result<ReleaseTaskState, ReleaseStateError> {
        self.update_timed(verified.request().task_id(), time, |state, now| {
            state.reserve_verified_request(
                verified,
                connection_id,
                connection_generation,
                connection_subject,
                now,
            )
        })
    }

    #[cfg(test)]
    pub(crate) fn reserve_write(
        &self,
        approved: &ApprovedTaskWrite,
        now: u64,
    ) -> Result<ReleaseTaskState, ReleaseStateError> {
        self.update(&approved.intent().task_id, |state| {
            state.reserve_write(approved, now)
        })
    }

    pub(crate) fn reserve_write_with_namespace(
        &self,
        approved: &ApprovedTaskWrite,
        verified: &crate::engine::VerifiedCommand,
        operator_namespace: &str,
        time: &crate::QualificationGate,
        valid_until: Option<u64>,
    ) -> Result<ReleaseTaskState, ReleaseStateError> {
        self.update_timed(&approved.intent().task_id, time, |state, now| {
            if valid_until.is_some_and(|deadline| now >= deadline) {
                return Err(ReleaseStateError::Inactive);
            }
            state.admit_write_participant(verified, approved.intent(), now)?;
            state.reserve_write_with_namespace(approved, operator_namespace, now)
        })
    }

    pub(crate) fn record_effect_plan(
        &self,
        task_id: &str,
        plan: &VerifiedEffectPlan,
        time: &crate::QualificationGate,
    ) -> Result<ReleaseTaskState, ReleaseStateError> {
        self.update_timed(task_id, time, |state, now| {
            state.record_effect_plan(plan, now)
        })
    }

    pub(crate) fn record_populate_preflight(
        &self,
        task_id: &str,
        preflight: &VerifiedPopulatePreflight,
        time: &crate::QualificationGate,
    ) -> Result<ReleaseTaskState, ReleaseStateError> {
        self.update_timed(task_id, time, |state, now| {
            state.record_populate_preflight(preflight, now)
        })
    }

    pub(crate) fn bind_created_child(
        &self,
        approved: &ApprovedTaskWrite,
        child: &VerifiedCreatedChild,
        response_digest: &[u8; 32],
        time: &crate::QualificationGate,
    ) -> Result<ReleaseTaskState, ReleaseStateError> {
        self.update_timed(&approved.intent().task_id, time, |state, now| {
            state.bind_created_child(approved, child, response_digest, now)
        })
    }

    pub(crate) fn bind_recovered_child(
        &self,
        approved: &ApprovedTaskWrite,
        plan: &VerifiedEffectPlan,
        child: &VerifiedCreatedChild,
        attestation: &VerifiedRecoveryAttestation,
        human_action_commitment: &str,
        time: &crate::QualificationGate,
    ) -> Result<ReleaseTaskState, ReleaseStateError> {
        self.update_timed(&approved.intent().task_id, time, |state, now| {
            state.bind_recovered_child(
                approved,
                plan,
                child,
                attestation,
                human_action_commitment,
                now,
            )
        })
    }

    #[cfg(test)]
    pub(crate) fn reserve_closed_request(
        &self,
        request: &ClosedReleaseRequest,
        verified_actors: &[String],
        connection_id: &str,
        connection_generation: u64,
        connection_subject: &str,
        now: u64,
    ) -> Result<ReleaseTaskState, ReleaseStateError> {
        self.update(request.task_id(), |state| {
            state.reserve_closed_request(
                request,
                verified_actors,
                connection_id,
                connection_generation,
                connection_subject,
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

    pub(crate) fn release_refused(
        &self,
        task_id: &str,
        operation_id: &str,
    ) -> Result<ReleaseTaskState, ReleaseStateError> {
        self.update(task_id, |state| state.release_refused(operation_id))
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
            initiator_principal: "jules-principal".to_owned(),
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
                connection_id: "jules-read".to_owned(),
                connection_generation: 3,
                connection_subject: "jules-subject".to_owned(),
            }],
        }
    }

    #[test]
    fn obsolete_or_cardless_journal_shape_is_refused() {
        let state = ReleaseTaskState::new(policy()).expect("state");
        let mut value: serde_json::Value =
            serde_json::from_slice(&state.encode().expect("canonical state")).expect("state JSON");
        value["schema"] = serde_json::json!("auths.gateway-agent-task-state/5");
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
            connection_id: "jules-read",
            connection_generation: 3,
            connection_subject: "jules-subject",
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
            connection_id: "jules-google".to_owned(),
            connection_generation: 3,
            connection_subject: "jules-subject".to_owned(),
        }];
        task
    }

    fn write_intent(operation_id: &str) -> ApprovedTaskWrite {
        ApprovedTaskWrite::from_test_intent(ExactWriteIntent {
            writer: crate::participant_enrollment::EnrolledParticipant::for_test(
                "agent",
                &[0x11; 32],
                1,
                1,
            ),
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
            task_id: state.task_id.clone(),
            task_commitment: state.task_commitment.clone(),
            operation_id: operation_id.to_owned(),
            recipient: state.operations[operation_id].recipient.clone(),
            released_bytes: state.operations[operation_id]
                .released_bytes
                .expect("entered bytes"),
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
        let (entered, _permit) = ledger
            .enter_release(
                "task-1",
                "read-1",
                b"Approved",
                &key,
                &crate::harness::time_gate(102),
            )
            .expect("charge");
        assert_eq!(entered.acknowledged_key_version("read-1", "source-1"), None);
        assert!(!entered.acknowledged_content_matches("read-1", "source-1", b"Approved", &key,));
        let mut wrong = acknowledgement(&entered, "read-1");
        wrong.recipient = "other-agent".to_owned();
        assert_eq!(
            ledger.acknowledge(&wrong).err(),
            Some(ReleaseStateError::Binding)
        );
        let mut wrong = acknowledgement(&entered, "read-1");
        wrong.task_commitment = "22".repeat(32);
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
            loaded.acknowledged_key_version("read-1", "source-1"),
            Some(2)
        );
        assert_eq!(loaded.acknowledged_key_version("read-1", "other"), None);
        assert!(loaded.acknowledged_content_matches("read-1", "source-1", b"Approved", &key));
        assert!(!loaded.acknowledged_content_matches("read-1", "other", b"Approved", &key));
        assert!(!loaded.acknowledged_content_matches("read-1", "source-1", b"Rejected", &key));
        assert!(!loaded.acknowledged_content_matches("read-2", "source-1", b"Approved", &key));
        let other_key = ReleaseCommitmentKey::new(2, Zeroizing::new([0x94; 32])).expect("key");
        assert!(!loaded.acknowledged_content_matches(
            "read-1",
            "source-1",
            b"Approved",
            &other_key,
        ));
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
        let evidence = ProvenNoSend::before_content("task-1", "read-1");
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
        let mut wrong_subject = call("read-1");
        wrong_subject.connection_subject = "different-subject";
        assert_eq!(
            state.reserve_provider_call(wrong_subject, 101),
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
    fn post_provider_policy_refusal_is_terminal_without_delivering_content() {
        let mut state = ReleaseTaskState::new(policy()).expect("policy");
        state
            .reserve_provider_call(call("read-1"), 101)
            .expect("call charged");
        state.release_refused("read-1").expect("withheld");
        assert_eq!(state.stage("read-1"), Some(ReleaseStage::ReleaseRefused));
        assert_eq!(state.counts(), (1, 0, 0));
        let key = ReleaseCommitmentKey::new(1, Zeroizing::new([1; 32])).expect("key");
        assert_eq!(
            state.enter_release("read-1", b"private", &key, 102),
            Err(ReleaseStateError::Stage)
        );
        assert_eq!(
            state.reserve_provider_call(call("read-1"), 103),
            Err(ReleaseStateError::Replay)
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
        let fixture = crate::task_enrollment::tests::Fixture::with_limits(false, 2, 1, 8);
        fixture.bootstrap().expect("native root");
        let path = fixture.path.clone();
        let ledger = FileReleaseTaskLedger::open(&path).expect("open");
        fixture
            .reserve_read(&fixture.read(false, "read-1"))
            .expect("call claim");
        let key = ReleaseCommitmentKey::new(1, Zeroizing::new([7; 32])).expect("key");
        let (entered, _permit) = ledger
            .enter_release(
                crate::task_enrollment::tests::TASK,
                "read-1",
                b"Approved",
                &key,
                &crate::harness::time_gate(crate::task_enrollment::tests::NOW),
            )
            .expect("durable charge");
        let digest = entered.digest().expect("canonical digest");
        drop(ledger);

        let restarted = FileReleaseTaskLedger::open(&path).expect("reopen");
        let loaded = restarted
            .load(crate::task_enrollment::tests::TASK)
            .expect("load")
            .expect("task");
        assert_eq!(loaded.digest().expect("digest"), digest);
        assert_eq!(loaded.counts(), (1, 1, 8));
        assert!(loaded.delivery_unknown("read-1"));
        let stored = fs::read(
            restarted
                .key_path(crate::task_enrollment::tests::TASK)
                .expect("path"),
        )
        .expect("stored state");
        assert!(
            !stored
                .windows(b"Approved".len())
                .any(|part| part == b"Approved")
        );
        assert_eq!(
            fixture.reserve_read(&fixture.read(false, "read-1")).err(),
            Some(ReleaseStateError::Replay)
        );
        assert_eq!(
            restarted
                .enter_release(
                    crate::task_enrollment::tests::TASK,
                    "read-1",
                    b"Approved",
                    &key,
                    &crate::harness::time_gate(crate::task_enrollment::tests::NOW)
                )
                .err(),
            Some(ReleaseStateError::Stage)
        );
        let loaded = restarted
            .load(crate::task_enrollment::tests::TASK)
            .expect("load")
            .expect("task");
        assert_eq!(loaded.counts(), (1, 1, 8));
        restarted
            .revoke(crate::task_enrollment::tests::TASK)
            .expect("revoke");
        assert_eq!(
            fixture.reserve_read(&fixture.read(false, "read-2")).err(),
            Some(ReleaseStateError::Inactive)
        );
    }

    #[test]
    fn no_send_receipt_survives_restart_without_refunding_or_replay() {
        let fixture = crate::task_enrollment::tests::Fixture::with_limits(false, 2, 1, 8);
        fixture.bootstrap().expect("native root");
        let path = fixture.path.clone();
        let ledger = FileReleaseTaskLedger::open(&path).expect("open");
        fixture
            .reserve_read(&fixture.read(false, "read-1"))
            .expect("call claim");
        let key = ReleaseCommitmentKey::new(1, Zeroizing::new([7; 32])).expect("key");
        ledger
            .enter_release(
                crate::task_enrollment::tests::TASK,
                "read-1",
                b"Approved",
                &key,
                &crate::harness::time_gate(crate::task_enrollment::tests::NOW),
            )
            .expect("durable charge");
        ledger
            .not_delivered(&ProvenNoSend::before_content(
                crate::task_enrollment::tests::TASK,
                "read-1",
            ))
            .expect("durable no-content proof");
        drop(ledger);

        let restarted = FileReleaseTaskLedger::open(&path).expect("reopen");
        let loaded = restarted
            .load(crate::task_enrollment::tests::TASK)
            .expect("load")
            .expect("task");
        assert_eq!(loaded.stage("read-1"), Some(ReleaseStage::NotDelivered));
        assert_eq!(loaded.counts(), (1, 1, 8));
        assert!(!loaded.delivery_unknown("read-1"));
        assert_eq!(
            fixture.reserve_read(&fixture.read(false, "read-1")).err(),
            Some(ReleaseStateError::Replay)
        );
        assert_eq!(
            restarted
                .enter_release(
                    crate::task_enrollment::tests::TASK,
                    "read-1",
                    b"Approved",
                    &key,
                    &crate::harness::time_gate(crate::task_enrollment::tests::NOW)
                )
                .err(),
            Some(ReleaseStateError::Stage)
        );
    }

    #[test]
    fn simultaneous_claim_has_one_winner_and_corruption_fails_closed() {
        let fixture = crate::task_enrollment::tests::Fixture::with_limits(false, 2, 1, 8);
        fixture.bootstrap().expect("native root");
        let path = fixture.path.clone();
        let barrier = Arc::new(Barrier::new(2));
        let outcomes = std::thread::scope(|scope| {
            let mut jobs = Vec::new();
            for _ in 0..2 {
                let barrier = Arc::clone(&barrier);
                let fixture = &fixture;
                jobs.push(scope.spawn(move || {
                    let verified = fixture.read(false, "read-1");
                    barrier.wait();
                    fixture.reserve_read(&verified)
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
            ledger
                .load(crate::task_enrollment::tests::TASK)
                .expect("load")
                .expect("task")
                .counts(),
            (1, 0, 0)
        );
        ledger
            .provider_unavailable(crate::task_enrollment::tests::TASK, "read-1")
            .expect("provider failed");
        assert_eq!(
            ledger
                .load(crate::task_enrollment::tests::TASK)
                .expect("load")
                .expect("task")
                .stage("read-1"),
            Some(ReleaseStage::ProviderUnavailable)
        );
        fs::write(
            ledger
                .key_path(crate::task_enrollment::tests::TASK)
                .expect("path"),
            b"{}",
        )
        .expect("tamper");
        assert_eq!(
            ledger.load(crate::task_enrollment::tests::TASK).err(),
            Some(ReleaseStateError::Corrupt)
        );
    }

    #[test]
    fn competing_release_entries_charge_only_one_budget_slot() {
        let fixture = crate::task_enrollment::tests::Fixture::with_limits(false, 2, 1, 8);
        fixture.bootstrap().expect("native root");
        let path = fixture.path.clone();
        let ledger = FileReleaseTaskLedger::open(&path).expect("open");
        fixture
            .reserve_read(&fixture.read(false, "read-1"))
            .expect("first call");
        fixture
            .reserve_read(&fixture.read(false, "read-2"))
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
                        .enter_release(
                            crate::task_enrollment::tests::TASK,
                            operation,
                            b"Approved",
                            &key,
                            &crate::harness::time_gate(crate::task_enrollment::tests::NOW),
                        )
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
            ledger
                .load(crate::task_enrollment::tests::TASK)
                .expect("load")
                .expect("task")
                .counts(),
            (2, 1, 8)
        );
    }

    fn clock_gate(clock: &Arc<crate::FixedClock>) -> crate::QualificationGate {
        crate::QualificationGate::new(
            crate::QualificationPolicy::Optional,
            None,
            None,
            Box::new(Arc::clone(clock)),
            auths_recipe_qualification::VerifierState::default(),
        )
    }

    /// Hold the actual journal lock while the caller starts with valid time.
    /// Advance to the exact exclusive deadline before allowing the transaction.
    fn advance_while_locked<T: Send>(
        ledger: &FileReleaseTaskLedger,
        clock: &crate::FixedClock,
        deadline: u64,
        change: impl FnOnce() -> T + Send,
    ) -> T {
        let lock = ledger
            .lock(rustix::fs::FlockOperation::LockExclusive)
            .unwrap();
        std::thread::scope(|scope| {
            let (started, ready) = std::sync::mpsc::channel();
            let worker = scope.spawn(move || {
                started.send(()).unwrap();
                change()
            });
            ready.recv().unwrap();
            clock.set(deadline);
            drop(lock);
            worker.join().unwrap()
        })
    }

    #[test]
    fn disclosure_samples_locked_time_but_late_evidence_keeps_its_charge() {
        let fixture = crate::task_enrollment::tests::Fixture::with_limits(false, 2, 1, 8);
        fixture.bootstrap().unwrap();
        fixture
            .reserve_read(&fixture.read(false, "read-1"))
            .unwrap();
        let ledger = fixture.ledger();
        let before = ledger
            .load(crate::task_enrollment::tests::TASK)
            .unwrap()
            .unwrap()
            .digest()
            .unwrap();
        let clock = fixture.clock.clone();
        let time = clock_gate(&clock);
        let key = ReleaseCommitmentKey::new(2, Zeroizing::new([0x93; 32])).unwrap();
        let enter = || {
            ledger.enter_release(
                crate::task_enrollment::tests::TASK,
                "read-1",
                b"Approved",
                &key,
                &time,
            )
        };
        assert_eq!(
            advance_while_locked(
                &ledger,
                &clock,
                crate::task_enrollment::tests::NOW + 600,
                enter
            )
            .err(),
            Some(ReleaseStateError::Inactive)
        );
        assert_eq!(
            ledger
                .load(crate::task_enrollment::tests::TASK)
                .unwrap()
                .unwrap()
                .digest()
                .unwrap(),
            before
        );
        clock.set(crate::task_enrollment::tests::NOW);
        clock.trust_is(false);
        assert_eq!(enter().err(), Some(ReleaseStateError::Inactive));
        assert_eq!(
            ledger
                .load(crate::task_enrollment::tests::TASK)
                .unwrap()
                .unwrap()
                .digest()
                .unwrap(),
            before
        );
        clock.trust_is(true);
        let (entered, _permit) = enter().unwrap();
        let evidence = acknowledgement(&entered, "read-1");
        clock.set(crate::task_enrollment::tests::NOW + 600);
        clock.trust_is(false);
        ledger.acknowledge(&evidence).unwrap();
        ledger.revoke(crate::task_enrollment::tests::TASK).unwrap();
        let retained = ledger
            .load(crate::task_enrollment::tests::TASK)
            .unwrap()
            .unwrap();
        assert_eq!(retained.counts(), (1, 1, 8));
        assert_eq!(
            retained.stage("read-1"),
            Some(ReleaseStage::AgentAcknowledged)
        );
    }

    #[test]
    fn exact_write_claim_spends_once_and_rejects_changed_task_or_connection() {
        let mut state = ReleaseTaskState::from_test_policy(write_policy()).expect("write task");
        let first = write_intent("edit-1");
        state.reserve_write(&first, 101).expect("first write claim");
        assert_eq!(state.write_count(), 1);
        let mut obsolete = serde_json::to_value(&state).expect("task JSON");
        obsolete["writes"]["edit-1"]
            .as_object_mut()
            .expect("write record")
            .remove("operator_namespace");
        assert!(
            serde_json::from_value::<ReleaseTaskState>(obsolete).is_err(),
            "obsolete claims without a recipe namespace must be rejected"
        );
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
    fn paired_recipes_share_one_durable_write_budget_after_restart() {
        let mut policy = write_policy();
        policy.max_writes = 2;
        policy.write_scopes.push(TaskWriteScope {
            handle: "project-a-folder".to_owned(),
            recipe_digest: "e".repeat(64),
            verb: TaskWriteVerb::Create,
            connection_id: "jules-google".to_owned(),
            connection_generation: 3,
            connection_subject: "jules-subject".to_owned(),
        });
        let root = tempfile::tempdir().expect("private directory");
        let path = fs::canonicalize(root.path())
            .expect("canonical directory")
            .join("task");
        let ledger = FileReleaseTaskLedger::open(&path).expect("open");
        ledger.initialize_policy(policy).expect("task");
        let mut create = write_intent("create-1").intent().clone();
        create.resource_handle = "project-a-folder".to_owned();
        create.recipe_digest = "e".repeat(64);
        create.verb = TaskWriteVerb::Create;
        let create = ApprovedTaskWrite::from_test_intent(create);
        ledger.reserve_write(&create, 101).expect("create reserved");
        drop(ledger);
        let reopened = FileReleaseTaskLedger::open(path).expect("reopen");
        reopened
            .reserve_write(&write_intent("edit-1"), 101)
            .expect("edit reserved under same task");
        assert_eq!(
            reopened.reserve_write(&create, 101).err(),
            Some(ReleaseStateError::Replay)
        );
        assert_eq!(
            reopened.reserve_write(&write_intent("edit-2"), 101).err(),
            Some(ReleaseStateError::Exhausted)
        );
        assert_eq!(
            reopened
                .load("task-1")
                .expect("load")
                .expect("task")
                .write_count(),
            2
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
    fn mixed_reads_and_writes_share_the_hard_operation_bound() {
        let mut policy = policy();
        policy.max_provider_calls = 64;
        policy.max_writes = 32;
        policy.write_scopes = write_policy().write_scopes;
        let mut state = ReleaseTaskState::from_test_policy(policy).unwrap();
        for index in 0..33 {
            state
                .reserve_provider_call(call(&format!("read-{index}")), 101)
                .unwrap();
        }
        for index in 0..31 {
            state
                .reserve_write(&write_intent(&format!("write-{index}")), 101)
                .unwrap();
        }
        assert_eq!(state.operation_count(), Some(64));
        let encoded = state.encode().unwrap();
        let mut reopened = ReleaseTaskState::decode(&encoded).unwrap();
        assert_eq!(
            reopened.reserve_provider_call(call("read-extra"), 101),
            Err(ReleaseStateError::Exhausted)
        );
        assert_eq!(
            reopened.reserve_write(&write_intent("write-extra"), 101),
            Err(ReleaseStateError::Exhausted)
        );
        assert_eq!(reopened.encode().unwrap(), encoded);
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
