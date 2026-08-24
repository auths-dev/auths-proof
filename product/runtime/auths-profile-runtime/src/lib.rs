//! Passive operation values exchanged between the common journal and concrete profiles.
//!
//! This crate deliberately defines no executor trait, callback registry, provider
//! dispatcher, or runtime installation mechanism. The generated build-time roster
//! calls concrete domain functions and uses these values only to preserve one common
//! durable order.

#![forbid(unsafe_code)]

use auths_connections::{ConnectionBinding, ProviderCredentialLease};
use auths_lifecycle::{
    OperationIdV1, OperationProfileV1, OperationProjectionV1, PreparationBindingV1,
};
use auths_stores::{
    JournalCompletionV1, JournalDecisionClassV1, JournalExecutionReceiptBasisV1, JournalRecordV1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

/// Immutable deployment-owned verifier configuration supplied to one profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileConfigurationBinding {
    profile_ref: String,
    format: String,
    canonical_bytes: Arc<[u8]>,
    sha256: [u8; 32],
    path: PathBuf,
    maximum_bytes: usize,
    file_device: u64,
    file_inode: u64,
    file_length: u64,
    file_modified_nanoseconds: i128,
}

impl ProfileConfigurationBinding {
    /// Constructs a binding only after the deployment loader validated storage and bytes.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn from_loader(
        profile_ref: String,
        format: String,
        canonical_bytes: Arc<[u8]>,
        sha256: [u8; 32],
        path: PathBuf,
        maximum_bytes: usize,
        file_device: u64,
        file_inode: u64,
        file_length: u64,
        file_modified_nanoseconds: i128,
    ) -> Self {
        Self {
            profile_ref,
            format,
            canonical_bytes,
            sha256,
            path,
            maximum_bytes,
            file_device,
            file_inode,
            file_length,
            file_modified_nanoseconds,
        }
    }

    #[must_use]
    pub fn profile_ref(&self) -> &str {
        &self.profile_ref
    }
    #[must_use]
    pub fn format(&self) -> &str {
        &self.format
    }
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
    #[must_use]
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
    #[must_use]
    pub const fn maximum_bytes(&self) -> usize {
        self.maximum_bytes
    }
    #[must_use]
    pub const fn file_device(&self) -> u64 {
        self.file_device
    }
    #[must_use]
    pub const fn file_inode(&self) -> u64 {
        self.file_inode
    }
    #[must_use]
    pub const fn file_length(&self) -> u64 {
        self.file_length
    }
    #[must_use]
    pub const fn file_modified_nanoseconds(&self) -> i128 {
        self.file_modified_nanoseconds
    }

    /// Returns whether two profile references are backed by the exact same
    /// immutable deployment source. The profile-reference strings themselves
    /// are deliberately excluded so paired preflight/effect profiles can
    /// share one configuration artifact.
    #[must_use]
    pub fn same_source(&self, other: &Self) -> bool {
        self.format == other.format
            && self.canonical_bytes == other.canonical_bytes
            && self.sha256 == other.sha256
            && self.path == other.path
            && self.maximum_bytes == other.maximum_bytes
            && self.file_device == other.file_device
            && self.file_inode == other.file_inode
            && self.file_length == other.file_length
            && self.file_modified_nanoseconds == other.file_modified_nanoseconds
    }
}

/// Immutable connection contract required by one concrete profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileConnectionRequirement {
    pub provider_kind: &'static str,
    pub contract: &'static str,
    pub descriptor_schema: &'static str,
    pub credential_scope: &'static str,
}

/// Rust-owned authority and caller facts supplied to a concrete profile.
#[derive(Clone, Copy)]
pub struct ProfileOperationContext<'a> {
    workload_id: &'a str,
    principal: &'a str,
    profile: &'a OperationProfileV1,
    authority_proof: &'a [u8],
    trusted_context: &'a [u8],
    authority_commitment: [u8; 32],
    configuration: Option<&'a ProfileConfigurationBinding>,
    profile_state_root: &'a Path,
}

impl<'a> ProfileOperationContext<'a> {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        workload_id: &'a str,
        principal: &'a str,
        profile: &'a OperationProfileV1,
        authority_proof: &'a [u8],
        trusted_context: &'a [u8],
        authority_commitment: [u8; 32],
        configuration: Option<&'a ProfileConfigurationBinding>,
        profile_state_root: &'a Path,
    ) -> Self {
        Self {
            workload_id,
            principal,
            profile,
            authority_proof,
            trusted_context,
            authority_commitment,
            configuration,
            profile_state_root,
        }
    }

    #[must_use]
    pub const fn workload_id(self) -> &'a str {
        self.workload_id
    }
    #[must_use]
    pub const fn principal(self) -> &'a str {
        self.principal
    }
    #[must_use]
    pub const fn profile(self) -> &'a OperationProfileV1 {
        self.profile
    }
    #[must_use]
    pub const fn authority_proof(self) -> &'a [u8] {
        self.authority_proof
    }
    #[must_use]
    pub const fn trusted_context(self) -> &'a [u8] {
        self.trusted_context
    }
    #[must_use]
    pub const fn authority_commitment(self) -> [u8; 32] {
        self.authority_commitment
    }
    #[must_use]
    pub const fn configuration(self) -> Option<&'a ProfileConfigurationBinding> {
        self.configuration
    }
    #[must_use]
    pub const fn profile_state_root(self) -> &'a Path {
        self.profile_state_root
    }
}

/// Result of effect-free concrete preparation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfilePreparation {
    pub canonical_input_commitment: [u8; 32],
    pub canonical_action_commitment: [u8; 32],
    pub configuration_commitment: [u8; 32],
    /// Exact canonical action bytes committed by the decision receipt.
    pub canonical_action: Vec<u8>,
    /// Stable profile-owned reason recorded in the decision receipt.
    pub decision_reason: String,
    pub profile_state: Vec<u8>,
    pub kind: ProfilePreparationKind,
}

/// Closed effect-free preparation result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfilePreparationKind {
    Ready,
    Denied { issue: Vec<u8> },
    Unavailable { issue: Vec<u8> },
}

/// One statically named profile-public receipt claim commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileReceiptClaimCommitment {
    /// Stable claim ID registered by the concrete profile.
    pub id: &'static str,
    /// Domain-separated SHA-256 commitment to the exact durable fact.
    pub sha256: [u8; 32],
}

/// Durable facts available both when minting and when reinspecting a decision receipt.
#[derive(Clone, Copy)]
pub struct ProfileDecisionReceiptFacts<'a> {
    /// Complete immutable preparation binding.
    pub binding: &'a PreparationBindingV1,
    /// Immutable common decision class.
    pub decision_class: JournalDecisionClassV1,
    /// Exact action commitment signed by the common receipt envelope.
    pub receipt_action_commitment: [u8; 32],
    /// Exact context commitment signed by the common receipt envelope.
    pub receipt_context_commitment: [u8; 32],
    /// Exact canonical profile-owned durable preparation state.
    pub profile_state: &'a [u8],
}

impl<'a> ProfileDecisionReceiptFacts<'a> {
    /// Reconstructs the decision facts from one durable operation record.
    #[must_use]
    pub fn from_record(record: &'a JournalRecordV1) -> Self {
        Self {
            binding: record.binding(),
            decision_class: record.decision_class(),
            receipt_action_commitment: *record.receipt_action_commitment(),
            receipt_context_commitment: *record.receipt_context_commitment(),
            profile_state: record.preparation_profile_state(),
        }
    }
}

/// Immutable mint-time facts used to build and later re-inspect execution claims.
#[derive(Clone, Copy)]
pub struct ProfileExecutionReceiptFacts<'a> {
    /// Complete immutable preparation binding.
    pub binding: &'a PreparationBindingV1,
    /// Stable operation identity bound by the execution lease.
    pub operation_id: &'a OperationIdV1,
    /// Exact profile state present when the execution receipt was minted.
    pub profile_state: &'a [u8],
    /// Immutable sealed command.
    pub sealed_command: &'a [u8],
    /// Provider result present at mint time, if any.
    pub provider_result: Option<&'a [u8]>,
    /// Exact observation prefix present at mint time.
    pub observations: &'a [Vec<u8>],
}

/// Bounded, recovery-capability-free facts needed to re-inspect profile receipts.
///
/// This is the only durable operation projection permitted to cross into live
/// qualification evidence. It deliberately excludes recovery handles, issues,
/// public result values, progress, receipt bytes, and journal concurrency state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileReceiptInspectionFactsV1 {
    binding: PreparationBindingV1,
    decision_class: JournalDecisionClassV1,
    receipt_action_commitment: [u8; 32],
    receipt_context_commitment: [u8; 32],
    preparation_profile_state: Vec<u8>,
    operation_id: OperationIdV1,
    execution_receipt_basis: Option<JournalExecutionReceiptBasisV1>,
    sealed_command: Option<Vec<u8>>,
    profile_state: Vec<u8>,
    provider_result: Option<Vec<u8>>,
    observations: Vec<Vec<u8>>,
    projection: OperationProjectionV1,
    provider_entered: bool,
    completion: Option<JournalCompletionV1>,
}

impl ProfileReceiptInspectionFactsV1 {
    /// Maximum bytes allowed in any one profile-owned opaque value.
    pub const MAXIMUM_VALUE_BYTES: usize = 1_048_576;
    /// Maximum ordered observations retained for independent inspection.
    pub const MAXIMUM_OBSERVATIONS: usize = 64;
    /// Maximum aggregate bytes across profile-owned opaque values.
    pub const MAXIMUM_AGGREGATE_BYTES: usize = 4_194_304;

    /// Captures only the exact receipt-inspection basis from a durable record.
    #[must_use]
    pub fn from_record(record: &JournalRecordV1) -> Self {
        Self {
            binding: record.binding().clone(),
            decision_class: record.decision_class(),
            receipt_action_commitment: *record.receipt_action_commitment(),
            receipt_context_commitment: *record.receipt_context_commitment(),
            preparation_profile_state: record.preparation_profile_state().to_vec(),
            operation_id: record.operation_id().clone(),
            execution_receipt_basis: record.execution_receipt_basis().cloned(),
            sealed_command: record.sealed_command().map(<[u8]>::to_vec),
            profile_state: record.profile_state().to_vec(),
            provider_result: record.provider_result().map(<[u8]>::to_vec),
            observations: record.observations().to_vec(),
            projection: record.projection(),
            provider_entered: record.provider_entered(),
            completion: record.completion(),
        }
    }

    /// Revalidates all decoded common values and bounded opaque payloads.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileRuntimeError`] when any common field, lifecycle shape,
    /// or bounded profile-owned payload is invalid.
    pub fn validate(&self) -> Result<(), ProfileRuntimeError> {
        self.binding
            .validate()
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        self.projection
            .validate()
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        if !matches!(
            OperationIdV1::parse(self.operation_id.as_str()),
            Ok(value) if value == self.operation_id
        ) || self.observations.len() > Self::MAXIMUM_OBSERVATIONS
            || self.execution_receipt_basis.is_some() != self.sealed_command.is_some()
        {
            return Err(ProfileRuntimeError::Invalid);
        }
        let mut values = vec![
            self.preparation_profile_state.as_slice(),
            self.profile_state.as_slice(),
        ];
        if let Some(command) = self.sealed_command.as_deref() {
            values.push(command);
        }
        if let Some(result) = self.provider_result.as_deref() {
            values.push(result);
        }
        if let Some(basis) = &self.execution_receipt_basis {
            values.push(basis.profile_state());
            if let Some(result) = basis.provider_result() {
                values.push(result);
            }
            values.extend(basis.observations().iter().map(Vec::as_slice));
        }
        values.extend(self.observations.iter().map(Vec::as_slice));
        if values
            .iter()
            .any(|value| value.len() > Self::MAXIMUM_VALUE_BYTES)
            || values
                .iter()
                .try_fold(0_usize, |total, value| total.checked_add(value.len()))
                .is_none_or(|total| total > Self::MAXIMUM_AGGREGATE_BYTES)
        {
            return Err(ProfileRuntimeError::Invalid);
        }
        Ok(())
    }

    #[must_use]
    pub const fn binding(&self) -> &PreparationBindingV1 {
        &self.binding
    }
    #[must_use]
    pub const fn operation_id(&self) -> &OperationIdV1 {
        &self.operation_id
    }
    #[must_use]
    pub fn profile_state(&self) -> &[u8] {
        &self.profile_state
    }
    #[must_use]
    pub fn sealed_command(&self) -> Option<&[u8]> {
        self.sealed_command.as_deref()
    }
    #[must_use]
    pub fn provider_result(&self) -> Option<&[u8]> {
        self.provider_result.as_deref()
    }
    #[must_use]
    pub fn observations(&self) -> &[Vec<u8>] {
        &self.observations
    }
    #[must_use]
    pub const fn projection(&self) -> OperationProjectionV1 {
        self.projection
    }
    #[must_use]
    pub const fn provider_entered(&self) -> bool {
        self.provider_entered
    }
    #[must_use]
    pub const fn completion(&self) -> Option<JournalCompletionV1> {
        self.completion
    }

    /// Reconstructs the immutable decision-claim mint facts.
    #[must_use]
    pub fn decision_facts(&self) -> ProfileDecisionReceiptFacts<'_> {
        ProfileDecisionReceiptFacts {
            binding: &self.binding,
            decision_class: self.decision_class,
            receipt_action_commitment: self.receipt_action_commitment,
            receipt_context_commitment: self.receipt_context_commitment,
            profile_state: &self.preparation_profile_state,
        }
    }

    /// Reconstructs the immutable execution-claim mint facts when present.
    #[must_use]
    pub fn execution_facts(&self) -> Option<ProfileExecutionReceiptFacts<'_>> {
        let basis = self.execution_receipt_basis.as_ref()?;
        Some(ProfileExecutionReceiptFacts {
            binding: &self.binding,
            operation_id: &self.operation_id,
            profile_state: basis.profile_state(),
            sealed_command: self.sealed_command.as_deref()?,
            provider_result: basis.provider_result(),
            observations: basis.observations(),
        })
    }
}

/// Complete input to one statically registered profile receipt inspector.
#[derive(Clone, Copy)]
pub struct ProfileReceiptInspection<'a> {
    /// Bounded persisted facts, including post-receipt reconciliation truth.
    pub facts: &'a ProfileReceiptInspectionFactsV1,
    /// Exact signed decision profile-claim envelope.
    pub decision_claims: &'a [u8],
    /// Exact signed execution profile-claim envelope when one exists.
    pub execution_claims: Option<&'a [u8]>,
}

/// Capability-free public commitment projection of one protected receipt inspection.
///
/// Raw profile state, commands, provider results, observations, principals,
/// connection identifiers, and provider identifiers never enter this value.
/// The protected `ReceiptVerifier` runs the full profile-owned inspector first;
/// this projection lets independent attesters bind that assertion to exact
/// receipt claims and common journal truth without retaining private bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileReceiptInspectionCommitmentsV1 {
    pub schema: String,
    pub operation_id: String,
    pub profile: String,
    pub runtime_contract_sha256: String,
    pub connection_generation: String,
    pub principal_sha256: String,
    pub canonical_input_sha256: String,
    pub idempotency_sha256: Option<String>,
    pub preparation_evidence_sha256: Option<String>,
    pub preparation_evidence_intent_sha256: Option<String>,
    pub connection_descriptor_sha256: String,
    pub connection_account_sha256: String,
    pub canonical_action_sha256: String,
    pub authority_sha256: String,
    pub configuration_sha256: String,
    pub preparation_sha256: String,
    pub decision_class: JournalDecisionClassV1,
    pub receipt_action_sha256: String,
    pub receipt_context_sha256: String,
    pub preparation_profile_state_sha256: String,
    pub sealed_command_sha256: Option<String>,
    pub profile_state_sha256: String,
    pub provider_result_sha256: Option<String>,
    pub observation_sha256s: Vec<String>,
    pub execution_basis_profile_state_sha256: Option<String>,
    pub execution_basis_provider_result_sha256: Option<String>,
    pub execution_basis_observation_sha256s: Option<Vec<String>>,
    pub projection: OperationProjectionV1,
    pub provider_entered: bool,
    pub completion: Option<JournalCompletionV1>,
    pub decision_profile_claims_sha256: String,
    pub execution_profile_claims_sha256: Option<String>,
}

impl ProfileReceiptInspectionCommitmentsV1 {
    /// Builds the public projection only from a fully validated raw inspection.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileRuntimeError`] when the raw facts, receipt claims, or
    /// derived public commitment shape is invalid.
    pub fn from_inspection(
        inspection: ProfileReceiptInspection<'_>,
    ) -> Result<Self, ProfileRuntimeError> {
        inspection.facts.validate()?;
        if inspection.decision_claims.is_empty()
            || inspection.execution_claims.is_some_and(<[u8]>::is_empty)
        {
            return Err(ProfileRuntimeError::Invalid);
        }
        let binding = inspection.facts.binding();
        let profile = binding.profile();
        let connection = binding.connection().ok_or(ProfileRuntimeError::Invalid)?;
        let decision = inspection.facts.decision_facts();
        let execution = inspection.facts.execution_facts();
        if execution.is_some() != inspection.execution_claims.is_some() {
            return Err(ProfileRuntimeError::Invalid);
        }
        let value = Self {
            schema: "auths.profile-receipt-inspection-commitments/1".into(),
            operation_id: inspection.facts.operation_id().as_str().into(),
            profile: format!("{}/{}", profile.id(), profile.version()),
            runtime_contract_sha256: commitment(profile.runtime_contract_digest()),
            connection_generation: connection.generation().to_string(),
            principal_sha256: digest(binding.principal().as_bytes()),
            canonical_input_sha256: commitment(binding.canonical_input_commitment()),
            idempotency_sha256: binding.idempotency_commitment().map(commitment),
            preparation_evidence_sha256: binding.preparation_evidence_commitment().map(commitment),
            preparation_evidence_intent_sha256: binding
                .preparation_evidence_intent_commitment()
                .map(commitment),
            connection_descriptor_sha256: commitment(connection.descriptor_commitment()),
            connection_account_sha256: commitment(connection.account_commitment()),
            canonical_action_sha256: commitment(binding.canonical_action_commitment()),
            authority_sha256: commitment(binding.authority_commitment()),
            configuration_sha256: commitment(binding.configuration_commitment()),
            preparation_sha256: commitment(binding.preparation_commitment()),
            decision_class: decision.decision_class,
            receipt_action_sha256: commitment(&decision.receipt_action_commitment),
            receipt_context_sha256: commitment(&decision.receipt_context_commitment),
            preparation_profile_state_sha256: digest(decision.profile_state),
            sealed_command_sha256: inspection.facts.sealed_command().map(digest),
            profile_state_sha256: digest(inspection.facts.profile_state()),
            provider_result_sha256: inspection.facts.provider_result().map(digest),
            observation_sha256s: inspection
                .facts
                .observations()
                .iter()
                .map(|value| digest(value))
                .collect(),
            execution_basis_profile_state_sha256: execution
                .map(|facts| digest(facts.profile_state)),
            execution_basis_provider_result_sha256: execution
                .and_then(|facts| facts.provider_result.map(digest)),
            execution_basis_observation_sha256s: execution.map(|facts| {
                facts
                    .observations
                    .iter()
                    .map(|value| digest(value))
                    .collect()
            }),
            projection: inspection.facts.projection(),
            provider_entered: inspection.facts.provider_entered(),
            completion: inspection.facts.completion(),
            decision_profile_claims_sha256: digest(inspection.decision_claims),
            execution_profile_claims_sha256: inspection.execution_claims.map(digest),
        };
        value.validate()?;
        Ok(value)
    }

    /// Revalidates the fixed public grammar and cross-field presence rules.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileRuntimeError`] when any commitment or cross-field
    /// presence invariant is invalid.
    pub fn validate(&self) -> Result<(), ProfileRuntimeError> {
        let (profile_id, version) = self
            .profile
            .rsplit_once('/')
            .ok_or(ProfileRuntimeError::Invalid)?;
        OperationProfileV1::new(
            profile_id,
            version
                .parse::<u16>()
                .map_err(|_| ProfileRuntimeError::Invalid)?,
            [1; 32],
        )
        .map_err(|_| ProfileRuntimeError::Invalid)?;
        OperationIdV1::parse(&self.operation_id).map_err(|_| ProfileRuntimeError::Invalid)?;
        self.projection
            .validate()
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        let required = [
            &self.runtime_contract_sha256,
            &self.principal_sha256,
            &self.canonical_input_sha256,
            &self.connection_descriptor_sha256,
            &self.connection_account_sha256,
            &self.canonical_action_sha256,
            &self.authority_sha256,
            &self.configuration_sha256,
            &self.preparation_sha256,
            &self.receipt_action_sha256,
            &self.receipt_context_sha256,
            &self.preparation_profile_state_sha256,
            &self.profile_state_sha256,
            &self.decision_profile_claims_sha256,
        ];
        let optional = [
            self.idempotency_sha256.as_ref(),
            self.preparation_evidence_sha256.as_ref(),
            self.preparation_evidence_intent_sha256.as_ref(),
            self.sealed_command_sha256.as_ref(),
            self.provider_result_sha256.as_ref(),
            self.execution_basis_profile_state_sha256.as_ref(),
            self.execution_basis_provider_result_sha256.as_ref(),
            self.execution_profile_claims_sha256.as_ref(),
        ];
        let execution_present = self.execution_basis_profile_state_sha256.is_some();
        if self.schema != "auths.profile-receipt-inspection-commitments/1"
            || self
                .connection_generation
                .parse::<u64>()
                .ok()
                .is_none_or(|value| value == 0)
            || required.into_iter().any(|value| !sha256(value))
            || optional.into_iter().flatten().any(|value| !sha256(value))
            || self.observation_sha256s.len() > Self::MAXIMUM_OBSERVATIONS
            || self.observation_sha256s.iter().any(|value| !sha256(value))
            || execution_present != self.execution_basis_observation_sha256s.is_some()
            || execution_present != self.execution_profile_claims_sha256.is_some()
            || execution_present && self.sealed_command_sha256.is_none()
            || self
                .execution_basis_observation_sha256s
                .as_ref()
                .is_some_and(|values| {
                    values.len() > Self::MAXIMUM_OBSERVATIONS
                        || values.iter().any(|value| !sha256(value))
                })
            || (!execution_present && self.execution_basis_provider_result_sha256.is_some())
        {
            return Err(ProfileRuntimeError::Invalid);
        }
        Ok(())
    }

    const MAXIMUM_OBSERVATIONS: usize = 64;
}

fn digest(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn commitment(value: &[u8; 32]) -> String {
    hex::encode(value)
}

fn sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

impl<'a> ProfileExecutionReceiptFacts<'a> {
    /// Captures the current facts before the receipt boundary is persisted.
    #[must_use]
    pub fn at_mint(record: &'a JournalRecordV1) -> Option<Self> {
        Some(Self {
            binding: record.binding(),
            operation_id: record.operation_id(),
            profile_state: record.profile_state(),
            sealed_command: record.sealed_command()?,
            provider_result: record.provider_result(),
            observations: record.observations(),
        })
    }

    /// Reconstructs the exact immutable mint-time basis from a durable record.
    #[must_use]
    pub fn from_record(record: &'a JournalRecordV1) -> Option<Self> {
        let basis = record.execution_receipt_basis()?;
        Some(Self {
            binding: record.binding(),
            operation_id: record.operation_id(),
            profile_state: basis.profile_state(),
            sealed_command: record.sealed_command()?,
            provider_result: basis.provider_result(),
            observations: basis.observations(),
        })
    }
}

/// Computes one unambiguous domain-separated profile receipt claim commitment.
///
/// Concrete profiles own the domain label and fact selection; common code only
/// owns the collision-resistant length-delimited framing.
#[must_use]
pub fn profile_receipt_claim_digest(domain: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"AUTHS-PROFILE-RECEIPT-CLAIM\0\x01");
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update((parts.len() as u64).to_be_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Profile-sealed command produced only after fresh critical rereads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedProfileCall {
    pub command: Vec<u8>,
    pub profile_state: Vec<u8>,
}

/// Profile-owned critical reread committed only after the sealed command is
/// durable and before common code leases credentials or marks provider entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfilePreEntryRecheck {
    pub profile_state: Vec<u8>,
}

/// Bounded authenticated evidence acquired only by a manifest-declared
/// connection companion and persisted behind an opaque common lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparationEvidenceAcquisition {
    pub bytes: Vec<u8>,
    pub authority_action_commitment: [u8; 32],
}

/// Concrete observation plus its profile-owned effect conclusion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileObservation {
    pub bytes: Vec<u8>,
    pub conclusion: ProfileConclusion,
}

/// Closed profile-owned conclusion projected into common lifecycle state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileConclusion {
    Completed {
        value: Vec<u8>,
        profile_state: Vec<u8>,
    },
    Partial {
        value: Vec<u8>,
        issue: Vec<u8>,
        profile_state: Vec<u8>,
    },
    NotApplied {
        issue: Vec<u8>,
        profile_state: Vec<u8>,
    },
    RecoveryRequired {
        issue: Vec<u8>,
        progress: Option<Vec<u8>>,
        profile_state: Vec<u8>,
    },
}

/// Failure at one statically linked concrete profile boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileRuntimeError {
    PreEntry(Vec<u8>),
    /// A protected post-command reread is not available yet. Common code must
    /// keep the durable not-entered checkpoint and permit only retrying the
    /// original execute attempt.
    PreEntryPending,
    Possible(Vec<u8>),
    /// Provider entry is durable and the domain also completed a durable
    /// post-call state transition before reporting an indeterminate result.
    /// Common code must persist these exact canonical profile-state bytes
    /// before minting the linked indeterminate execution receipt.
    PossibleWithProfileState {
        issue: Vec<u8>,
        profile_state: Vec<u8>,
    },
    Invalid,
}

/// Borrowed inputs for sealing one already prepared command.
pub struct SealProfileCallInput<'a> {
    pub context: ProfileOperationContext<'a>,
    pub record: &'a JournalRecordV1,
    pub now_unix_seconds: u64,
}

/// Borrowed inputs for the post-command, pre-credential critical reread.
pub struct PreEntryRecheckInput<'a> {
    pub context: ProfileOperationContext<'a>,
    pub record: &'a JournalRecordV1,
    pub now_unix_seconds: u64,
}

/// Borrowed inputs for one manifest-declared connection-owned evidence lease.
pub struct PreparationEvidenceAuthorizationInput<'a> {
    pub context: ProfileOperationContext<'a>,
    pub workflow_id: &'a str,
    pub profile_input: &'a [u8],
    pub connection: Option<&'a ConnectionBinding>,
    pub now_unix_seconds: u64,
}

/// Borrowed inputs for the protected read after preliminary authorization.
pub struct PreparationEvidenceAcquisitionInput<'a> {
    pub context: ProfileOperationContext<'a>,
    pub workflow_id: &'a str,
    pub profile_input: &'a [u8],
    pub connection: Option<&'a ConnectionBinding>,
    pub authority_action_commitment: [u8; 32],
    pub now_unix_seconds: u64,
}

/// Borrowed inputs for releasing profile-owned state while the common journal
/// still durably proves that provider entry never occurred.
pub struct ReleaseProfileCallInput<'a> {
    pub context: ProfileOperationContext<'a>,
    pub record: &'a JournalRecordV1,
}

/// Borrowed inputs for one provider call.
pub struct CallProviderInput<'a> {
    pub context: ProfileOperationContext<'a>,
    pub call: &'a SealedProfileCall,
    pub credential: Option<&'a ProviderCredentialLease>,
    pub now_unix_seconds: u64,
}

/// Borrowed inputs for classifying a durable provider result.
pub struct ObserveProviderResultInput<'a> {
    pub context: ProfileOperationContext<'a>,
    pub record: &'a JournalRecordV1,
    pub provider_result: &'a [u8],
    pub now_unix_seconds: u64,
}

/// Borrowed inputs for reconciling one possible-effect operation.
pub struct ReconcileProfileInput<'a> {
    pub context: ProfileOperationContext<'a>,
    pub record: &'a JournalRecordV1,
    pub credential: Option<&'a ProviderCredentialLease>,
    pub now_unix_seconds: u64,
}

/// Borrowed inputs for effect-free profile preparation.
pub struct PrepareProfileInput<'a> {
    pub context: ProfileOperationContext<'a>,
    /// Stable common-owned workflow identity derived from the business
    /// idempotency commitment, or from the request identity when absent.
    pub workflow_id: &'a str,
    pub profile_input: &'a [u8],
    pub connection: Option<&'a ConnectionBinding>,
    /// Exact authenticated evidence resolved locally from a durable opaque
    /// lease. Profiles without a manifest declaration always receive `None`.
    pub preparation_evidence: Option<&'a [u8]>,
    pub now_unix_seconds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_lifecycle::{
        ClientRequestIdV1, ConnectionBindingCommitmentsV1, OperationEffectV1, OperationStateV1,
    };

    #[test]
    fn public_receipt_inspection_preserves_common_decision_commitments() {
        let profile = OperationProfileV1::new("auths.stripe.refund", 1, [1; 32]).unwrap();
        let connection =
            ConnectionBindingCommitmentsV1::new("primary", "connection-1", 7, [6; 32], [7; 32])
                .unwrap();
        let binding = PreparationBindingV1::new(
            "did:key:workload",
            profile,
            ClientRequestIdV1::from_bytes([2; 16]),
            Some([3; 32]),
            [4; 32],
            Some([5; 32]),
            Some([8; 32]),
            Some(connection),
            [9; 32],
            [10; 32],
            [11; 32],
        )
        .unwrap();
        let operation_id = OperationIdV1::from_random_bytes([12; 16]).unwrap();
        let facts = ProfileReceiptInspectionFactsV1 {
            binding,
            decision_class: JournalDecisionClassV1::Authorized,
            receipt_action_commitment: [13; 32],
            receipt_context_commitment: [14; 32],
            preparation_profile_state: b"private-preparation-state".to_vec(),
            operation_id,
            execution_receipt_basis: None,
            sealed_command: None,
            profile_state: b"private-profile-state".to_vec(),
            provider_result: None,
            observations: Vec::new(),
            projection: OperationProjectionV1::new(
                OperationStateV1::Ready,
                OperationEffectV1::NotApplied,
                false,
            )
            .unwrap(),
            provider_entered: false,
            completion: None,
        };
        let public =
            ProfileReceiptInspectionCommitmentsV1::from_inspection(ProfileReceiptInspection {
                facts: &facts,
                decision_claims: b"decision-profile-claims",
                execution_claims: None,
            })
            .unwrap();
        let binding = facts.binding();
        let connection = binding.connection().unwrap();

        assert_eq!(
            public.runtime_contract_sha256,
            hex::encode(binding.profile().runtime_contract_digest())
        );
        assert_eq!(
            public.canonical_input_sha256,
            hex::encode(binding.canonical_input_commitment())
        );
        assert_eq!(public.idempotency_sha256, Some(hex::encode([3; 32])));
        assert_eq!(
            public.preparation_evidence_sha256,
            Some(hex::encode([5; 32]))
        );
        assert_eq!(
            public.preparation_evidence_intent_sha256,
            Some(hex::encode([8; 32]))
        );
        assert_eq!(
            public.connection_descriptor_sha256,
            hex::encode(connection.descriptor_commitment())
        );
        assert_eq!(
            public.connection_account_sha256,
            hex::encode(connection.account_commitment())
        );
        assert_eq!(
            public.canonical_action_sha256,
            hex::encode(binding.canonical_action_commitment())
        );
        assert_eq!(
            public.authority_sha256,
            hex::encode(binding.authority_commitment())
        );
        assert_eq!(
            public.configuration_sha256,
            hex::encode(binding.configuration_commitment())
        );
        assert_eq!(
            public.preparation_sha256,
            hex::encode(binding.preparation_commitment())
        );
        assert_eq!(public.receipt_action_sha256, hex::encode([13; 32]));
        assert_eq!(public.receipt_context_sha256, hex::encode([14; 32]));
    }
}
