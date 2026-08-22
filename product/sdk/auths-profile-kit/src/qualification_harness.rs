//! Qualification-only provider adapter and crash-evidence contracts.
//!
//! These types are used by protected qualification tooling. Production local
//! agent construction never accepts this trait as a callback or runtime port.

// These bounded qualification DTOs expose one fail-closed harness error; the
// shared validator owns the detailed reason so callers cannot branch on it.
#![allow(clippy::missing_errors_doc)]

use crate::qualification::QualificationTarget;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const MAX_SCENARIOS: usize = 256;
const MAX_VECTOR_BYTES: usize = 16_777_216;
const MAX_RECEIPTS: usize = 16;
const MAX_RUN_REFERENCES: usize = 64;

/// Closed crash boundaries exercised by the external qualification supervisor.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationFailpoint {
    /// Before a durable decision exists.
    BeforeDecision,
    /// After the decision is durable.
    AfterDecision,
    /// After a domain reservation is durable.
    AfterReservation,
    /// After the sealed provider command is durable.
    AfterCommand,
    /// After the critical fresh re-read succeeds.
    AfterReread,
    /// After a credential is leased but before provider entry.
    AfterLease,
    /// After the durable provider-entry marker.
    AfterEntryMarker,
    /// After the provider request may have been committed.
    AfterRequestWrite,
    /// After the durable provider result is written.
    AfterProviderResult,
    /// After durable observation.
    AfterObservation,
    /// After the linked execution receipt is durable and before terminal projection.
    AfterExecutionReceipt,
    /// After the terminal result is durable but before response delivery.
    AfterTerminal,
}

impl QualificationFailpoint {
    /// Complete canonical failpoint roster in lifecycle order.
    pub const ALL: [Self; 12] = [
        Self::BeforeDecision,
        Self::AfterDecision,
        Self::AfterReservation,
        Self::AfterCommand,
        Self::AfterReread,
        Self::AfterLease,
        Self::AfterEntryMarker,
        Self::AfterRequestWrite,
        Self::AfterProviderResult,
        Self::AfterObservation,
        Self::AfterExecutionReceipt,
        Self::AfterTerminal,
    ];

    /// Returns the one canonical command/manifest token for this failpoint.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BeforeDecision => "before-decision",
            Self::AfterDecision => "after-decision",
            Self::AfterReservation => "after-reservation",
            Self::AfterCommand => "after-command",
            Self::AfterReread => "after-reread",
            Self::AfterLease => "after-lease",
            Self::AfterEntryMarker => "after-entry-marker",
            Self::AfterRequestWrite => "after-request-write",
            Self::AfterProviderResult => "after-provider-result",
            Self::AfterObservation => "after-observation",
            Self::AfterExecutionReceipt => "after-execution-receipt",
            Self::AfterTerminal => "after-terminal",
        }
    }

    /// Parses only the closed canonical failpoint vocabulary.
    #[must_use]
    pub fn from_token(value: &str) -> Option<Self> {
        Some(match value {
            "before-decision" => Self::BeforeDecision,
            "after-decision" => Self::AfterDecision,
            "after-reservation" => Self::AfterReservation,
            "after-command" => Self::AfterCommand,
            "after-reread" => Self::AfterReread,
            "after-lease" => Self::AfterLease,
            "after-entry-marker" => Self::AfterEntryMarker,
            "after-request-write" => Self::AfterRequestWrite,
            "after-provider-result" => Self::AfterProviderResult,
            "after-observation" => Self::AfterObservation,
            "after-execution-receipt" => Self::AfterExecutionReceipt,
            "after-terminal" => Self::AfterTerminal,
            _ => return None,
        })
    }
}

/// Closed effect truth used by common and domain qualification reports.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationEffect {
    /// Independent evidence proves the provider effect did not happen.
    NotApplied,
    /// The provider effect may have happened and blind retry is forbidden.
    Possible,
    /// Independent evidence proves the exact provider effect happened.
    Applied,
}

/// Exact common ordering counters recorded for every scenario.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationCounters {
    /// Durable profile-owned reservation acquisitions.
    pub reservation_writes: u32,
    /// Idempotent releases of unused reservations.
    pub reservation_releases: u32,
    /// Terminal successful disposition, including a preflight capability
    /// handed to its paired effect operation.
    pub reservation_consumptions: u32,
    /// Unresolved reservations retained against quota while effect is possible.
    pub reservation_retentions: u32,
    /// Fresh connection/configuration re-reads.
    pub connection_rereads: u32,
    /// Credential lease attempts.
    pub credential_lease_attempts: u32,
    /// Successful credential leases.
    pub credential_leases: u32,
    /// Closed credential leases.
    pub credential_lease_closes: u32,
    /// Durable provider-entry markers.
    pub provider_entry_markers: u32,
    /// Provider mutation calls.
    pub provider_calls: u32,
    /// Provider request bodies committed by the protected transport proxy.
    pub provider_request_writes: u32,
    /// Provider responses observed by the protected transport proxy.
    pub provider_responses: u32,
    /// Durable provider-result writes.
    pub durable_provider_results: u32,
    /// Durable observations.
    pub observations: u32,
    /// Durable receipt writes.
    pub receipt_writes: u32,
}

impl QualificationCounters {
    /// Validates the common single-operation lifecycle algebra.
    ///
    /// Scenario-specific validation may further narrow these bounds, but no
    /// qualification report may contradict the durable common lifecycle.
    #[must_use]
    pub fn valid_for_instance(
        &self,
        effect: QualificationEffect,
        has_sealed_command: bool,
        has_provider_result: bool,
        reconciled: bool,
    ) -> bool {
        if self.credential_leases > self.credential_lease_attempts
            || self.reservation_releases > self.reservation_writes
            || self.reservation_consumptions > self.reservation_writes
            || self.reservation_retentions > self.reservation_writes
            || self
                .reservation_releases
                .checked_add(self.reservation_consumptions)
                .and_then(|value| value.checked_add(self.reservation_retentions))
                != Some(self.reservation_writes)
            || self.credential_lease_closes != self.credential_leases
            || self.provider_entry_markers > self.credential_leases
            || self.provider_calls > self.provider_entry_markers
            || self.provider_request_writes != self.provider_calls
            || self.provider_responses > self.provider_request_writes
            || self.durable_provider_results > self.provider_calls
            || self.connection_rereads > 1
            || self.reservation_writes > 1
            || self.reservation_releases > 1
            || self.reservation_consumptions > 1
            || self.reservation_retentions > 1
            || self.credential_lease_attempts > 1
            || self.credential_leases > 1
            || self.credential_lease_closes > 1
            || self.provider_entry_markers > 1
            || self.provider_calls > 1
            || self.provider_request_writes > 1
            || self.provider_responses > 1
            || self.durable_provider_results > 1
            || self.receipt_writes > 2
            || has_provider_result != (self.durable_provider_results == 1)
            || (!has_sealed_command
                && (self.connection_rereads != 0
                    || self.credential_lease_attempts != 0
                    || self.credential_leases != 0
                    || self.credential_lease_closes != 0
                    || self.provider_entry_markers != 0
                    || self.provider_calls != 0
                    || self.provider_request_writes != 0
                    || self.provider_responses != 0
                    || self.durable_provider_results != 0
                    || self.observations != 0))
        {
            return false;
        }

        match effect {
            QualificationEffect::Applied => {
                has_sealed_command
                    && (has_provider_result || reconciled)
                    && (self.reservation_writes == 0 || self.reservation_consumptions == 1)
                    && self.connection_rereads == 1
                    && self.credential_lease_attempts == 1
                    && self.credential_leases == 1
                    && self.credential_lease_closes == 1
                    && self.provider_entry_markers == 1
                    && self.provider_calls == 1
                    && self.provider_request_writes == 1
                    && self.durable_provider_results == u32::from(has_provider_result)
                    && self.observations >= 1
                    && self.receipt_writes == 2
            }
            QualificationEffect::Possible => {
                !reconciled
                    && has_sealed_command
                    && (self.reservation_writes == 0 || self.reservation_retentions == 1)
                    && self.connection_rereads == 1
                    && self.credential_lease_attempts == 1
                    && self.credential_leases == 1
                    && self.credential_lease_closes == 1
                    && self.provider_entry_markers == 1
                    && self.provider_request_writes == self.provider_calls
                    && self.receipt_writes >= 1
            }
            QualificationEffect::NotApplied => {
                (!reconciled || self.observations >= 1)
                    && (self.reservation_writes == 0
                        || self
                            .reservation_releases
                            .checked_add(self.reservation_consumptions)
                            == Some(1))
            }
        }
    }
}

/// Release-owned immutable context for one protected qualification run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationRunContext {
    /// Canonical GitHub repository identifier.
    pub repository_id: String,
    /// Exact tested Git revision.
    pub candidate_revision: String,
    /// Exact compilation target.
    pub target: QualificationTarget,
    /// Manifest-owned protected environment.
    pub protected_environment: String,
    /// GitHub Actions run identifier.
    pub run_id: String,
    /// GitHub Actions run attempt.
    pub run_attempt: u32,
    /// Exact immutable provider-matrix row executed by this job.
    pub provider_run_id: String,
}

/// Canonical secret-free handoff from candidate collection to protected observation.
///
/// The reference contains provider-owned namespace/identity commitments only.
/// It cannot carry a credential, command, callback, filesystem path, or opaque
/// application-controlled environment map.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationRunReference {
    /// Fixed schema identity.
    pub schema: String,
    /// Exact provider domain.
    pub domain: String,
    /// Exact qualified target.
    pub target: QualificationTarget,
    /// Exact candidate revision.
    pub candidate_revision: String,
    /// Canonical GitHub repository identifier.
    pub repository_id: String,
    /// Protected workflow run identity.
    pub run_id: String,
    /// Protected workflow attempt.
    pub run_attempt: u32,
    /// Exact immutable provider-matrix row executed by this candidate job.
    pub provider_run_id: String,
    /// Run-owned provider namespace, safe to disclose to protected jobs.
    pub provider_namespace: String,
    /// SHA-256 commitment to the onboarded connection alias.
    pub connection_alias_sha256: String,
    /// Byte-sorted provider resource identifiers or commitments.
    pub resource_references: Vec<String>,
    /// Byte-sorted connection generations used by this run.
    pub connection_generations: Vec<String>,
}

/// One protected, capability-free setup handoff consumed by collection.
///
/// Provider setup owns resource creation and connection onboarding. The
/// no-secret collection process receives only this canonical public projection
/// and cannot reconstruct a setup, mutation, read, observer, or cleanup
/// credential from it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationSetupHandoffV1 {
    /// Fixed schema identity.
    pub schema: String,
    /// Exact immutable workflow/run context used for setup.
    pub run_context: QualificationRunContext,
    /// Exact provider domain selected by the reviewed matrix row.
    pub domain: String,
    /// Public connection alias already onboarded by the protected setup zone.
    pub connection_alias: String,
    /// Secret-free provider resource and cleanup reference.
    pub run_reference: QualificationRunReference,
    /// Exact program-ordered scenario inputs selected by protected setup.
    pub vectors: Vec<QualificationSetupVectorV1>,
}

/// Canonical public input for one reviewed qualification scenario.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationSetupVectorV1 {
    /// Stable scenario ID from the reviewed matrix.
    pub id: String,
    /// Exact executable scenario program committed by the ledger plan.
    pub scenario_program: crate::QualificationScenarioProgramV1,
    /// Exact case-scoped public SDK inputs in scenario-program order.
    pub cases: Vec<QualificationSetupCaseV1>,
    /// Optional closed crash boundary fixed by the reviewed scenario ID.
    pub failpoint: Option<QualificationFailpoint>,
}

/// One protected-setup public input bound to a reviewed scenario case.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationSetupCaseV1 {
    pub case_id: String,
    pub input_base64url: String,
}

/// Immutable protected input supplied to one domain-owned setup implementation.
///
/// The setup credential is deliberately excluded. It is handed to
/// [`QualificationProtectedSetup::setup`] as a separate zeroizable byte slice
/// and can never become part of this serializable public policy projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationProtectedSetupInput<'a> {
    /// Exact workflow-owned run context.
    pub run_context: &'a QualificationRunContext,
    /// Exact public connection alias selected from the checked agent config.
    pub connection_alias: &'a str,
    /// Canonical public connection descriptor supplied to `CredentialBroker`.
    pub connection_descriptor: &'a [u8],
    /// Exact provider version selected by the reviewed matrix row.
    pub provider_version: &'a str,
    /// Exact provider artifact commitment selected by the reviewed matrix row.
    pub provider_artifact_sha256: &'a str,
    /// Exact byte-sorted scenario roster selected by that row.
    pub scenario_ids: &'a [String],
    /// Canonical public profile configurations selected by the checked agent
    /// configuration, keyed by exact semantic profile.
    pub profile_configurations: &'a std::collections::BTreeMap<String, Vec<u8>>,
}

/// Exact secret-free candidate collection retained only as a mismatch oracle.
///
/// Protected source processes and the common ledger remain authoritative for
/// every lifecycle fact. This closed envelope merely keeps the installed
/// client's public projections together with the provider-row handoff that
/// produced them.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationCandidateCollectionV1 {
    pub schema: String,
    pub run_reference: QualificationRunReference,
    pub scenarios: Vec<QualificationCollectedScenario>,
}

/// One candidate-collected invocation passed as untrusted evidence to the observer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationCollectedScenario {
    /// Scenario ID from the closed manifest.
    pub scenario_id: String,
    /// Exact provider-matrix row that produced this invocation.
    pub provider_run_id: String,
    /// Closed failpoint selected by the external supervisor, when any.
    pub failpoint: Option<QualificationFailpoint>,
    /// Ordered public operations exercised by the family workflow.
    pub operations: Vec<QualificationCollectedOperation>,
}

/// One public operation exercised through the installed generated client.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationCollectedOperation {
    /// Operation's role in the atomic family workflow.
    pub role: QualificationOperationRole,
    /// Exact semantic profile reference used by this operation.
    pub profile: String,
}

/// Closed public operation roles in an atomic profile family.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationOperationRole {
    /// Protected discovery or planning operation.
    Preflight,
    /// Effect operation that consumes the protected handle.
    Effect,
}

/// Closed public client calls used by qualification scenarios.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationAttemptKind {
    Execute,
    Replay,
    Conflict,
    Status,
    Recover,
    CancelAfterWrite,
}

/// Closed public outcome projections.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationOutcomeKind {
    Denied,
    Unavailable,
    Completed,
    Partial,
    NotApplied,
    RecoveryRequired,
    Conflict,
}

/// Closed terminal completion classes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationCompletion {
    Fresh,
    Replayed,
    Reconciled,
}

/// Protected cleanup facts that must be independently observed before signing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationCleanupEvidence {
    /// Every run-scoped provider resource was destroyed.
    pub provider_resources_destroyed: bool,
    /// The run-scoped Auths connection was disabled or removed.
    pub connection_disabled: bool,
    /// All run-scoped provider credentials were revoked or rotated.
    pub credentials_revoked: bool,
    /// Residual run-scoped provider resources after cleanup.
    pub residual_resource_count: u32,
}

/// Static metadata implemented by every domain qualification adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationAdapterMetadata {
    /// Domain token.
    pub domain: &'static str,
    /// Atomic semantic profile family.
    pub family: &'static [&'static str],
    /// Closed supported qualification targets.
    pub targets: &'static [QualificationTarget],
    /// Manifest-owned protected environment.
    pub protected_environment: &'static str,
    /// Byte-sorted domain scenario IDs.
    pub scenarios: &'static [&'static str],
}

/// One bounded domain-owned scenario vector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationVector {
    /// Stable common or domain scenario ID.
    pub id: String,
    /// Exact reviewed executable scenario program.
    pub scenario_program: crate::QualificationScenarioProgramV1,
    /// Exact reviewed case inputs interpreted only by the static adapter.
    pub cases: Vec<QualificationCaseVector>,
    /// Optional closed crash boundary selected by the common supervisor.
    pub failpoint: Option<QualificationFailpoint>,
}

/// One decoded bounded public SDK case input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationCaseVector {
    pub case_id: String,
    pub input: Vec<u8>,
}

/// Independent provider observation that does not trust the Auths result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationProviderTruth {
    /// Exact operation observed.
    pub operation_id: String,
    /// Exact provider-matrix run observed.
    pub provider_run_id: String,
    /// Observed effect class.
    pub effect: QualificationEffect,
    /// Number of provider mutation calls for this operation.
    pub provider_calls: u32,
    /// Domain-defined redacted commitment to exact provider truth.
    pub commitment: [u8; 32],
    /// Canonical domain-owned redacted facts.
    pub domain_facts: Vec<u8>,
    /// Exact observed provider version.
    pub provider_version: String,
    /// SHA-256 of the exact provider image/binary/artifact.
    pub provider_artifact_sha256: String,
}

/// Schema-bounded protected projection for one public operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationRedactedOperation {
    /// Atomic family role.
    pub role: QualificationOperationRole,
    /// Exact semantic profile.
    pub profile: String,
    /// Protected created operation instances.
    pub instances: Vec<QualificationRedactedOperationInstance>,
    /// Protected public attempt projections.
    pub attempts: Vec<QualificationRedactedAttempt>,
}

/// Shared protected journal projection for one durable operation instance.
///
/// This contains only common lifecycle facts. Provider truth is observed
/// independently and is added by the protected qualification harness after
/// this record has been validated.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationCommonOperationInstanceEvidence {
    pub operation_id: String,
    pub connection_generation: String,
    pub principal_sha256: String,
    pub connection_alias_sha256: Option<String>,
    pub connection_id_sha256: Option<String>,
    pub connection_descriptor_sha256: Option<String>,
    pub connection_account_sha256: Option<String>,
    pub credential_scope_sha256: Option<String>,
    pub canonical_input_sha256: String,
    pub idempotency_sha256: Option<String>,
    pub canonical_action_sha256: String,
    pub receipt_action_sha256: String,
    pub receipt_context_sha256: String,
    pub authority_sha256: String,
    pub configuration_sha256: String,
    pub runtime_contract_sha256: String,
    pub preparation_sha256: String,
    pub decision_class: QualificationReceiptDecisionClass,
    pub reconciled: bool,
    pub effect: QualificationEffect,
    pub counters: QualificationCounters,
    pub sealed_command_sha256: Option<String>,
    pub provider_result_sha256: Option<String>,
    pub execution_result_sha256: Option<String>,
}

/// Protected evidence for one durable operation instance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationRedactedOperationInstance {
    pub operation_id: String,
    pub connection_generation: String,
    pub principal_sha256: String,
    pub connection_alias_sha256: Option<String>,
    pub connection_id_sha256: Option<String>,
    pub connection_descriptor_sha256: Option<String>,
    pub connection_account_sha256: Option<String>,
    pub credential_scope_sha256: Option<String>,
    pub canonical_input_sha256: String,
    pub idempotency_sha256: Option<String>,
    pub canonical_action_sha256: String,
    pub receipt_action_sha256: String,
    pub receipt_context_sha256: String,
    pub authority_sha256: String,
    pub configuration_sha256: String,
    pub runtime_contract_sha256: String,
    pub preparation_sha256: String,
    pub decision_class: QualificationReceiptDecisionClass,
    pub reconciled: bool,
    pub effect: QualificationEffect,
    pub counters: QualificationCounters,
    pub provider_truth_sha256: String,
    pub sealed_command_sha256: Option<String>,
    pub provider_result_sha256: Option<String>,
    pub execution_result_sha256: Option<String>,
}

/// Common receipt verification result passed to the domain payload validator.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationCommonReceiptClaims {
    pub sequence: u8,
    /// Exact public SDK attempt to which this receipt state belongs.
    pub attempt_sequence: u8,
    /// Exact request ID observed by the shared protected request log.
    pub request_id: String,
    pub operation_id: String,
    pub profile: String,
    pub connection_generation: String,
    pub state: QualificationReceiptState,
    pub decision_receipt_id: Option<String>,
    pub execution_receipt_id: Option<String>,
    /// Signed decision action commitment, when a decision is present.
    pub decision_action_sha256: Option<String>,
    /// Signed decision context commitment, when a decision is present.
    pub decision_context_sha256: Option<String>,
    /// Signed decision class, when a decision is present.
    pub decision_class: Option<QualificationReceiptDecisionClass>,
    /// Signed execution command commitment, when execution is present.
    pub execution_command_sha256: Option<String>,
    /// Signed execution result commitment, when execution is present.
    pub execution_result_sha256: Option<String>,
    /// Signed execution outcome, when execution is present.
    pub execution_outcome: Option<QualificationReceiptExecutionOutcome>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationReceiptState {
    None,
    DecisionOnly,
    LinkedExecution,
}

/// Closed decision class decoded from a natively verified receipt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationReceiptDecisionClass {
    Authorized,
    Denied,
    Indeterminate,
}

/// Closed execution outcome decoded from a natively verified receipt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationReceiptExecutionOutcome {
    Succeeded,
    Failed,
    Indeterminate,
}

/// Canonical qualification-only export produced by the shared protected
/// journal/request/receipt reader. Provider adapters never construct this
/// lifecycle projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationCommonPhaseEvidence {
    pub schema: String,
    pub repository_id: String,
    pub workflow_run_id: String,
    pub workflow_run_attempt: u32,
    pub candidate_revision: String,
    pub domain: String,
    pub target: QualificationTarget,
    pub protected_environment: String,
    pub provider_run_id: String,
    pub scenario_id: String,
    pub phase_index: u8,
    pub role: QualificationOperationRole,
    pub profile: String,
    pub failpoint: Option<QualificationFailpoint>,
    pub operation_plan_sha256: String,
    pub scenario_program_sha256: String,
    pub ledger_id: String,
    pub session_nonce_sha256: String,
    pub supervisor_generation: u32,
    pub first_event_sequence: u32,
    pub last_event_sequence: u32,
    pub instances: Vec<QualificationCommonOperationEvidence>,
    pub attempts: Vec<QualificationRedactedAttempt>,
}

/// One shared durable operation and its native receipt-verification claims.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationCommonOperationEvidence {
    pub projection: QualificationCommonOperationInstanceEvidence,
    pub receipt_claims: Vec<QualificationCommonReceiptClaims>,
}

impl QualificationCommonReceiptClaims {
    /// Validates the exact receipt-state/ID relationship derived by the
    /// shared native portable-receipt verifier.
    pub fn validate(&self) -> Result<(), QualificationHarnessError> {
        let decision_present = self.decision_receipt_id.as_deref().is_some_and(receipt_id)
            && self.decision_action_sha256.as_deref().is_some_and(digest)
            && self.decision_context_sha256.as_deref().is_some_and(digest)
            && self.decision_class.is_some();
        let execution_present = self.execution_receipt_id.as_deref().is_some_and(receipt_id)
            && self.execution_command_sha256.as_deref().is_some_and(digest)
            && self.execution_result_sha256.as_deref().is_none_or(digest)
            && self.execution_outcome.is_some();
        let valid_state = match self.state {
            QualificationReceiptState::None => {
                self.decision_receipt_id.is_none()
                    && self.execution_receipt_id.is_none()
                    && self.decision_action_sha256.is_none()
                    && self.decision_context_sha256.is_none()
                    && self.decision_class.is_none()
                    && self.execution_command_sha256.is_none()
                    && self.execution_result_sha256.is_none()
                    && self.execution_outcome.is_none()
            }
            QualificationReceiptState::DecisionOnly => {
                decision_present
                    && self.execution_receipt_id.is_none()
                    && self.execution_command_sha256.is_none()
                    && self.execution_result_sha256.is_none()
                    && self.execution_outcome.is_none()
            }
            QualificationReceiptState::LinkedExecution => {
                decision_present
                    && execution_present
                    && self.decision_receipt_id != self.execution_receipt_id
            }
        };
        if self.sequence == 0
            || self.attempt_sequence == 0
            || !registered_token(&self.request_id)
            || !registered_token(&self.operation_id)
            || !semantic_profile(&self.profile)
            || !decimal_token(&self.connection_generation)
            || !valid_state
        {
            return Err(QualificationHarnessError::Redaction);
        }
        Ok(())
    }
}

/// Protected bounded public outcome projection for one SDK call.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationRedactedAttempt {
    pub sequence: u8,
    pub kind: QualificationAttemptKind,
    pub request_id: String,
    pub operation_id: Option<String>,
    pub recovery_id: Option<String>,
    pub outcome: QualificationOutcomeKind,
    pub completion: Option<QualificationCompletion>,
    pub idempotency_sha256: Option<String>,
    pub request_input_sha256: String,
    pub preparation_input_sha256: Option<String>,
    pub principal_sha256: String,
    pub connection_alias_sha256: Option<String>,
    pub connection_generation: Option<String>,
    pub requested_scope_sha256: Option<String>,
    pub configuration_sha256: Option<String>,
    pub sealed_command_sha256: Option<String>,
    pub error_code: Option<String>,
    pub issue_metadata_sha256: Option<String>,
    pub result_sha256: String,
    pub receipt_ids: Vec<String>,
}

/// Returns the exact authenticated SDK-attempt count for a reviewed common
/// scenario that must be rejected before a durable operation exists.
///
/// The controller, protected readers, and staging verifier all consume this
/// closed policy so an operation-free scenario cannot drift between them.
#[must_use]
pub fn qualification_pre_admission_attempt_count(scenario_id: &str) -> Option<usize> {
    match scenario_id {
        "boundary-plus-one"
        | "configuration-mismatch"
        | "connection-substitution"
        | "principal-substitution" => Some(1),
        "malformed-input" => Some(4),
        _ => None,
    }
}

/// Protected `ClientProxy` endpoints for one phase-scoped generated SDK call.
///
/// The common qualification harness owns these endpoints. Domain adapters may
/// use them only to construct the installed client for the current phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationPhaseClient {
    agent_socket: String,
    result_socket: String,
    scenario_program: Option<crate::QualificationScenarioProgramV1>,
    phase_index: Option<u8>,
    role: Option<QualificationOperationRole>,
    installed: Option<QualificationInstalledClient>,
}

/// Exact checked installed-client process selected by the common harness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationInstalledClient {
    python: String,
    profile_source: String,
    working_directory: String,
    python_module: String,
    client_class: String,
    group: String,
    method: String,
    input_type: String,
    deadline_at_unix_seconds: u64,
}

/// Bounded canonical public outcome returned by the installed generated SDK.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationInstalledClientOutcome {
    /// Closed public SDK outcome kind.
    pub kind: String,
    /// Generated public success value; absent for every non-completed outcome.
    pub value: Option<serde_json::Value>,
}

impl QualificationPhaseClient {
    /// Constructs one exact phase-scoped endpoint pair.
    pub fn new(
        agent_socket: String,
        result_socket: String,
    ) -> Result<Self, QualificationHarnessError> {
        let agent = std::path::Path::new(&agent_socket);
        let result = std::path::Path::new(&result_socket);
        if !agent.is_absolute()
            || !result.is_absolute()
            || agent == result
            || agent.parent() != result.parent()
            || agent.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
            || result.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
            || agent_socket.contains('\0')
            || result_socket.contains('\0')
        {
            return Err(QualificationHarnessError::InvalidPhaseClient);
        }
        Ok(Self {
            agent_socket,
            result_socket,
            scenario_program: None,
            phase_index: None,
            role: None,
            installed: None,
        })
    }

    /// Binds the installed invocation to the exact immutable phase selected by
    /// the protected controller. Scenario-specific retry/concurrency behavior
    /// is common harness policy and cannot be selected by a domain adapter.
    pub fn with_reviewed_phase(
        mut self,
        scenario_program: crate::QualificationScenarioProgramV1,
        phase_index: u8,
        role: QualificationOperationRole,
    ) -> Result<Self, QualificationHarnessError> {
        if !lower_token(scenario_program.id())
            || scenario_program.sha256().is_err()
            || !(1..=8).contains(&phase_index)
        {
            return Err(QualificationHarnessError::InvalidPhaseClient);
        }
        self.scenario_program = Some(scenario_program);
        self.phase_index = Some(phase_index);
        self.role = Some(role);
        Ok(self)
    }

    /// Attaches the one common checked installed-client process contract.
    pub fn with_installed_client(
        mut self,
        installed: QualificationInstalledClient,
    ) -> Result<Self, QualificationHarnessError> {
        installed.validate()?;
        self.installed = Some(installed);
        Ok(self)
    }

    /// `ClientProxy` request socket supplied to the generated SDK.
    #[must_use]
    pub fn agent_socket(&self) -> &str {
        &self.agent_socket
    }

    /// `ClientProxy` terminal-result socket supplied only to qualification SDKs.
    #[must_use]
    pub fn result_socket(&self) -> &str {
        &self.result_socket
    }

    /// Invokes one generated `*_outcome` method over the protected sockets.
    pub fn invoke_installed(
        &self,
        connection_alias: &str,
        canonical_input: &[u8],
    ) -> Result<QualificationInstalledClientOutcome, QualificationHarnessError> {
        if !registered_token(connection_alias) {
            return Err(QualificationHarnessError::Invocation);
        }
        let installed = self
            .installed
            .as_ref()
            .ok_or(QualificationHarnessError::InvalidPhaseClient)?;
        if self.scenario_program.is_none() || self.phase_index.is_none() || self.role.is_none() {
            return Err(QualificationHarnessError::InvalidPhaseClient);
        }
        installed.invoke(self, connection_alias, canonical_input)
    }
}

impl QualificationInstalledClient {
    /// Constructs a manifest-derived installed-client invocation contract.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        python: String,
        profile_source: String,
        working_directory: String,
        python_module: String,
        client_class: String,
        group: String,
        method: String,
        input_type: String,
        deadline_at_unix_seconds: u64,
    ) -> Result<Self, QualificationHarnessError> {
        let value = Self {
            python,
            profile_source,
            working_directory,
            python_module,
            client_class,
            group,
            method,
            input_type,
            deadline_at_unix_seconds,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), QualificationHarnessError> {
        let paths = [
            self.python.as_str(),
            self.profile_source.as_str(),
            self.working_directory.as_str(),
        ];
        if paths.iter().any(|value| !safe_absolute_path(value))
            || !python_module(&self.python_module)
            || !public_class_name(&self.client_class)
            || !python_identifier(&self.group)
            || !python_identifier(&self.method)
            || !public_class_name(&self.input_type)
            || self.deadline_at_unix_seconds == 0
        {
            return Err(QualificationHarnessError::InvalidPhaseClient);
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn invoke(
        &self,
        phase: &QualificationPhaseClient,
        connection_alias: &str,
        canonical_input: &[u8],
    ) -> Result<QualificationInstalledClientOutcome, QualificationHarnessError> {
        use std::io::{Read as _, Write as _};
        use std::process::Stdio;
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        if canonical_input.is_empty()
            || canonical_input.len() > MAX_VECTOR_BYTES
            || serde_json::from_slice::<serde_json::Value>(canonical_input)
                .ok()
                .and_then(|value| serde_json_canonicalizer::to_vec(&value).ok())
                .as_deref()
                != Some(canonical_input)
        {
            return Err(QualificationHarnessError::Invocation);
        }
        let phase_index = phase
            .phase_index
            .ok_or(QualificationHarnessError::InvalidPhaseClient)?
            .to_string();
        let scenario_program = phase
            .scenario_program
            .as_ref()
            .ok_or(QualificationHarnessError::InvalidPhaseClient)?;
        let scenario_program_json = String::from_utf8(
            serde_json_canonicalizer::to_vec(scenario_program)
                .map_err(|_| QualificationHarnessError::InvalidPhaseClient)?,
        )
        .map_err(|_| QualificationHarnessError::InvalidPhaseClient)?;
        let role = match phase
            .role
            .ok_or(QualificationHarnessError::InvalidPhaseClient)?
        {
            QualificationOperationRole::Preflight => "preflight",
            QualificationOperationRole::Effect => "effect",
        };
        let mut child = std::process::Command::new(&self.python)
            .args([
                "-I",
                "-c",
                INSTALLED_QUALIFICATION_CLIENT,
                &self.profile_source,
                &self.python_module,
                &self.client_class,
                &self.group,
                &self.method,
                &self.input_type,
                phase.agent_socket(),
                connection_alias,
                scenario_program.id(),
                &phase_index,
                role,
                &scenario_program_json,
            ])
            .current_dir(&self.working_directory)
            .env_clear()
            .env("PYTHONNOUSERSITE", "1")
            .env(
                "AUTHS_QUALIFICATION_CLIENT_RESULT_SOCKET",
                phase.result_socket(),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|_| QualificationHarnessError::Invocation)?;
        let mut input = child
            .stdin
            .take()
            .ok_or(QualificationHarnessError::Invocation)?;
        input
            .write_all(canonical_input)
            .map_err(|_| QualificationHarnessError::Invocation)?;
        drop(input);
        let output = child
            .stdout
            .take()
            .ok_or(QualificationHarnessError::Invocation)?;
        let reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            output
                .take(u64::try_from(MAX_VECTOR_BYTES + 1).unwrap_or(u64::MAX))
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        });
        let status = loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|_| QualificationHarnessError::Invocation)?
            {
                break status;
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| QualificationHarnessError::Invocation)?
                .as_secs();
            if now >= self.deadline_at_unix_seconds {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(QualificationHarnessError::Invocation);
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let bytes = reader
            .join()
            .map_err(|_| QualificationHarnessError::Invocation)?
            .map_err(|_| QualificationHarnessError::Invocation)?;
        if !status.success() || bytes.is_empty() || bytes.len() > MAX_VECTOR_BYTES {
            return Err(QualificationHarnessError::Invocation);
        }
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| QualificationHarnessError::Invocation)?;
        if serde_json_canonicalizer::to_vec(&value)
            .map_err(|_| QualificationHarnessError::Invocation)?
            != bytes
        {
            return Err(QualificationHarnessError::Invocation);
        }
        let object = value
            .as_object()
            .ok_or(QualificationHarnessError::Invocation)?;
        if object.keys().map(String::as_str).collect::<Vec<_>>()
            != if object.contains_key("value") {
                vec!["kind", "value"]
            } else {
                vec!["kind"]
            }
        {
            return Err(QualificationHarnessError::Invocation);
        }
        let kind = object
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .filter(|kind| {
                matches!(
                    *kind,
                    "completed"
                        | "denied"
                        | "unavailable"
                        | "conflict"
                        | "not-applied"
                        | "partial"
                        | "recovery-required"
                        | "receipt-integrity-failed"
                )
            })
            .ok_or(QualificationHarnessError::Invocation)?
            .to_owned();
        let value = object.get("value").cloned();
        if (kind == "completed") != value.is_some() {
            return Err(QualificationHarnessError::Invocation);
        }
        Ok(QualificationInstalledClientOutcome { kind, value })
    }
}

fn safe_absolute_path(value: &str) -> bool {
    let path = std::path::Path::new(value);
    path.is_absolute()
        && !value.contains('\0')
        && !path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
}

fn python_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && (value.as_bytes()[0].is_ascii_lowercase() || value.as_bytes()[0] == b'_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn python_module(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.split('.').all(python_identifier)
}

fn public_class_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_uppercase()
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

const INSTALLED_QUALIFICATION_CLIENT: &str = r#"
import asyncio, copy, dataclasses, importlib, json, sys
from auths._cbor import encode as encode_cbor

source, module_name, client_name, group_name, method_name, input_name, socket, connection, scenario, phase_index, role, program_json = sys.argv[1:]
phase_index = int(phase_index)
program = json.loads(program_json)
if program.get("id") != scenario or not isinstance(program.get("cases"), list) or role not in ("preflight", "effect"):
    raise ValueError("installed-client scenario program differs from selected scenario")
sys.path.insert(0, source)
import auths
module = importlib.import_module(module_name)
api = module._PROFILE_API

def snake(name):
    out = []
    for c in name:
        if c.isupper():
            out.extend(("_", c.lower()))
        else:
            out.append(c)
    return "".join(out).lstrip("_")

def convert(value, spec):
    kind = spec["kind"]
    if kind == "ref":
        target = api["types"][spec["name"]]
        if target["kind"] == "enum":
            return value
        if target["kind"] != "record" or not isinstance(value, dict):
            raise ValueError("invalid installed-client record")
        expected = {field["name"] for field in target["fields"]}
        if set(value) != expected:
            raise ValueError("installed-client record fields differ")
        cls = getattr(module, spec["name"])
        return cls(**{
            snake(field["name"]): convert(value[field["name"]], field["value"])
            for field in target["fields"]
        })
    if kind == "list":
        if not isinstance(value, list):
            raise ValueError("invalid installed-client list")
        return tuple(convert(item, spec["value"]) for item in value)
    return value

def public(value):
    if dataclasses.is_dataclass(value):
        return {field.name: public(getattr(value, field.name)) for field in dataclasses.fields(value)}
    if isinstance(value, tuple):
        return [public(item) for item in value]
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    raise ValueError("installed-client outcome contains an unsupported value")

def completion(outcome):
    if outcome.kind == "completed":
        return outcome.value.auths.completion
    return getattr(outcome, "completion", None)

def operation_id(outcome):
    if outcome.kind == "completed":
        return outcome.value.auths.operation_id
    return getattr(outcome, "operation_id", None)

def stable_completed_value(outcome):
    value = public(outcome.value)
    metadata = value.get("auths") if isinstance(value, dict) else None
    if not isinstance(metadata, dict):
        raise ValueError("completed outcome omits operation metadata")
    stable = copy.deepcopy(value)
    stable["auths"].pop("completion", None)
    return stable

def conflict_input(request):
    changed = copy.deepcopy(request)
    for key in ("paymentIntent", "tenantKey", "workspace", "preparedUpdate", "preparedPlan"):
        value = changed.get(key)
        if isinstance(value, str) and value:
            changed[key] = value + "x"
            return changed
    assignments = changed.get("assignments")
    if isinstance(assignments, list) and assignments and isinstance(assignments[0], dict):
        value = assignments[0].get("value")
        if isinstance(value, str):
            assignments[0]["value"] = value + "x"
            return changed
    amount = changed.get("amount")
    if isinstance(amount, int) and amount > 0:
        changed["amount"] = amount + 1
        return changed
    raise ValueError("installed-client scenario has no safe conflict mutation")

async def main():
    raw = sys.stdin.buffer.read(16_777_217)
    if not raw or len(raw) > 16_777_216:
        raise ValueError("installed-client input exceeds bound")
    request = json.loads(raw)
    canonical = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    if canonical != raw or not isinstance(request, dict):
        raise ValueError("installed-client input is not canonical")
    async with auths.connect(options=auths.ClientOptions(agent_socket=socket)) as session:
        client = getattr(module, client_name)(session, connection=connection)
        group = getattr(client, group_name)
        method = getattr(group, method_name + "_outcome")
        bound_profile = group._profile
        input_spec = {"kind": "ref", "name": input_name}

        async def invoke(value, key):
            input_value = convert(value, input_spec)
            kwargs = {
                field.name: getattr(input_value, field.name)
                for field in dataclasses.fields(input_value)
            }
            return await method(
                **kwargs,
                options=auths.OperationOptions(idempotency_key=key),
            )

        intent = "aq:" + scenario + ":" + str(phase_index)
        if scenario == "boundary-plus-one":
            outcome = await bound_profile._qualification_invoke_encoded_outcome(
                encode_cbor(request),
                options=auths.OperationOptions(idempotency_key=intent),
            )
            if outcome.kind != "unavailable" or operation_id(outcome) is not None:
                raise ValueError("installed-client boundary-plus-one reached admission")
        elif scenario == "malformed-input":
            if not isinstance(request, dict) or not request:
                raise ValueError("malformed-input vector has no record shape")
            missing = copy.deepcopy(request)
            missing.pop(sorted(missing)[0])
            unknown = copy.deepcopy(request)
            unknown["__unknown"] = 1
            hostile = (
                b"\x18\x00",                       # noncanonical integer encoding
                encode_cbor(unknown),               # unknown field
                encode_cbor(missing),               # missing field
                b"\xa2\x61x\x01\x61x\x02",       # duplicate map field
            )
            outcomes = []
            for index, encoded in enumerate(hostile):
                candidate = await bound_profile._qualification_invoke_encoded_outcome(
                    encoded,
                    options=auths.OperationOptions(
                        idempotency_key=intent + ":" + str(index),
                    ),
                )
                if candidate.kind != "unavailable" or operation_id(candidate) is not None:
                    raise ValueError("installed-client malformed input reached admission")
                outcomes.append(candidate)
            outcome = outcomes[-1]
        elif scenario == "stale-evidence":
            edge = await invoke(request, intent + ":edge")
            stale = await invoke(request, intent + ":stale")
            if (
                edge.kind != "completed"
                or operation_id(edge) is None
                or completion(edge) not in ("fresh", "reconciled")
                or stale.kind != "unavailable"
                or operation_id(stale) is not None
            ):
                raise ValueError("installed-client freshness boundary was not exact")
            outcome = edge
        elif scenario == "replay":
            first = await invoke(request, intent)
            second = await invoke(request, intent)
            if (
                first.kind != "completed"
                or second.kind != "completed"
                or stable_completed_value(first) != stable_completed_value(second)
                or operation_id(first) != operation_id(second)
                or completion(first) not in ("fresh", "reconciled")
                or completion(second) != "replayed"
            ):
                raise ValueError("installed-client replay changed durable result identity")
            outcome = second
        elif scenario == "changed-input-conflict":
            first = await invoke(request, intent)
            second = await invoke(conflict_input(request), intent)
            if (
                first.kind != "completed"
                or second.kind != "conflict"
                or operation_id(first) != operation_id(second)
            ):
                raise ValueError("installed-client changed-input conflict was not exact")
            outcome = first
        elif scenario == "quota-final-capacity" and (
            client_name == "Stripe" or phase_index == 2
        ):
            contenders = await asyncio.gather(
                invoke(request, intent + ":a"),
                invoke(request, intent + ":b"),
            )
            winners = [candidate for candidate in contenders if candidate.kind == "completed"]
            if len(winners) != 1:
                raise ValueError("installed-client final capacity did not select one winner")
            outcome = winners[0]
        else:
            outcome = await invoke(request, intent)
    response = {"kind": outcome.kind}
    if outcome.kind == "completed":
        response["value"] = public(outcome.value)
    encoded = json.dumps(response, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    if len(encoded) > 16_777_216:
        raise ValueError("installed-client output exceeds bound")
    sys.stdout.buffer.write(encoded)

asyncio.run(main())
"#;

/// Candidate collection interface implemented once per provider domain.
///
/// This no-secret phase may invoke the production vertical through the
/// protected agent, but it cannot provision, onboard, observe authoritative
/// provider truth, sign evidence, or clean resources.
pub trait QualificationCollectionAdapter {
    /// Domain-owned capability-free environment, never serialized by the common harness.
    type Environment;

    /// Returns immutable adapter metadata.
    fn metadata(&self) -> QualificationAdapterMetadata;

    /// Opens the exact protected setup handoff without receiving credentials.
    fn open(
        &self,
        context: &QualificationRunContext,
        handoff: &QualificationSetupHandoffV1,
    ) -> Result<Self::Environment, QualificationHarnessError>;

    /// Invokes exactly one reviewed phase through the installed generated client.
    ///
    /// The common harness owns phase ordering and the protected controller gate.
    /// Mutable domain state may retain a bounded preflight capability for the
    /// immediately following effect phase, but the adapter cannot batch phases.
    #[allow(clippy::too_many_arguments)]
    fn invoke_phase(
        &self,
        environment: &mut Self::Environment,
        client: &QualificationPhaseClient,
        connection_alias: &str,
        vector: &QualificationVector,
        phase_index: u8,
        role: QualificationOperationRole,
        profile: &str,
    ) -> Result<QualificationCollectedOperation, QualificationHarnessError>;
}

/// Protected provider setup interface implemented once per provider domain.
///
/// Implementations own live resource creation and emit only the canonical,
/// capability-free handoff accepted by the no-secret collection process. The
/// caller supplies exactly one setup credential on a private stdin boundary;
/// implementations must neither retain it nor copy it into the result.
pub trait QualificationProtectedSetup {
    /// Returns immutable adapter metadata.
    fn metadata(&self) -> QualificationAdapterMetadata;

    /// Creates the exact live provider resources and public scenario vectors.
    fn setup(
        &self,
        input: QualificationProtectedSetupInput<'_>,
        setup_credential: &[u8],
    ) -> Result<QualificationSetupHandoffV1, QualificationHarnessError>;
}

/// Protected observer and cleanup interface implemented once per provider.
///
/// Implementations reconstruct their environment from trusted run context,
/// the secret-free run reference, and domain-prefixed credentials supplied by
/// the protected job. No candidate-owned in-memory value crosses this boundary.
pub trait QualificationProtectedObserver {
    /// Protected domain environment reconstructed independently of candidate code.
    type Environment;

    /// Returns immutable adapter metadata.
    fn metadata(&self) -> QualificationAdapterMetadata;

    /// Reopens the exact run through protected read/cleanup credentials.
    fn open(
        &self,
        context: &QualificationRunContext,
        reference: Option<&QualificationRunReference>,
    ) -> Result<Self::Environment, QualificationHarnessError>;

    /// Observes provider truth through an independent read-only boundary.
    fn provider_truth(
        &self,
        environment: &Self::Environment,
        scenario_id: &str,
        phase: &QualificationCollectedOperation,
        instance: &QualificationCommonOperationInstanceEvidence,
        in_row_domain_facts: &[u8],
    ) -> Result<QualificationProviderTruth, QualificationHarnessError>;

    /// Validates only generated profile-specific receipt payload claims.
    /// Common canonicality, signature, link, and common-claim verification is
    /// always performed by the protected shared harness before this hook.
    fn validate_receipt_payload(
        &self,
        environment: &Self::Environment,
        phase: &QualificationCollectedOperation,
        instance: &QualificationCommonOperationInstanceEvidence,
        truth: &QualificationProviderTruth,
        claims: &[QualificationCommonReceiptClaims],
    ) -> Result<(), QualificationHarnessError>;

    /// Exact-validates one executable scenario program after all common and
    /// independently observed provider facts have been authenticated.
    fn validate_domain_scenario(
        &self,
        environment: &Self::Environment,
        program: &crate::QualificationScenarioProgramV1,
        operations: &[QualificationRedactedOperation],
        truths: &[QualificationProviderTruth],
    ) -> Result<(), QualificationHarnessError>;

    /// Destroys every provider resource and credential, proving cleanup.
    fn cleanup(
        &self,
        context: &QualificationRunContext,
        reference: Option<&QualificationRunReference>,
    ) -> Result<QualificationCleanupEvidence, QualificationHarnessError>;
}

/// Validates the provider-independent projection of one executable scenario.
/// Domain adapters call this first, then enforce their hook-specific facts.
pub fn validate_scenario_program_projection(
    program: &crate::QualificationScenarioProgramV1,
    failpoint: Option<QualificationFailpoint>,
    operations: &[QualificationRedactedOperation],
    truths: &[QualificationProviderTruth],
) -> Result<(), QualificationHarnessError> {
    if operations.is_empty()
        || operations.len() > 8
        || truths.len() > 32
        || truths
            .windows(2)
            .any(|pair| pair[0].operation_id >= pair[1].operation_id)
    {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    let mut projected_instances = Vec::new();
    let mut matched_roles = std::collections::BTreeSet::new();
    for operation in operations {
        operation.validate()?;
        projected_instances.extend(operation.instances.iter());
        let cases = program
            .cases()
            .iter()
            .filter(|case| case.role() == operation.role)
            .collect::<Vec<_>>();
        if cases.is_empty() {
            continue;
        }
        matched_roles.insert(operation.role);
        let exact_expectation = cases
            .iter()
            .all(|case| case.expectation() == crate::QualificationScenarioExpectation::Exact);
        if exact_expectation == failpoint.is_some() {
            return Err(QualificationHarnessError::ProviderTruth);
        }
        if exact_expectation {
            if operation.attempts.len() != cases.len() {
                return Err(QualificationHarnessError::ProviderTruth);
            }
            let mut offset = 0_usize;
            while offset < cases.len() {
                let group = cases[offset].group();
                let end = cases[offset..]
                    .iter()
                    .position(|case| case.group() != group)
                    .map_or(cases.len(), |relative| offset + relative);
                let topology = cases[offset].topology();
                if cases[offset..end]
                    .iter()
                    .any(|case| case.topology() != topology)
                {
                    return Err(QualificationHarnessError::ProviderTruth);
                }
                let mut expected = cases[offset..end]
                    .iter()
                    .map(|case| (case.expected_outcome(), case.expected_effect()))
                    .collect::<Vec<_>>();
                let mut actual = operation.attempts[offset..end]
                    .iter()
                    .map(|attempt| {
                        let effect = attempt.operation_id.as_deref().map_or(
                            Ok(QualificationEffect::NotApplied),
                            |operation_id| {
                                operation
                                    .instances
                                    .iter()
                                    .find(|instance| instance.operation_id == operation_id)
                                    .map(|instance| instance.effect)
                                    .ok_or(QualificationHarnessError::ProviderTruth)
                            },
                        )?;
                        Ok((attempt.outcome, effect))
                    })
                    .collect::<Result<Vec<_>, QualificationHarnessError>>()?;
                if topology == crate::QualificationScenarioTopology::Parallel {
                    expected.sort_unstable();
                    actual.sort_unstable();
                }
                if actual != expected {
                    return Err(QualificationHarnessError::ProviderTruth);
                }
                offset = end;
            }
        }
        if exact_expectation {
            let expected_calls = cases.iter().try_fold(0_u32, |total, case| {
                total.checked_add(case.expected_provider_calls())
            });
            let actual_calls = operation
                .instances
                .iter()
                .try_fold(0_u32, |total, instance| {
                    total.checked_add(instance.counters.provider_calls)
                });
            if expected_calls.is_none() || expected_calls != actual_calls {
                return Err(QualificationHarnessError::ProviderTruth);
            }
        }
    }
    if program
        .cases()
        .iter()
        .any(|case| !matched_roles.contains(&case.role()))
    {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    projected_instances.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
    if projected_instances.len() != truths.len()
        || projected_instances
            .iter()
            .zip(truths)
            .any(|(instance, truth)| {
                instance.operation_id != truth.operation_id
                    || instance.effect != truth.effect
                    || instance.counters.provider_calls != truth.provider_calls
            })
    {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    Ok(())
}

impl QualificationAdapterMetadata {
    /// Validates ordering, identity, family, target, and scenario bounds.
    pub fn validate(&self) -> Result<(), QualificationHarnessError> {
        if !lower_token(self.domain)
            || self.family.is_empty()
            || self.family.len() > 8
            || self.targets.is_empty()
            || self.targets.len() > 4
            || self.scenarios.is_empty()
            || self.scenarios.len() > MAX_SCENARIOS
            || !registered_token(self.protected_environment)
            || !self.family.windows(2).all(|pair| pair[0] < pair[1])
            || !self.targets.windows(2).all(|pair| pair[0] < pair[1])
            || !self.scenarios.windows(2).all(|pair| pair[0] < pair[1])
            || self.family.iter().any(|profile| {
                !profile.starts_with(&format!("auths.{}.", self.domain)) || !profile.contains('/')
            })
            || self
                .scenarios
                .iter()
                .any(|scenario| !registered_token(scenario))
        {
            return Err(QualificationHarnessError::InvalidMetadata);
        }
        Ok(())
    }
}

impl QualificationVector {
    /// Validates one domain vector before application or provider I/O.
    pub fn validate(&self) -> Result<(), QualificationHarnessError> {
        if !registered_token(&self.id)
            || self.scenario_program.id() != self.id
            || self.scenario_program.sha256().is_err()
            || self.cases.is_empty()
            || self.cases.len() != self.scenario_program.cases().len()
            || self
                .cases
                .iter()
                .zip(self.scenario_program.cases())
                .any(|(actual, expected)| {
                    actual.case_id != expected.case_id()
                        || actual.input.is_empty()
                        || actual.input.len() > MAX_VECTOR_BYTES
                })
        {
            return Err(QualificationHarnessError::Limit);
        }
        Ok(())
    }
}

impl QualificationRunContext {
    /// Validates the immutable workflow-owned run tuple.
    pub fn validate(&self) -> Result<(), QualificationHarnessError> {
        if !decimal_token(&self.repository_id)
            || self.candidate_revision.len() != 40
            || !self.candidate_revision.bytes().all(lower_hex_byte)
            || !registered_token(&self.protected_environment)
            || !decimal_token(&self.run_id)
            || self.run_attempt == 0
            || !registered_token(&self.provider_run_id)
        {
            return Err(QualificationHarnessError::InvalidRunReference);
        }
        Ok(())
    }
}

impl QualificationSetupVectorV1 {
    /// Decodes and validates one public scenario vector.
    pub fn vector(&self) -> Result<QualificationVector, QualificationHarnessError> {
        if !registered_token(&self.id)
            || self.scenario_program.id() != self.id
            || self.cases.is_empty()
            || self.cases.len() != self.scenario_program.cases().len()
            || self
                .cases
                .iter()
                .zip(self.scenario_program.cases())
                .any(|(actual, expected)| {
                    actual.case_id != expected.case_id()
                        || actual.input_base64url.is_empty()
                        || actual.input_base64url.len() > encoded_vector_bound()
                        || actual.input_base64url.contains('=')
                })
        {
            return Err(QualificationHarnessError::InvalidSetupHandoff);
        }
        let cases = self
            .cases
            .iter()
            .map(|case| {
                Ok(QualificationCaseVector {
                    case_id: case.case_id.clone(),
                    input: Base64UrlUnpadded::decode_vec(&case.input_base64url)
                        .map_err(|_| QualificationHarnessError::InvalidSetupHandoff)?,
                })
            })
            .collect::<Result<Vec<_>, QualificationHarnessError>>()?;
        let expected_failpoint = self
            .id
            .strip_prefix("crash-")
            .and_then(QualificationFailpoint::from_token);
        if self.failpoint != expected_failpoint {
            return Err(QualificationHarnessError::InvalidSetupHandoff);
        }
        let vector = QualificationVector {
            id: self.id.clone(),
            scenario_program: self.scenario_program.clone(),
            cases,
            failpoint: self.failpoint,
        };
        vector.validate()?;
        if vector
            .cases
            .iter()
            .zip(&self.cases)
            .any(|(decoded, encoded)| {
                Base64UrlUnpadded::encode_string(&decoded.input) != encoded.input_base64url
            })
        {
            return Err(QualificationHarnessError::InvalidSetupHandoff);
        }
        Ok(vector)
    }
}

impl QualificationSetupHandoffV1 {
    /// Validates the complete capability-free setup/collection boundary.
    pub fn validate(&self) -> Result<(), QualificationHarnessError> {
        self.run_context.validate()?;
        self.run_reference.validate()?;
        if self.schema != "auths.profile-qualification-setup-handoff/1"
            || !lower_token(&self.domain)
            || !registered_token(&self.connection_alias)
            || self.vectors.is_empty()
            || self.vectors.len() > MAX_SCENARIOS
            || !self.vectors.windows(2).all(|pair| pair[0].id < pair[1].id)
            || self.vectors.iter().any(|vector| vector.vector().is_err())
            || self.run_reference.domain != self.domain
            || self.run_reference.target != self.run_context.target
            || self.run_reference.candidate_revision != self.run_context.candidate_revision
            || self.run_reference.repository_id != self.run_context.repository_id
            || self.run_reference.run_id != self.run_context.run_id
            || self.run_reference.run_attempt != self.run_context.run_attempt
            || self.run_reference.provider_run_id != self.run_context.provider_run_id
            || self.run_reference.connection_alias_sha256
                != hex::encode(Sha256::digest(self.connection_alias.as_bytes()))
        {
            return Err(QualificationHarnessError::InvalidSetupHandoff);
        }
        Ok(())
    }

    /// Returns the exact decoded scenario roster after full validation.
    pub fn decoded_vectors(&self) -> Result<Vec<QualificationVector>, QualificationHarnessError> {
        self.validate()?;
        self.vectors
            .iter()
            .map(QualificationSetupVectorV1::vector)
            .collect()
    }
}

impl QualificationRunReference {
    /// Validates the exact secret-free cross-job handoff.
    pub fn validate(&self) -> Result<(), QualificationHarnessError> {
        if self.schema != "auths.profile-qualification-run-reference/1"
            || !lower_token(&self.domain)
            || self.candidate_revision.len() != 40
            || !self.candidate_revision.bytes().all(lower_hex_byte)
            || !decimal_token(&self.repository_id)
            || !decimal_token(&self.run_id)
            || self.run_attempt == 0
            || !registered_token(&self.provider_run_id)
            || !registered_token(&self.provider_namespace)
            || !digest(&self.connection_alias_sha256)
            || self.resource_references.is_empty()
            || self.resource_references.len() > MAX_RUN_REFERENCES
            || !sorted_unique_registered(&self.resource_references)
            || self.connection_generations.is_empty()
            || self.connection_generations.len() > MAX_RUN_REFERENCES
            || !sorted_unique_decimal(&self.connection_generations)
        {
            return Err(QualificationHarnessError::InvalidRunReference);
        }
        Ok(())
    }
}

impl QualificationCandidateCollectionV1 {
    /// Validates the bounded, byte-sorted candidate mismatch projection.
    pub fn validate(&self) -> Result<(), QualificationHarnessError> {
        self.run_reference.validate()?;
        if self.schema != "auths.profile-qualification-candidate-collection/1"
            || self.scenarios.is_empty()
            || self.scenarios.len() > 128
            || !self
                .scenarios
                .windows(2)
                .all(|pair| pair[0].scenario_id < pair[1].scenario_id)
            || self.scenarios.iter().any(|scenario| {
                scenario.validate().is_err()
                    || scenario.provider_run_id != self.run_reference.provider_run_id
            })
        {
            return Err(QualificationHarnessError::Limit);
        }
        Ok(())
    }
}

impl QualificationCollectedScenario {
    /// Validates one untrusted candidate invocation before protected use.
    pub fn validate(&self) -> Result<(), QualificationHarnessError> {
        if !registered_token(&self.scenario_id)
            || !registered_token(&self.provider_run_id)
            || self.operations.is_empty()
            || self.operations.len() > 8
            || !self
                .operations
                .windows(2)
                .all(|pair| operation_order(&pair[0]) < operation_order(&pair[1]))
            || self
                .operations
                .iter()
                .any(|operation| operation.validate().is_err())
        {
            return Err(QualificationHarnessError::Limit);
        }
        Ok(())
    }
}

impl QualificationCollectedOperation {
    /// Validates one installed-client operation before protected use.
    pub fn validate(&self) -> Result<(), QualificationHarnessError> {
        if !semantic_profile(&self.profile) {
            return Err(QualificationHarnessError::Limit);
        }
        Ok(())
    }
}

impl QualificationRedactedOperationInstance {
    /// Returns the independently protected common projection without the
    /// separately observed provider-truth commitment.
    #[must_use]
    pub fn common_projection(&self) -> QualificationCommonOperationInstanceEvidence {
        QualificationCommonOperationInstanceEvidence {
            operation_id: self.operation_id.clone(),
            connection_generation: self.connection_generation.clone(),
            principal_sha256: self.principal_sha256.clone(),
            connection_alias_sha256: self.connection_alias_sha256.clone(),
            connection_id_sha256: self.connection_id_sha256.clone(),
            connection_descriptor_sha256: self.connection_descriptor_sha256.clone(),
            connection_account_sha256: self.connection_account_sha256.clone(),
            credential_scope_sha256: self.credential_scope_sha256.clone(),
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
            reconciled: self.reconciled,
            effect: self.effect,
            counters: self.counters.clone(),
            sealed_command_sha256: self.sealed_command_sha256.clone(),
            provider_result_sha256: self.provider_result_sha256.clone(),
            execution_result_sha256: self.execution_result_sha256.clone(),
        }
    }
}

impl QualificationCleanupEvidence {
    /// Requires complete cleanup; partial or inconclusive cleanup cannot sign.
    pub fn validate(&self) -> Result<(), QualificationHarnessError> {
        if self.provider_resources_destroyed
            && self.connection_disabled
            && self.credentials_revoked
            && self.residual_resource_count == 0
        {
            Ok(())
        } else {
            Err(QualificationHarnessError::Cleanup)
        }
    }
}

impl QualificationRedactedOperation {
    /// Validates the bounded protected operation projection before serialization.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), QualificationHarnessError> {
        let instance_ids = self
            .instances
            .iter()
            .map(|instance| instance.operation_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if !semantic_profile(&self.profile)
            || self.instances.len() > 8
            || !self
                .instances
                .windows(2)
                .all(|pair| pair[0].operation_id < pair[1].operation_id)
            || self.instances.iter().any(|instance| {
                !registered_token(&instance.operation_id)
                    || !decimal_token(&instance.connection_generation)
                    || !digest(&instance.principal_sha256)
                    || instance
                        .connection_alias_sha256
                        .as_deref()
                        .is_some_and(|value| !digest(value))
                    || instance
                        .connection_id_sha256
                        .as_deref()
                        .is_some_and(|value| !digest(value))
                    || instance
                        .connection_descriptor_sha256
                        .as_deref()
                        .is_some_and(|value| !digest(value))
                    || instance
                        .connection_account_sha256
                        .as_deref()
                        .is_some_and(|value| !digest(value))
                    || instance
                        .credential_scope_sha256
                        .as_deref()
                        .is_some_and(|value| !digest(value))
                    || !connected_commitments_are_complete(
                        instance.connection_alias_sha256.as_deref(),
                        instance.connection_id_sha256.as_deref(),
                        instance.connection_descriptor_sha256.as_deref(),
                        instance.connection_account_sha256.as_deref(),
                        instance.credential_scope_sha256.as_deref(),
                    )
                    || !digest(&instance.canonical_input_sha256)
                    || instance
                        .idempotency_sha256
                        .as_deref()
                        .is_some_and(|value| !digest(value))
                    || !digest(&instance.canonical_action_sha256)
                    || !digest(&instance.receipt_action_sha256)
                    || !digest(&instance.receipt_context_sha256)
                    || !digest(&instance.authority_sha256)
                    || !digest(&instance.configuration_sha256)
                    || !digest(&instance.runtime_contract_sha256)
                    || !digest(&instance.preparation_sha256)
                    || !digest(&instance.provider_truth_sha256)
                    || instance
                        .sealed_command_sha256
                        .as_deref()
                        .is_some_and(|value| !digest(value))
                    || instance
                        .provider_result_sha256
                        .as_deref()
                        .is_some_and(|value| !digest(value))
                    || instance
                        .execution_result_sha256
                        .as_deref()
                        .is_some_and(|value| !digest(value))
                    || !instance.counters.valid_for_instance(
                        instance.effect,
                        instance.sealed_command_sha256.is_some(),
                        instance.provider_result_sha256.is_some(),
                        instance.reconciled,
                    )
            })
            || self.attempts.is_empty()
            || self.attempts.len() > 8
            || self.attempts.iter().enumerate().any(|(index, attempt)| {
                attempt.sequence != u8::try_from(index + 1).unwrap_or(u8::MAX)
                    || attempt.validate().is_err()
                    || attempt
                        .operation_id
                        .as_deref()
                        .is_some_and(|id| !instance_ids.contains(id))
            })
            || self.attempts.iter().any(|attempt| {
                let Some(operation_id) = attempt.operation_id.as_deref() else {
                    return false;
                };
                let Some(instance) = self
                    .instances
                    .iter()
                    .find(|instance| instance.operation_id == operation_id)
                else {
                    return true;
                };
                attempt.principal_sha256 != instance.principal_sha256
                    || attempt.configuration_sha256.as_deref()
                        != Some(instance.configuration_sha256.as_str())
                    || attempt.connection_alias_sha256 != instance.connection_alias_sha256
                    || attempt.connection_generation.as_deref()
                        != Some(instance.connection_generation.as_str())
                    || attempt.requested_scope_sha256 != instance.credential_scope_sha256
                    || attempt.idempotency_sha256 != instance.idempotency_sha256
                    || (is_preparation_attempt(attempt.kind)
                        && attempt.preparation_input_sha256.is_none())
                    || (attempt.kind == QualificationAttemptKind::Conflict
                        && attempt.preparation_input_sha256.as_deref()
                            == Some(instance.canonical_input_sha256.as_str()))
                    || (is_preparation_attempt(attempt.kind)
                        && attempt.kind != QualificationAttemptKind::Conflict
                        && attempt.preparation_input_sha256.as_deref()
                            != Some(instance.canonical_input_sha256.as_str()))
                    || (!is_preparation_attempt(attempt.kind)
                        && (attempt.preparation_input_sha256.is_some()
                            || attempt.idempotency_sha256.is_some()
                            || attempt.connection_alias_sha256.is_some()
                            || attempt.connection_generation.is_some()
                            || attempt.requested_scope_sha256.is_some()))
                    || attempt.sealed_command_sha256.is_some()
                        && attempt.sealed_command_sha256 != instance.sealed_command_sha256
            })
        {
            return Err(QualificationHarnessError::Redaction);
        }
        Ok(())
    }
}

impl QualificationCommonOperationInstanceEvidence {
    /// Validates the common protected journal projection before domain truth
    /// is consulted.
    pub fn validate(&self) -> Result<(), QualificationHarnessError> {
        if !registered_token(&self.operation_id)
            || !decimal_token(&self.connection_generation)
            || !digest(&self.principal_sha256)
            || self
                .connection_alias_sha256
                .as_deref()
                .is_some_and(|value| !digest(value))
            || self
                .connection_id_sha256
                .as_deref()
                .is_some_and(|value| !digest(value))
            || self
                .connection_descriptor_sha256
                .as_deref()
                .is_some_and(|value| !digest(value))
            || self
                .connection_account_sha256
                .as_deref()
                .is_some_and(|value| !digest(value))
            || self
                .credential_scope_sha256
                .as_deref()
                .is_some_and(|value| !digest(value))
            || !connected_commitments_are_complete(
                self.connection_alias_sha256.as_deref(),
                self.connection_id_sha256.as_deref(),
                self.connection_descriptor_sha256.as_deref(),
                self.connection_account_sha256.as_deref(),
                self.credential_scope_sha256.as_deref(),
            )
            || !digest(&self.canonical_input_sha256)
            || self
                .idempotency_sha256
                .as_deref()
                .is_some_and(|value| !digest(value))
            || !digest(&self.canonical_action_sha256)
            || !digest(&self.receipt_action_sha256)
            || !digest(&self.receipt_context_sha256)
            || !digest(&self.authority_sha256)
            || !digest(&self.configuration_sha256)
            || !digest(&self.runtime_contract_sha256)
            || !digest(&self.preparation_sha256)
            || self
                .sealed_command_sha256
                .as_deref()
                .is_some_and(|value| !digest(value))
            || self
                .provider_result_sha256
                .as_deref()
                .is_some_and(|value| !digest(value))
            || self
                .execution_result_sha256
                .as_deref()
                .is_some_and(|value| !digest(value))
            || !self.counters.valid_for_instance(
                self.effect,
                self.sealed_command_sha256.is_some(),
                self.provider_result_sha256.is_some(),
                self.reconciled,
            )
        {
            return Err(QualificationHarnessError::Redaction);
        }
        Ok(())
    }
}

impl QualificationRedactedAttempt {
    /// Validates one protected public call projection.
    pub fn validate(&self) -> Result<(), QualificationHarnessError> {
        if self.sequence == 0
            || !registered_token(&self.request_id)
            || self
                .operation_id
                .as_deref()
                .is_some_and(|value| !registered_token(value))
            || self
                .recovery_id
                .as_deref()
                .is_some_and(|value| !registered_token(value))
            || !attempt_semantics(
                self.kind,
                self.outcome,
                self.completion,
                self.recovery_id.as_deref(),
                self.error_code.as_deref(),
                self.issue_metadata_sha256.as_deref(),
                self.connection_alias_sha256.as_deref(),
                self.connection_generation.as_deref(),
                self.requested_scope_sha256.as_deref(),
            )
            || self
                .idempotency_sha256
                .as_deref()
                .is_some_and(|value| !digest(value))
            || !digest(&self.request_input_sha256)
            || self
                .preparation_input_sha256
                .as_deref()
                .is_some_and(|value| !digest(value))
            || !digest(&self.principal_sha256)
            || self
                .connection_alias_sha256
                .as_deref()
                .is_some_and(|value| !digest(value))
            || self
                .connection_generation
                .as_deref()
                .is_some_and(|value| !decimal_token(value))
            || self
                .requested_scope_sha256
                .as_deref()
                .is_some_and(|value| !digest(value))
            || self
                .configuration_sha256
                .as_deref()
                .is_some_and(|value| !digest(value))
            || self.operation_id.is_some() != self.configuration_sha256.is_some()
            || self
                .sealed_command_sha256
                .as_deref()
                .is_some_and(|value| !digest(value))
            || self
                .error_code
                .as_deref()
                .is_some_and(|value| !registered_token(value))
            || self
                .issue_metadata_sha256
                .as_deref()
                .is_some_and(|value| !digest(value))
            || !digest(&self.result_sha256)
            || self.receipt_ids.len() > MAX_RECEIPTS
            || self
                .receipt_ids
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.receipt_ids.len()
            || self.receipt_ids.iter().any(|id| !receipt_id(id))
        {
            return Err(QualificationHarnessError::Redaction);
        }
        Ok(())
    }
}

/// Closed qualification harness failures. No variant can make a profile qualified.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum QualificationHarnessError {
    /// Adapter metadata differs from its manifest/generated roster.
    #[error("qualification adapter metadata is invalid")]
    InvalidMetadata,
    /// The common harness supplied a malformed protected client endpoint pair.
    #[error("qualification protected client endpoints are invalid")]
    InvalidPhaseClient,
    /// The cross-job provider run reference is malformed or contains unsafe data.
    #[error("qualification run reference is invalid")]
    InvalidRunReference,
    /// The protected setup handoff is malformed or differs from workflow policy.
    #[error("qualification protected setup handoff is invalid")]
    InvalidSetupHandoff,
    /// A vector, result, receipt, or report exceeded its hard bound.
    #[error("qualification harness input exceeds its hard bound")]
    Limit,
    /// A required production prerequisite is intentionally unavailable.
    #[error("qualification prerequisite is unavailable: {0}")]
    PrerequisiteUnavailable(&'static str),
    /// Production onboarding failed.
    #[error("qualification provider onboarding failed")]
    Onboarding,
    /// Installed generated-client invocation failed or was inconclusive.
    #[error("qualification invocation failed or was inconclusive")]
    Invocation,
    /// Independent provider truth could not be established.
    #[error("qualification provider truth is unavailable")]
    ProviderTruth,
    /// Portable receipts or domain claims did not match provider truth.
    #[error("qualification receipt verification failed")]
    Receipt,
    /// Redaction or secret scanning failed closed.
    #[error("qualification evidence redaction failed")]
    Redaction,
    /// Provider resource or credential cleanup was not proved.
    #[error("qualification environment cleanup failed")]
    Cleanup,
}

fn lower_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

const fn encoded_vector_bound() -> usize {
    MAX_VECTOR_BYTES.div_ceil(3) * 4
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
    let Some((id, version)) = value.rsplit_once('/') else {
        return false;
    };
    registered_token(id) && decimal_token(version)
}

fn receipt_id(value: &str) -> bool {
    value.len() == 48
        && value.starts_with("rcpt_")
        && value[5..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn operation_order(
    operation: &QualificationCollectedOperation,
) -> (QualificationOperationRole, &str) {
    (operation.role, operation.profile.as_str())
}

fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(lower_hex_byte)
}

#[allow(clippy::too_many_arguments)]
fn attempt_semantics(
    kind: QualificationAttemptKind,
    outcome: QualificationOutcomeKind,
    completion: Option<QualificationCompletion>,
    recovery_id: Option<&str>,
    error_code: Option<&str>,
    issue_metadata_sha256: Option<&str>,
    connection_alias_sha256: Option<&str>,
    connection_generation: Option<&str>,
    requested_scope_sha256: Option<&str>,
) -> bool {
    let terminal_success = matches!(
        outcome,
        QualificationOutcomeKind::Completed
            | QualificationOutcomeKind::Partial
            | QualificationOutcomeKind::NotApplied
    );
    let carries_issue = outcome != QualificationOutcomeKind::Completed;
    let carries_recovery = matches!(
        outcome,
        QualificationOutcomeKind::RecoveryRequired | QualificationOutcomeKind::Conflict
    );
    let connected_fields = [
        connection_alias_sha256.is_some(),
        connection_generation.is_some(),
        requested_scope_sha256.is_some(),
    ];
    let allowed = match kind {
        QualificationAttemptKind::Execute | QualificationAttemptKind::Replay => {
            !matches!(outcome, QualificationOutcomeKind::Conflict)
        }
        QualificationAttemptKind::Conflict => outcome == QualificationOutcomeKind::Conflict,
        QualificationAttemptKind::Status => !matches!(outcome, QualificationOutcomeKind::Conflict),
        QualificationAttemptKind::Recover | QualificationAttemptKind::CancelAfterWrite => {
            matches!(
                outcome,
                QualificationOutcomeKind::Completed
                    | QualificationOutcomeKind::Partial
                    | QualificationOutcomeKind::NotApplied
                    | QualificationOutcomeKind::RecoveryRequired
            )
        }
    };
    allowed
        && terminal_success == completion.is_some()
        && carries_recovery == recovery_id.is_some()
        && carries_issue == error_code.is_some()
        && carries_issue == issue_metadata_sha256.is_some()
        && (connected_fields.iter().all(|present| *present)
            || connected_fields.iter().all(|present| !*present))
}

fn is_preparation_attempt(kind: QualificationAttemptKind) -> bool {
    matches!(
        kind,
        QualificationAttemptKind::Execute
            | QualificationAttemptKind::Replay
            | QualificationAttemptKind::Conflict
            | QualificationAttemptKind::CancelAfterWrite
    )
}

fn connected_commitments_are_complete(
    alias: Option<&str>,
    connection_id: Option<&str>,
    descriptor: Option<&str>,
    account: Option<&str>,
    scope: Option<&str>,
) -> bool {
    let present = [alias, connection_id, descriptor, account, scope]
        .into_iter()
        .flatten()
        .count();
    present == 0 || present == 5
}

fn lower_hex_byte(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

fn decimal_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

fn sorted_unique_registered(values: &[String]) -> bool {
    values.iter().all(|value| registered_token(value))
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn sorted_unique_decimal(values: &[String]) -> bool {
    values.iter().all(|value| decimal_token(value))
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation_free_attempt() -> QualificationRedactedAttempt {
        QualificationRedactedAttempt {
            sequence: 1,
            kind: QualificationAttemptKind::Execute,
            request_id: "request-1".into(),
            operation_id: None,
            recovery_id: None,
            outcome: QualificationOutcomeKind::Denied,
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
        }
    }

    #[test]
    fn pre_admission_scenario_roster_is_closed_and_exact() {
        assert_eq!(
            qualification_pre_admission_attempt_count("boundary-plus-one"),
            Some(1)
        );
        assert_eq!(
            qualification_pre_admission_attempt_count("malformed-input"),
            Some(4)
        );
        for scenario in [
            "configuration-mismatch",
            "connection-substitution",
            "principal-substitution",
        ] {
            assert_eq!(qualification_pre_admission_attempt_count(scenario), Some(1));
        }
        for scenario in [
            "happy-path",
            "exact-boundary",
            "stale-evidence",
            "crash-before-decision",
        ] {
            assert_eq!(qualification_pre_admission_attempt_count(scenario), None);
        }
    }

    #[test]
    fn operation_and_configuration_projection_are_all_or_none() {
        let attempt = operation_free_attempt();
        assert!(attempt.validate().is_ok());

        let mut forged_configuration = attempt.clone();
        forged_configuration.configuration_sha256 = Some("e".repeat(64));
        assert_eq!(
            forged_configuration.validate(),
            Err(QualificationHarnessError::Redaction)
        );

        let mut forged_operation = attempt;
        forged_operation.operation_id = Some("operation-1".into());
        assert_eq!(
            forged_operation.validate(),
            Err(QualificationHarnessError::Redaction)
        );
    }

    #[test]
    fn phase_client_requires_one_absolute_sibling_socket_pair() {
        let common = crate::QualificationScenarioManifest::from_json(include_bytes!(
            "../../../conformance/v2/profile-qualification-common.json"
        ))
        .unwrap();
        let conflict = common.program("changed-input-conflict").unwrap().clone();
        let happy = common.program("happy-path").unwrap().clone();
        let client = QualificationPhaseClient::new(
            "/run/auths/phase/client.sock".into(),
            "/run/auths/phase/result.sock".into(),
        )
        .unwrap();
        assert_eq!(client.agent_socket(), "/run/auths/phase/client.sock");
        assert_eq!(client.result_socket(), "/run/auths/phase/result.sock");
        let reviewed = client
            .clone()
            .with_reviewed_phase(conflict, 2, QualificationOperationRole::Effect)
            .unwrap();
        assert_eq!(
            reviewed
                .scenario_program
                .as_ref()
                .map(crate::QualificationScenarioProgramV1::id),
            Some("changed-input-conflict")
        );
        assert_eq!(reviewed.phase_index, Some(2));
        assert_eq!(reviewed.role, Some(QualificationOperationRole::Effect));
        assert_eq!(
            client.with_reviewed_phase(happy, 0, QualificationOperationRole::Effect),
            Err(QualificationHarnessError::InvalidPhaseClient)
        );
        assert_eq!(
            QualificationPhaseClient::new("client.sock".into(), "result.sock".into()),
            Err(QualificationHarnessError::InvalidPhaseClient)
        );
        assert_eq!(
            QualificationPhaseClient::new(
                "/run/auths/phase/client.sock".into(),
                "/run/auths/other/result.sock".into(),
            ),
            Err(QualificationHarnessError::InvalidPhaseClient)
        );
        assert_eq!(
            QualificationPhaseClient::new(
                "/run/auths/phase/client.sock".into(),
                "/run/auths/phase/client.sock".into(),
            ),
            Err(QualificationHarnessError::InvalidPhaseClient)
        );
    }

    #[test]
    fn failpoint_roster_is_closed_and_exact() {
        let values = [
            QualificationFailpoint::BeforeDecision,
            QualificationFailpoint::AfterDecision,
            QualificationFailpoint::AfterReservation,
            QualificationFailpoint::AfterCommand,
            QualificationFailpoint::AfterReread,
            QualificationFailpoint::AfterLease,
            QualificationFailpoint::AfterEntryMarker,
            QualificationFailpoint::AfterRequestWrite,
            QualificationFailpoint::AfterProviderResult,
            QualificationFailpoint::AfterObservation,
            QualificationFailpoint::AfterExecutionReceipt,
            QualificationFailpoint::AfterTerminal,
        ];
        assert_eq!(values.len(), 12);
        for value in values {
            assert_eq!(
                QualificationFailpoint::from_token(value.as_str()),
                Some(value)
            );
        }
        let encoded = serde_json::to_value(values).unwrap();
        assert_eq!(encoded[0], "before-decision");
        assert_eq!(encoded[11], "after-terminal");
    }

    #[test]
    fn metadata_rejects_unsorted_or_cross_domain_profiles() {
        let metadata = QualificationAdapterMetadata {
            domain: "stripe",
            family: &["auths.postgresql.bounded-update/1"],
            targets: &[QualificationTarget::LinuxX86_64],
            protected_environment: "qualification-stripe",
            scenarios: &["happy-path"],
        };
        assert_eq!(
            metadata.validate(),
            Err(QualificationHarnessError::InvalidMetadata)
        );
    }

    #[test]
    fn not_applied_reservation_allows_release_or_successful_preflight_handoff() {
        let counters = |releases, consumptions| QualificationCounters {
            reservation_writes: 1,
            reservation_releases: releases,
            reservation_consumptions: consumptions,
            reservation_retentions: 0,
            connection_rereads: 0,
            credential_lease_attempts: 0,
            credential_leases: 0,
            credential_lease_closes: 0,
            provider_entry_markers: 0,
            provider_calls: 0,
            provider_request_writes: 0,
            provider_responses: 0,
            durable_provider_results: 0,
            observations: 0,
            receipt_writes: 0,
        };
        assert!(counters(1, 0).valid_for_instance(
            QualificationEffect::NotApplied,
            false,
            false,
            false,
        ));
        assert!(counters(0, 1).valid_for_instance(
            QualificationEffect::NotApplied,
            false,
            false,
            false,
        ));
        assert!(!counters(0, 0).valid_for_instance(
            QualificationEffect::NotApplied,
            false,
            false,
            false,
        ));
    }
}
