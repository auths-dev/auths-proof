// This closed canonical schema surface reports one fail-closed error type; the
// error variants, rather than repeated per-method prose, define the contract.
#![allow(clippy::missing_errors_doc)]
// Workflow paths are canonical evidence fields and intentionally require the
// exact lowercase `.yml` suffix rather than a case-insensitive filesystem test.
#![allow(clippy::case_sensitive_file_extension_comparisons)]

use crate::manifest::{lower_token, safe_path, semantic_id};
use crate::qualification_harness::{
    QualificationEffect, QualificationOperationRole, QualificationOutcomeKind,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

const MAX_TRUST_REGISTRY_BYTES: usize = 65_536;
const MAX_RECORD_BYTES: usize = 262_144;
const MAX_PROPOSAL_BYTES: usize = 262_144;
const MAX_OBSERVATION_BYTES: usize = 262_144;
const MAX_VERIFIED_BINDING_BYTES: usize = 16_384;
const MAX_ATTESTATION_BYTES: usize = 266_240;
const MAX_SCENARIO_MANIFEST_BYTES: usize = 32_768;
const MAX_ARTIFACT_BYTES: u64 = 536_870_912;
const MAX_QUALIFICATION_SECONDS: u64 = 21_600;
const SIGNATURE_DOMAIN: &[u8] = b"auths.profile-qualification-attestation/1";
const OBSERVATION_SIGNATURE_DOMAIN: &[u8] = b"auths.profile-qualification-observation/1";
const RELEASE_BUILD_ARTIFACT_ROLES: [&str; 9] = [
    "production-agent",
    "python-native",
    "python-profile-opentofu",
    "python-profile-postgresql",
    "python-profile-stripe",
    "python-wheel",
    "qualification-agent",
    "typescript-native",
    "typescript-package",
];

/// Closed build targets that may receive live-provider qualification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum QualificationTarget {
    /// GNU Linux on x86-64.
    #[serde(rename = "linux-x86_64")]
    LinuxX86_64,
    /// GNU Linux on `AArch64`.
    #[serde(rename = "linux-aarch64")]
    LinuxAarch64,
    /// macOS on x86-64.
    #[serde(rename = "macos-x86_64")]
    MacosX86_64,
    /// macOS on Apple Silicon.
    #[serde(rename = "macos-aarch64")]
    MacosAarch64,
}

impl QualificationTarget {
    /// Returns the target token serialized into qualification records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LinuxX86_64 => "linux-x86_64",
            Self::LinuxAarch64 => "linux-aarch64",
            Self::MacosX86_64 => "macos-x86_64",
            Self::MacosAarch64 => "macos-aarch64",
        }
    }

    /// Parses a closed qualification target without aliases or wildcards.
    pub fn parse(value: &str) -> Result<Self, QualificationError> {
        match value {
            "linux-x86_64" => Ok(Self::LinuxX86_64),
            "linux-aarch64" => Ok(Self::LinuxAarch64),
            "macos-x86_64" => Ok(Self::MacosX86_64),
            "macos-aarch64" => Ok(Self::MacosAarch64),
            _ => Err(QualificationError::InvalidTarget),
        }
    }

    /// Returns the exact Rust target triple qualified by this target.
    #[must_use]
    pub const fn rust_target(self) -> &'static str {
        match self {
            Self::LinuxX86_64 => "x86_64-unknown-linux-gnu",
            Self::LinuxAarch64 => "aarch64-unknown-linux-gnu",
            Self::MacosX86_64 => "x86_64-apple-darwin",
            Self::MacosAarch64 => "aarch64-apple-darwin",
        }
    }
}

/// Registry of release-owned public qualification keys.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationTrustRegistry {
    schema: String,
    keys: Vec<QualificationTrustKey>,
}

/// Registry of release-owned public protected-observer keys.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationObserverTrustRegistry {
    schema: String,
    keys: Vec<QualificationTrustKey>,
}

/// One bounded Ed25519 qualification trust key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationTrustKey {
    key_id: String,
    algorithm: String,
    public_key_base64url: String,
    allowed_domains: Vec<String>,
    not_before_unix_seconds: u64,
    not_after_unix_seconds: u64,
}

/// One public key identity participating in the qualification trust boundary.
///
/// Protected verifiers assemble these identities from every independently
/// controlled registry and the deployment-owned receipt and recovery trust
/// snapshots. Reuse of either the key ID or public key collapses those roles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationTrustIdentity<'a> {
    key_id: &'a str,
    public_key_base64url: &'a str,
}

impl<'a> QualificationTrustIdentity<'a> {
    /// Constructs one already-validated public trust identity.
    #[must_use]
    pub const fn new(key_id: &'a str, public_key_base64url: &'a str) -> Self {
        Self {
            key_id,
            public_key_base64url,
        }
    }

    /// Parses one standalone deployment-owned Ed25519 trust identity.
    pub fn parse(
        key_id: &'a str,
        public_key_base64url: &'a str,
    ) -> Result<Self, QualificationError> {
        let public_key = decode_fixed::<32>(public_key_base64url)?;
        if !registered_token(key_id)
            || public_key == [0; 32]
            || VerifyingKey::from_bytes(&public_key).is_err()
        {
            return Err(QualificationError::InvalidTrustKey);
        }
        Ok(Self::new(key_id, public_key_base64url))
    }

    /// Returns the registered public key identifier.
    #[must_use]
    pub const fn key_id(self) -> &'a str {
        self.key_id
    }

    /// Returns the canonical unpadded base64url Ed25519 public key.
    #[must_use]
    pub const fn public_key_base64url(self) -> &'a str {
        self.public_key_base64url
    }
}

/// Deterministic profile-and-target lookup for checked qualification records.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationIndex {
    schema: String,
    entries: Vec<QualificationIndexEntry>,
}

/// One exact profile/target to qualification-ID binding.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationIndexEntry {
    profile: String,
    target: QualificationTarget,
    qualification_id: String,
}

/// Canonical signed qualification statement for one domain family and target.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationRecord {
    schema: String,
    qualification_id: String,
    domain: String,
    profiles: Vec<QualificationProfile>,
    target: QualificationTarget,
    candidate_revision: String,
    semantic_closure_sha256: String,
    package_manifest_sha256: String,
    profile_runtime_digests: Vec<ProfileRuntimeDigest>,
    error_registry_sha256: String,
    provider_matrix_sha256: String,
    proposal_sha256: String,
    toolchain: QualificationToolchain,
    environment_class: String,
    started_at_unix_seconds: u64,
    completed_at_unix_seconds: u64,
    workflow: QualificationWorkflow,
    release_build: QualificationReleaseBuild,
    artifact: QualificationArtifact,
    provider_runs: Vec<QualificationProviderRun>,
    protected_observation: QualificationProtectedObservation,
    scenarios: Vec<QualificationScenario>,
    receipt_verification: QualificationReceiptVerification,
    secret_scan: QualificationSecretScan,
}

/// Canonical untrusted candidate proposal that cannot itself be signed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationProposal {
    schema: String,
    domain: String,
    profiles: Vec<QualificationProfile>,
    target: QualificationTarget,
    candidate_revision: String,
    semantic_closure_sha256: String,
    package_manifest_sha256: String,
    profile_runtime_digests: Vec<ProfileRuntimeDigest>,
    error_registry_sha256: String,
    provider_matrix_sha256: String,
    toolchain: QualificationToolchain,
    candidate_artifacts: Vec<QualificationCandidateArtifact>,
    environment_class: String,
    collection_started_at_unix_seconds: u64,
    collection_completed_at_unix_seconds: u64,
    provider_runs: Vec<QualificationProviderRun>,
    scenarios: Vec<QualificationScenario>,
    receipt_verification: QualificationProposalReceiptVerification,
    secret_scan: QualificationSecretScan,
}

/// One exact profile semantic subject in an atomic qualification family.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationProfile {
    id: String,
    version: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProfileRuntimeDigest {
    profile: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct QualificationToolchain {
    rust: String,
    node: String,
    python: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationWorkflow {
    provider: String,
    repository_id: String,
    workflow_path: String,
    workflow_revision: String,
    attester_revision: String,
    run_id: String,
    run_attempt: u32,
    protected_environment: String,
}

/// Independently verified immutable build run and its exact v1 artifact set.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationReleaseBuild {
    provider: String,
    repository_id: String,
    workflow_path: String,
    workflow_revision: String,
    run_id: String,
    run_attempt: u32,
    run_label: String,
    qualification_surface_sha256: String,
    artifacts: Vec<QualificationReleaseBuildArtifact>,
}

/// One immutable member selected from an authoritative release-build artifact.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationReleaseBuildArtifact {
    role: String,
    artifact_id: String,
    uploaded_archive_sha256: String,
    member_path: String,
    member_sha256: String,
    bytes: u64,
}

/// Candidate-owned mismatch projection of one authoritative release artifact.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationCandidateArtifact {
    role: String,
    member_sha256: String,
    bytes: u64,
}

/// Bounded raw-evidence artifact metadata retained outside the repository.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationArtifact {
    evidence_tar_sha256: String,
    evidence_tar_bytes: u64,
    retention_days: u16,
    created_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    redaction_report_sha256: String,
    storage_provider: String,
    artifact_id: String,
    uploaded_archive_sha256: String,
}

/// One exact provider-version/tool run in a qualification matrix.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationProviderRun {
    id: String,
    provider_version: String,
    provider_artifact_sha256: String,
    scenario_set_sha256: String,
    status: String,
}

/// Digest binding to the independently signed protected observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationProtectedObservation {
    schema: String,
    key_id: String,
    sha256: String,
}

/// One passed common or domain-owned qualification scenario.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationScenario {
    id: String,
    status: String,
    assertions: u32,
    report_sha256: String,
    provider_run_ids: Vec<String>,
}

/// Closed common or domain-owned qualification scenario roster.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationScenarioManifest {
    schema: String,
    domain: String,
    programs: Vec<QualificationScenarioProgramV1>,
}

/// One immutable executable qualification scenario contract.
///
/// Common orchestration owns only the closed case topology and hook schedule;
/// provider meaning remains in the generated static domain adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationScenarioProgramV1 {
    id: String,
    cases: Vec<QualificationScenarioCaseV1>,
    hooks: Vec<QualificationScenarioHookV1>,
}

/// One installed-client case in an executable scenario program.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationScenarioCaseV1 {
    case_id: String,
    intent_id: String,
    stimulus: String,
    role: QualificationOperationRole,
    group: u8,
    topology: QualificationScenarioTopology,
    expectation: QualificationScenarioExpectation,
    expected_outcome: QualificationOutcomeKind,
    expected_effect: QualificationEffect,
    expected_provider_calls: u32,
}

/// Closed execution topology for cases in the same group.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationScenarioTopology {
    Serial,
    Parallel,
}

/// Authority that owns the case's terminal expectation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationScenarioExpectation {
    /// The scenario program fixes the exact public outcome/effect/call tuple.
    Exact,
    /// The reviewed failpoint contract fixes the terminal tuple instead.
    Failpoint,
}

/// Closed protected hook stages. The domain-owned hook token fixes meaning.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationScenarioHookV1 {
    case_id: String,
    stage: QualificationScenarioHookStage,
    hook: String,
}

/// Protected owners at which a reviewed domain hook may execute.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationScenarioHookStage {
    Setup,
    BeforeCall,
    BeforeProvider,
    AfterProviderBeforeResponse,
    BeforeObserver,
    StateFileCorruption,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationReceiptVerification {
    rust: String,
    python: String,
    typescript: String,
    portable_receipt_schema: String,
    receipt_trust_anchor_sha256: String,
    decision_verification_method: String,
    execution_verification_method: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationProposalReceiptVerification {
    rust: String,
    python: String,
    typescript: String,
    portable_receipt_schema: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationSecretScan {
    tool: String,
    status: String,
    report_sha256: String,
}

/// Signed envelope containing one canonical qualification record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationAttestation {
    schema: String,
    record: QualificationRecord,
    signing: QualificationSigning,
}

/// Signed, protected, independently observed provider truth for one run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationObservation {
    schema: String,
    record: QualificationObservationRecord,
    signing: QualificationSigning,
}

/// Canonical observation facts produced only by protected observer code.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationObservationRecord {
    repository_id: String,
    workflow_path: String,
    workflow_revision: String,
    run_id: String,
    run_attempt: u32,
    candidate_revision: String,
    domain: String,
    target: QualificationTarget,
    profiles: Vec<QualificationProfile>,
    provider_runs: Vec<QualificationProviderRun>,
    release_build_sha256: String,
    attester_tools_sha256: String,
    ledgers: Vec<QualificationEvidenceLedgerReference>,
    operation_ids: Vec<String>,
    connection_generations: Vec<String>,
    external_provider_call_counts: Vec<QualificationProviderCallCount>,
    provider_truth_sha256: String,
    counter_report_sha256: String,
    cleanup_report_sha256: String,
    receipt_trust_anchor_sha256: String,
    recovery_key_id: String,
    recovery_public_key_base64url: String,
    observed_report_digests: Vec<QualificationNamedDigest>,
    started_at_unix_seconds: u64,
    completed_at_unix_seconds: u64,
}

/// One independently observed provider-call count for an exact operation.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationProviderCallCount {
    operation_id: String,
    count: u32,
}

/// One byte-sorted named SHA-256 commitment in protected evidence.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationNamedDigest {
    id: String,
    sha256: String,
}

/// Exact signed common-ledger commitment for one provider-matrix run.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationEvidenceLedgerReference {
    provider_run_id: String,
    ledger_sha256: String,
    sealer_key_id: String,
    source_trust_sha256: String,
    ledger_trust_sha256: String,
}

/// No-secret verifier handoff accepted by the minimal attestation signer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationVerifiedRecordBinding {
    schema: String,
    record_sha256: String,
    qualification_id: String,
    repository_id: String,
    workflow_path: String,
    workflow_revision: String,
    attester_revision: String,
    run_id: String,
    run_attempt: u32,
    candidate_revision: String,
    domain: String,
    target: QualificationTarget,
    artifact_id: String,
    uploaded_archive_sha256: String,
    release_build_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationSigning {
    algorithm: String,
    key_id: String,
    signature_base64url: String,
}

/// A qualification attestation verified against a trusted current key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedQualification {
    record: QualificationRecord,
    key_id: String,
}

/// Protected observation verified against a domain-scoped observer key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedQualificationObservation {
    record: QualificationObservationRecord,
    key_id: String,
}

impl QualificationTrustRegistry {
    /// Parses canonical `auths.profile-qualification-trust/1` JSON.
    pub fn from_json(bytes: &[u8]) -> Result<Self, QualificationError> {
        canonical_document_parse(bytes, MAX_TRUST_REGISTRY_BYTES).and_then(|registry: Self| {
            registry.validate()?;
            Ok(registry)
        })
    }

    fn validate(&self) -> Result<(), QualificationError> {
        if self.schema != "auths.profile-qualification-trust/1" || self.keys.len() > 64 {
            return Err(QualificationError::InvalidTrustRegistry);
        }
        let mut previous: Option<&str> = None;
        for key in &self.keys {
            key.validate()?;
            if previous.is_some_and(|value| value >= key.key_id.as_str()) {
                return Err(QualificationError::InvalidTrustRegistry);
            }
            previous = Some(&key.key_id);
        }
        Ok(())
    }

    fn find(&self, key_id: &str) -> Result<&QualificationTrustKey, QualificationError> {
        self.keys
            .binary_search_by(|candidate| candidate.key_id.as_str().cmp(key_id))
            .ok()
            .map(|index| &self.keys[index])
            .ok_or(QualificationError::UnknownTrustKey)
    }

    /// Returns the byte-sorted trusted keys.
    #[must_use]
    pub fn keys(&self) -> &[QualificationTrustKey] {
        &self.keys
    }

    /// Returns every attestation-key identity for global role separation.
    pub fn identities(&self) -> impl Iterator<Item = QualificationTrustIdentity<'_>> {
        self.keys.iter().map(QualificationTrustKey::identity)
    }
}

impl QualificationObserverTrustRegistry {
    /// Parses canonical `auths.profile-qualification-observer-trust/1` JSON.
    pub fn from_json(bytes: &[u8]) -> Result<Self, QualificationError> {
        canonical_document_parse(bytes, MAX_TRUST_REGISTRY_BYTES).and_then(|registry: Self| {
            if registry.schema != "auths.profile-qualification-observer-trust/1"
                || registry.keys.len() > 64
            {
                return Err(QualificationError::InvalidObserverTrustRegistry);
            }
            let mut previous: Option<&str> = None;
            for key in &registry.keys {
                key.validate()?;
                if previous.is_some_and(|value| value >= key.key_id.as_str()) {
                    return Err(QualificationError::InvalidObserverTrustRegistry);
                }
                previous = Some(&key.key_id);
            }
            Ok(registry)
        })
    }

    fn find(&self, key_id: &str) -> Result<&QualificationTrustKey, QualificationError> {
        self.keys
            .binary_search_by(|candidate| candidate.key_id.as_str().cmp(key_id))
            .ok()
            .map(|index| &self.keys[index])
            .ok_or(QualificationError::UnknownObserverTrustKey)
    }

    /// Returns the byte-sorted protected-observer trust keys.
    #[must_use]
    pub fn keys(&self) -> &[QualificationTrustKey] {
        &self.keys
    }

    /// Returns every protected-observer identity for global role separation.
    pub fn identities(&self) -> impl Iterator<Item = QualificationTrustIdentity<'_>> {
        self.keys.iter().map(QualificationTrustKey::identity)
    }
}

impl QualificationTrustKey {
    /// Returns the canonical unpadded base64url Ed25519 public key.
    #[must_use]
    pub fn public_key_base64url(&self) -> &str {
        &self.public_key_base64url
    }

    /// Returns this key's role-neutral public identity.
    #[must_use]
    pub fn identity(&self) -> QualificationTrustIdentity<'_> {
        QualificationTrustIdentity::new(&self.key_id, &self.public_key_base64url)
    }
}

/// Requires every supplied qualification key ID and public key to be unique.
///
/// Individual parsers establish key grammar, algorithm, ordering, validity,
/// and authorization. This check establishes the cross-role invariant after a
/// protected verifier has assembled every repository and deployment identity.
pub fn validate_qualification_key_separation<'a>(
    identities: impl IntoIterator<Item = QualificationTrustIdentity<'a>>,
) -> Result<(), QualificationError> {
    let mut key_ids = BTreeSet::new();
    let mut public_keys = BTreeSet::new();
    for identity in identities {
        QualificationTrustIdentity::parse(identity.key_id, identity.public_key_base64url)?;
        if !key_ids.insert(identity.key_id) || !public_keys.insert(identity.public_key_base64url) {
            return Err(QualificationError::TrustZonesNotDisjoint);
        }
    }
    Ok(())
}

/// Requires the attestation and protected-observer trust roots to be disjoint.
///
/// The two protected jobs are separate trust zones. Reusing either a key ID or
/// an Ed25519 public key would collapse that separation even if the registries
/// were otherwise individually valid.
pub fn validate_qualification_trust_separation(
    attestation: &QualificationTrustRegistry,
    observer: &QualificationObserverTrustRegistry,
) -> Result<(), QualificationError> {
    validate_qualification_key_separation(attestation.identities().chain(observer.identities()))
}

impl QualificationIndex {
    /// Parses canonical `auths.profile-qualification-index/1` JSON.
    pub fn from_json(bytes: &[u8]) -> Result<Self, QualificationError> {
        canonical_document_parse(bytes, MAX_RECORD_BYTES).and_then(|index: Self| {
            if index.schema != "auths.profile-qualification-index/1" || index.entries.len() > 256 {
                return Err(QualificationError::InvalidIndex);
            }
            let mut previous: Option<(&str, QualificationTarget)> = None;
            for entry in &index.entries {
                let identity = (entry.profile.as_str(), entry.target);
                if !profile_reference(&entry.profile)
                    || !qualification_id(&entry.qualification_id)
                    || previous.is_some_and(|value| value >= identity)
                {
                    return Err(QualificationError::InvalidIndex);
                }
                previous = Some(identity);
            }
            Ok(index)
        })
    }

    /// Returns the byte-sorted exact bindings.
    #[must_use]
    pub fn entries(&self) -> &[QualificationIndexEntry] {
        &self.entries
    }

    /// Finds a trusted qualification ID for an exact profile and target.
    #[must_use]
    pub fn qualification_id(&self, profile: &str, target: QualificationTarget) -> Option<&str> {
        self.entries
            .binary_search_by(|entry| {
                (entry.profile.as_str(), entry.target).cmp(&(profile, target))
            })
            .ok()
            .map(|index| self.entries[index].qualification_id.as_str())
    }
}

impl QualificationIndexEntry {
    /// Returns the exact `id/version` profile subject.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Returns the exact qualified target.
    #[must_use]
    pub const fn target(&self) -> QualificationTarget {
        self.target
    }

    /// Returns the trusted qualification ID.
    #[must_use]
    pub fn qualification_id(&self) -> &str {
        &self.qualification_id
    }
}

impl QualificationTrustKey {
    fn validate(&self) -> Result<(), QualificationError> {
        let _ = decode_fixed::<32>(&self.public_key_base64url)?;
        let mut previous: Option<&str> = None;
        for domain in &self.allowed_domains {
            if !lower_token(domain)
                || previous.is_some_and(|candidate| candidate >= domain.as_str())
            {
                return Err(QualificationError::InvalidTrustKey);
            }
            previous = Some(domain);
        }
        if !registered_token(&self.key_id)
            || self.algorithm != "Ed25519"
            || self.allowed_domains.is_empty()
            || self.allowed_domains.len() > 64
            || (self.not_after_unix_seconds != 0
                && self.not_after_unix_seconds < self.not_before_unix_seconds)
        {
            return Err(QualificationError::InvalidTrustKey);
        }
        Ok(())
    }

    /// Returns the stable trust-key identifier.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the byte-sorted domains this key may qualify.
    #[must_use]
    pub fn allowed_domains(&self) -> &[String] {
        &self.allowed_domains
    }

    /// Returns the inclusive key activation time.
    #[must_use]
    pub const fn not_before_unix_seconds(&self) -> u64 {
        self.not_before_unix_seconds
    }

    /// Returns zero for no scheduled expiry, otherwise the inclusive expiry.
    #[must_use]
    pub const fn not_after_unix_seconds(&self) -> u64 {
        self.not_after_unix_seconds
    }
}

impl QualificationRecord {
    /// Parses and validates canonical `auths.profile-qualification/1` JSON.
    pub fn from_json(bytes: &[u8]) -> Result<Self, QualificationError> {
        canonical_parse(bytes, MAX_RECORD_BYTES).and_then(|record: Self| {
            record.validate()?;
            Ok(record)
        })
    }

    /// Returns canonical JCS bytes for this already-validated record.
    pub fn canonical_json(&self) -> Result<Vec<u8>, QualificationError> {
        canonical_bytes(self)
    }

    /// Returns SHA-256 of the exact canonical verified record bytes.
    pub fn sha256(&self) -> Result<String, QualificationError> {
        Ok(hex::encode(Sha256::digest(self.canonical_json()?)))
    }

    /// Finalizes a complete canonical protected record with an empty ID.
    ///
    /// Every final field must already have been independently reconstructed by
    /// trusted attester code. Candidate proposals are a distinct schema and
    /// cannot be passed to this function.
    pub fn finalize_json(bytes: &[u8]) -> Result<Self, QualificationError> {
        if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
            return Err(QualificationError::Limit);
        }
        let mut value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| QualificationError::Malformed)?;
        if canonical_bytes(&value)?.as_slice() != bytes {
            return Err(QualificationError::NonCanonical);
        }
        let object = value
            .as_object_mut()
            .ok_or(QualificationError::InvalidRecord)?;
        if object
            .get("qualificationId")
            .and_then(serde_json::Value::as_str)
            != Some("")
        {
            return Err(QualificationError::InvalidRecord);
        }
        let mut record: Self =
            serde_json::from_value(value).map_err(|_| QualificationError::Malformed)?;
        record.qualification_id = record.recompute_qualification_id()?;
        record.validate()?;
        Ok(record)
    }

    /// Returns the signature preimage for the qualification attestation.
    pub fn signature_preimage(&self) -> Result<Vec<u8>, QualificationError> {
        let canonical = self.canonical_json()?;
        let mut preimage = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 1 + canonical.len());
        preimage.extend_from_slice(SIGNATURE_DOMAIN);
        preimage.push(0);
        preimage.extend_from_slice(&canonical);
        Ok(preimage)
    }

    fn validate(&self) -> Result<(), QualificationError> {
        if self.schema != "auths.profile-qualification/1"
            || !lower_token(&self.domain)
            || !(1..=8).contains(&self.profiles.len())
            || !lower_hex(&self.candidate_revision, 40)
            || !digest(&self.semantic_closure_sha256)
            || !digest(&self.package_manifest_sha256)
            || !digest(&self.error_registry_sha256)
            || !digest(&self.provider_matrix_sha256)
            || !digest(&self.proposal_sha256)
            || self.environment_class != "disposable-provider-test"
            || self.started_at_unix_seconds >= self.completed_at_unix_seconds
            || self
                .completed_at_unix_seconds
                .checked_sub(self.started_at_unix_seconds)
                .is_none_or(|duration| duration > MAX_QUALIFICATION_SECONDS)
        {
            return Err(QualificationError::InvalidRecord);
        }
        self.validate_profiles()?;
        self.validate_runtime_digests()?;
        self.toolchain.validate()?;
        self.workflow.validate()?;
        self.release_build.validate()?;
        self.artifact.validate()?;
        self.validate_provider_runs()?;
        self.protected_observation.validate()?;
        self.validate_scenarios()?;
        self.receipt_verification.validate()?;
        self.secret_scan.validate()?;
        if self.recompute_qualification_id()? != self.qualification_id {
            return Err(QualificationError::QualificationIdMismatch);
        }
        Ok(())
    }

    fn validate_profiles(&self) -> Result<(), QualificationError> {
        let prefix = format!("auths.{}.", self.domain);
        let mut previous: Option<(&str, u16)> = None;
        for profile in &self.profiles {
            let identity = (profile.id.as_str(), profile.version);
            if profile.version == 0
                || !profile.id.starts_with(&prefix)
                || !semantic_id(&profile.id)
                || previous.is_some_and(|value| value >= identity)
            {
                return Err(QualificationError::InvalidProfileSet);
            }
            previous = Some(identity);
        }
        Ok(())
    }

    fn validate_runtime_digests(&self) -> Result<(), QualificationError> {
        if self.profile_runtime_digests.len() != self.profiles.len() {
            return Err(QualificationError::InvalidRuntimeDigests);
        }
        for (profile, runtime) in self.profiles.iter().zip(&self.profile_runtime_digests) {
            if runtime.profile != profile.semantic_subject() || !digest(&runtime.sha256) {
                return Err(QualificationError::InvalidRuntimeDigests);
            }
        }
        Ok(())
    }

    fn validate_scenarios(&self) -> Result<(), QualificationError> {
        if !(1..=256).contains(&self.scenarios.len()) {
            return Err(QualificationError::InvalidScenarios);
        }
        let mut previous: Option<&str> = None;
        for scenario in &self.scenarios {
            if !registered_token(&scenario.id)
                || scenario.status != "passed"
                || !(1..=100_000).contains(&scenario.assertions)
                || !digest(&scenario.report_sha256)
                || scenario.provider_run_ids.is_empty()
                || scenario.provider_run_ids.len() > 16
                || !sorted_unique_tokens(&scenario.provider_run_ids)
                || scenario.provider_run_ids.iter().any(|run| {
                    self.provider_runs
                        .binary_search_by(|candidate| candidate.id.as_str().cmp(run))
                        .is_err()
                })
                || previous.is_some_and(|value| value >= scenario.id.as_str())
            {
                return Err(QualificationError::InvalidScenarios);
            }
            previous = Some(&scenario.id);
        }
        Ok(())
    }

    fn validate_provider_runs(&self) -> Result<(), QualificationError> {
        if self.provider_runs.is_empty() || self.provider_runs.len() > 16 {
            return Err(QualificationError::InvalidProviderRuns);
        }
        let mut previous: Option<&str> = None;
        for run in &self.provider_runs {
            run.validate()?;
            if previous.is_some_and(|value| value >= run.id.as_str()) {
                return Err(QualificationError::InvalidProviderRuns);
            }
            previous = Some(&run.id);
        }
        Ok(())
    }

    fn recompute_qualification_id(&self) -> Result<String, QualificationError> {
        let mut candidate = self.clone();
        candidate.qualification_id.clear();
        let canonical = canonical_bytes(&candidate)?;
        Ok(format!(
            "qlf_{}",
            Base64UrlUnpadded::encode_string(&Sha256::digest(canonical))
        ))
    }

    /// Returns the content-derived qualification identifier.
    #[must_use]
    pub fn qualification_id(&self) -> &str {
        &self.qualification_id
    }

    /// Returns the domain qualified by this record.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns the exact atomic profile family.
    #[must_use]
    pub fn profiles(&self) -> &[QualificationProfile] {
        &self.profiles
    }

    /// Returns the exact tested target.
    #[must_use]
    pub const fn target(&self) -> QualificationTarget {
        self.target
    }

    /// Returns the exact candidate Git revision.
    #[must_use]
    pub fn candidate_revision(&self) -> &str {
        &self.candidate_revision
    }

    /// Returns the semantic-closure digest.
    #[must_use]
    pub fn semantic_closure_sha256(&self) -> &str {
        &self.semantic_closure_sha256
    }

    /// Returns the package-manifest digest.
    #[must_use]
    pub fn package_manifest_sha256(&self) -> &str {
        &self.package_manifest_sha256
    }

    /// Returns the negotiated runtime-contract digest for an exact profile.
    #[must_use]
    pub fn profile_runtime_sha256(&self, profile: &str) -> Option<&str> {
        self.profile_runtime_digests
            .binary_search_by(|entry| entry.profile.as_str().cmp(profile))
            .ok()
            .map(|index| self.profile_runtime_digests[index].sha256.as_str())
    }

    /// Returns the error-registry digest.
    #[must_use]
    pub fn error_registry_sha256(&self) -> &str {
        &self.error_registry_sha256
    }

    /// Returns the exact checked provider-matrix digest.
    #[must_use]
    pub fn provider_matrix_sha256(&self) -> &str {
        &self.provider_matrix_sha256
    }

    /// Returns the exact canonical candidate-proposal digest.
    #[must_use]
    pub fn proposal_sha256(&self) -> &str {
        &self.proposal_sha256
    }

    /// Returns the completed-at timestamp used for key validity.
    #[must_use]
    pub const fn completed_at_unix_seconds(&self) -> u64 {
        self.completed_at_unix_seconds
    }

    /// Returns the passed scenario roster.
    #[must_use]
    pub fn scenarios(&self) -> &[QualificationScenario] {
        &self.scenarios
    }

    /// Returns the exact protected provider-version runs.
    #[must_use]
    pub fn provider_runs(&self) -> &[QualificationProviderRun] {
        &self.provider_runs
    }

    /// Returns the protected workflow path that produced this record.
    #[must_use]
    pub fn workflow_path(&self) -> &str {
        &self.workflow.workflow_path
    }

    /// Returns the immutable GitHub repository identifier.
    #[must_use]
    pub fn repository_id(&self) -> &str {
        &self.workflow.repository_id
    }

    /// Returns the protected workflow revision.
    #[must_use]
    pub fn workflow_revision(&self) -> &str {
        &self.workflow.workflow_revision
    }

    /// Returns the reviewed attester revision.
    #[must_use]
    pub fn attester_revision(&self) -> &str {
        &self.workflow.attester_revision
    }

    /// Returns the immutable workflow run identifier.
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.workflow.run_id
    }

    /// Returns the workflow run attempt.
    #[must_use]
    pub const fn run_attempt(&self) -> u32 {
        self.workflow.run_attempt
    }

    /// Returns the protected environment bound by the workflow entrypoint.
    #[must_use]
    pub fn protected_environment(&self) -> &str {
        &self.workflow.protected_environment
    }

    /// Returns the independently verified authoritative release build.
    #[must_use]
    pub const fn release_build(&self) -> &QualificationReleaseBuild {
        &self.release_build
    }

    /// Returns raw evidence artifact metadata.
    #[must_use]
    pub const fn artifact(&self) -> &QualificationArtifact {
        &self.artifact
    }
}

impl QualificationVerifiedRecordBinding {
    /// Builds the only handoff accepted by the minimal signer.
    pub fn from_record(record: &QualificationRecord) -> Result<Self, QualificationError> {
        let binding = Self {
            schema: "auths.profile-qualification-verified-binding/1".to_owned(),
            record_sha256: record.sha256()?,
            qualification_id: record.qualification_id().to_owned(),
            repository_id: record.repository_id().to_owned(),
            workflow_path: record.workflow_path().to_owned(),
            workflow_revision: record.workflow_revision().to_owned(),
            attester_revision: record.attester_revision().to_owned(),
            run_id: record.run_id().to_owned(),
            run_attempt: record.run_attempt(),
            candidate_revision: record.candidate_revision().to_owned(),
            domain: record.domain().to_owned(),
            target: record.target(),
            artifact_id: record.artifact().artifact_id().to_owned(),
            uploaded_archive_sha256: record.artifact().uploaded_archive_sha256().to_owned(),
            release_build_sha256: record.release_build().sha256()?,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Parses one canonical, bounded verifier-to-signer binding.
    pub fn from_json(bytes: &[u8]) -> Result<Self, QualificationError> {
        canonical_document_parse(bytes, MAX_VERIFIED_BINDING_BYTES).and_then(|binding: Self| {
            binding.validate()?;
            Ok(binding)
        })
    }

    /// Returns exact canonical binding bytes.
    pub fn canonical_json(&self) -> Result<Vec<u8>, QualificationError> {
        canonical_bytes(self)
    }

    /// Requires the bound record digest and every protected identity to match.
    pub fn require_matches_record(
        &self,
        record: &QualificationRecord,
    ) -> Result<(), QualificationError> {
        let expected = Self::from_record(record)?;
        if self == &expected {
            Ok(())
        } else {
            Err(QualificationError::InvalidVerifiedBinding)
        }
    }

    fn validate(&self) -> Result<(), QualificationError> {
        if self.schema != "auths.profile-qualification-verified-binding/1"
            || !digest(&self.record_sha256)
            || !qualification_id(&self.qualification_id)
            || !decimal_token(&self.repository_id, 32)
            || !safe_path(&self.workflow_path)
            || !self
                .workflow_path
                .starts_with(".github/workflows/profile-qualification-")
            || !self.workflow_path.ends_with(".yml")
            || !lower_hex(&self.workflow_revision, 40)
            || !lower_hex(&self.attester_revision, 40)
            || !decimal_token(&self.run_id, 32)
            || self.run_attempt == 0
            || !lower_hex(&self.candidate_revision, 40)
            || !lower_token(&self.domain)
            || !decimal_token(&self.artifact_id, 32)
            || !digest(&self.uploaded_archive_sha256)
            || !digest(&self.release_build_sha256)
        {
            return Err(QualificationError::InvalidVerifiedBinding);
        }
        Ok(())
    }
}

impl QualificationProposal {
    /// Parses exact canonical `auths.profile-qualification-proposal/1` JSON.
    pub fn from_json(bytes: &[u8]) -> Result<Self, QualificationError> {
        canonical_parse(bytes, MAX_PROPOSAL_BYTES).and_then(|proposal: Self| {
            proposal.validate()?;
            Ok(proposal)
        })
    }

    /// Returns exact canonical proposal bytes.
    pub fn canonical_json(&self) -> Result<Vec<u8>, QualificationError> {
        canonical_bytes(self)
    }

    /// Returns SHA-256 of the exact canonical proposal bytes.
    pub fn sha256(&self) -> Result<String, QualificationError> {
        Ok(hex::encode(Sha256::digest(self.canonical_json()?)))
    }

    fn validate(&self) -> Result<(), QualificationError> {
        if self.schema != "auths.profile-qualification-proposal/1"
            || !lower_token(&self.domain)
            || !(1..=8).contains(&self.profiles.len())
            || !lower_hex(&self.candidate_revision, 40)
            || !digest(&self.semantic_closure_sha256)
            || !digest(&self.package_manifest_sha256)
            || !digest(&self.error_registry_sha256)
            || !digest(&self.provider_matrix_sha256)
            || self.environment_class != "disposable-provider-test"
            || self.collection_started_at_unix_seconds >= self.collection_completed_at_unix_seconds
            || self
                .collection_completed_at_unix_seconds
                .checked_sub(self.collection_started_at_unix_seconds)
                .is_none_or(|duration| duration > MAX_QUALIFICATION_SECONDS)
        {
            return Err(QualificationError::InvalidProposal);
        }
        validate_profiles(&self.domain, &self.profiles)?;
        validate_runtime_digests(&self.profiles, &self.profile_runtime_digests)?;
        self.toolchain.validate()?;
        validate_candidate_artifacts(&self.candidate_artifacts)?;
        validate_provider_runs(&self.provider_runs)?;
        validate_scenarios(&self.scenarios, &self.provider_runs)?;
        self.receipt_verification.validate()?;
        self.secret_scan.validate()?;
        Ok(())
    }

    /// Requires every candidate-owned claim to equal the protected record.
    pub fn require_matches_record(
        &self,
        record: &QualificationRecord,
    ) -> Result<(), QualificationError> {
        let receipt_matches = self.receipt_verification.rust == record.receipt_verification.rust
            && self.receipt_verification.python == record.receipt_verification.python
            && self.receipt_verification.typescript == record.receipt_verification.typescript
            && self.receipt_verification.portable_receipt_schema
                == record.receipt_verification.portable_receipt_schema;
        if self.domain != record.domain
            || self.profiles != record.profiles
            || self.target != record.target
            || self.candidate_revision != record.candidate_revision
            || self.semantic_closure_sha256 != record.semantic_closure_sha256
            || self.package_manifest_sha256 != record.package_manifest_sha256
            || self.profile_runtime_digests != record.profile_runtime_digests
            || self.error_registry_sha256 != record.error_registry_sha256
            || self.provider_matrix_sha256 != record.provider_matrix_sha256
            || self.toolchain != record.toolchain
            || self.candidate_artifacts.len() != record.release_build.artifacts.len()
            || self
                .candidate_artifacts
                .iter()
                .zip(&record.release_build.artifacts)
                .any(|(candidate, protected)| {
                    candidate.role != protected.role
                        || candidate.member_sha256 != protected.member_sha256
                        || candidate.bytes != protected.bytes
                })
            || self.environment_class != record.environment_class
            || self.provider_runs != record.provider_runs
            || self.scenarios != record.scenarios
            || !receipt_matches
            || self.secret_scan != record.secret_scan
            || self.sha256()? != record.proposal_sha256
        {
            return Err(QualificationError::ProposalMismatch);
        }
        Ok(())
    }

    /// Returns the proposed domain.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns the proposed target.
    #[must_use]
    pub const fn target(&self) -> QualificationTarget {
        self.target
    }

    /// Returns the candidate revision.
    #[must_use]
    pub fn candidate_revision(&self) -> &str {
        &self.candidate_revision
    }

    /// Returns the exact profile family proposed for qualification.
    #[must_use]
    pub fn profiles(&self) -> &[QualificationProfile] {
        &self.profiles
    }

    /// Returns the exact provider-run roster used by installed consumers.
    #[must_use]
    pub fn provider_runs(&self) -> &[QualificationProviderRun] {
        &self.provider_runs
    }

    /// Returns the exact scenario roster used by installed consumers.
    #[must_use]
    pub fn scenarios(&self) -> &[QualificationScenario] {
        &self.scenarios
    }

    /// Returns the immutable release artifact claims in role order.
    #[must_use]
    pub fn candidate_artifacts(&self) -> &[QualificationCandidateArtifact] {
        &self.candidate_artifacts
    }

    /// Returns the pinned Rust, Node, and Python toolchain values.
    #[must_use]
    pub fn toolchain_values(&self) -> (&str, &str, &str) {
        (
            &self.toolchain.rust,
            &self.toolchain.node,
            &self.toolchain.python,
        )
    }
}

impl QualificationProfile {
    /// Returns the profile identifier without its version suffix.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the profile semantic version.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// Returns the exact semantic subject `id/version`.
    #[must_use]
    pub fn semantic_subject(&self) -> String {
        format!("{}/{}", self.id, self.version)
    }
}

impl QualificationToolchain {
    fn validate(&self) -> Result<(), QualificationError> {
        if [self.rust.as_str(), self.node.as_str(), self.python.as_str()]
            .into_iter()
            .all(|value| printable(value, 128))
        {
            Ok(())
        } else {
            Err(QualificationError::InvalidRecord)
        }
    }
}

impl QualificationWorkflow {
    fn validate(&self) -> Result<(), QualificationError> {
        if self.provider != "github-actions"
            || !decimal_token(&self.repository_id, 32)
            || !safe_path(&self.workflow_path)
            || !self
                .workflow_path
                .starts_with(".github/workflows/profile-qualification-")
            || !self.workflow_path.ends_with(".yml")
            || !lower_hex(&self.workflow_revision, 40)
            || !lower_hex(&self.attester_revision, 40)
            || !decimal_token(&self.run_id, 32)
            || self.run_attempt == 0
            || !registered_token(&self.protected_environment)
        {
            return Err(QualificationError::InvalidWorkflow);
        }
        Ok(())
    }
}

impl QualificationReleaseBuild {
    /// Parses an independently verified canonical release-build projection.
    pub fn from_json(bytes: &[u8]) -> Result<Self, QualificationError> {
        canonical_parse(bytes, MAX_RECORD_BYTES).and_then(|build: Self| {
            build.validate()?;
            Ok(build)
        })
    }

    /// Returns exact canonical bytes for digest binding and protected handoff.
    pub fn canonical_json(&self) -> Result<Vec<u8>, QualificationError> {
        canonical_bytes(self)
    }

    /// Returns SHA-256 over the exact canonical release-build projection.
    pub fn sha256(&self) -> Result<String, QualificationError> {
        Ok(hex::encode(Sha256::digest(self.canonical_json()?)))
    }

    fn validate(&self) -> Result<(), QualificationError> {
        if self.provider != "github-actions"
            || !decimal_token(&self.repository_id, 32)
            || self.workflow_path != ".github/workflows/release-builder.yml"
            || !lower_hex(&self.workflow_revision, 40)
            || !decimal_token(&self.run_id, 32)
            || self.run_attempt == 0
            || self.run_label != "official"
            || !digest(&self.qualification_surface_sha256)
            || self.artifacts.len() != RELEASE_BUILD_ARTIFACT_ROLES.len()
        {
            return Err(QualificationError::InvalidReleaseBuild);
        }
        let mut paths = std::collections::BTreeSet::new();
        for (artifact, expected_role) in self.artifacts.iter().zip(RELEASE_BUILD_ARTIFACT_ROLES) {
            if artifact.role != expected_role
                || !decimal_token(&artifact.artifact_id, 32)
                || !digest(&artifact.uploaded_archive_sha256)
                || !safe_path(&artifact.member_path)
                || !paths.insert(artifact.member_path.as_str())
                || !digest(&artifact.member_sha256)
                || !(1..=MAX_ARTIFACT_BYTES).contains(&artifact.bytes)
            {
                return Err(QualificationError::InvalidReleaseBuild);
            }
        }
        Ok(())
    }

    /// Returns the immutable repository identifier of the build run.
    #[must_use]
    pub fn repository_id(&self) -> &str {
        &self.repository_id
    }

    /// Returns the exact six authoritative artifact rows.
    #[must_use]
    pub fn artifacts(&self) -> &[QualificationReleaseBuildArtifact] {
        &self.artifacts
    }

    /// Returns the closed isolated build label.
    #[must_use]
    pub fn run_label(&self) -> &str {
        &self.run_label
    }
}

impl QualificationReleaseBuildArtifact {
    /// Returns the closed artifact role.
    #[must_use]
    pub fn role(&self) -> &str {
        &self.role
    }

    /// Returns the exact member digest.
    #[must_use]
    pub fn member_sha256(&self) -> &str {
        &self.member_sha256
    }

    /// Returns the exact member length.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl QualificationCandidateArtifact {
    /// Returns the closed release artifact role.
    #[must_use]
    pub fn role(&self) -> &str {
        &self.role
    }

    /// Returns the exact candidate-owned member digest.
    #[must_use]
    pub fn member_sha256(&self) -> &str {
        &self.member_sha256
    }

    /// Returns the exact candidate-owned member length.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl QualificationArtifact {
    fn validate(&self) -> Result<(), QualificationError> {
        let minimum_expiry = self
            .created_at_unix_seconds
            .checked_add(u64::from(self.retention_days) * 86_400);
        if digest(&self.evidence_tar_sha256)
            && (1..=MAX_ARTIFACT_BYTES).contains(&self.evidence_tar_bytes)
            && (90..=365).contains(&self.retention_days)
            && self.created_at_unix_seconds > 0
            && minimum_expiry.is_some_and(|minimum| self.expires_at_unix_seconds >= minimum)
            && digest(&self.redaction_report_sha256)
            && self.storage_provider == "github-actions"
            && decimal_token(&self.artifact_id, 32)
            && digest(&self.uploaded_archive_sha256)
        {
            Ok(())
        } else {
            Err(QualificationError::InvalidArtifact)
        }
    }

    /// Returns the raw evidence artifact digest.
    #[must_use]
    pub fn evidence_tar_sha256(&self) -> &str {
        &self.evidence_tar_sha256
    }

    /// Returns the bounded raw artifact byte length.
    #[must_use]
    pub const fn evidence_tar_bytes(&self) -> u64 {
        self.evidence_tar_bytes
    }

    /// Returns the immutable GitHub Actions artifact identifier.
    #[must_use]
    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }

    /// Returns the digest reported for the immutable uploaded archive.
    #[must_use]
    pub fn uploaded_archive_sha256(&self) -> &str {
        &self.uploaded_archive_sha256
    }

    /// Returns the promised hosted-artifact retention duration.
    #[must_use]
    pub const fn retention_days(&self) -> u16 {
        self.retention_days
    }

    /// Returns the immutable hosted-artifact expiry timestamp.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }
}

impl QualificationProviderRun {
    fn validate(&self) -> Result<(), QualificationError> {
        if registered_token(&self.id)
            && printable(&self.provider_version, 128)
            && digest(&self.provider_artifact_sha256)
            && digest(&self.scenario_set_sha256)
            && self.status == "passed"
        {
            Ok(())
        } else {
            Err(QualificationError::InvalidProviderRuns)
        }
    }

    /// Returns the stable provider-run identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the observed provider/tool version.
    #[must_use]
    pub fn provider_version(&self) -> &str {
        &self.provider_version
    }

    /// Returns the immutable provider artifact digest.
    #[must_use]
    pub fn provider_artifact_sha256(&self) -> &str {
        &self.provider_artifact_sha256
    }

    /// Returns the canonical scenario-set digest for this provider run.
    #[must_use]
    pub fn scenario_set_sha256(&self) -> &str {
        &self.scenario_set_sha256
    }
}

impl QualificationProtectedObservation {
    fn validate(&self) -> Result<(), QualificationError> {
        if self.schema == "auths.profile-qualification-observation/1"
            && registered_token(&self.key_id)
            && digest(&self.sha256)
        {
            Ok(())
        } else {
            Err(QualificationError::InvalidObservation)
        }
    }
}

impl QualificationScenario {
    /// Returns the stable scenario identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the number of assertions proved by the scenario report.
    #[must_use]
    pub const fn assertions(&self) -> u32 {
        self.assertions
    }

    /// Returns the canonical scenario report digest.
    #[must_use]
    pub fn report_sha256(&self) -> &str {
        &self.report_sha256
    }

    /// Returns the exact provider runs covered by this scenario.
    #[must_use]
    pub fn provider_run_ids(&self) -> &[String] {
        &self.provider_run_ids
    }
}

impl QualificationScenarioManifest {
    /// Parses a bounded scenario manifest and rejects duplicate or unsorted IDs.
    pub fn from_json(bytes: &[u8]) -> Result<Self, QualificationError> {
        if bytes.is_empty() || bytes.len() > MAX_SCENARIO_MANIFEST_BYTES {
            return Err(QualificationError::Limit);
        }
        let manifest: Self =
            serde_json::from_slice(bytes).map_err(|_| QualificationError::Malformed)?;
        if manifest.schema != "auths.profile-qualification-scenarios/2"
            || (manifest.domain != "common" && !lower_token(&manifest.domain))
            || manifest.programs.is_empty()
            || manifest.programs.len() > 256
        {
            return Err(QualificationError::InvalidScenarios);
        }
        let mut previous: Option<&str> = None;
        for program in &manifest.programs {
            if program.validate().is_err()
                || previous.is_some_and(|value| value >= program.id.as_str())
            {
                return Err(QualificationError::InvalidScenarios);
            }
            previous = Some(&program.id);
        }
        Ok(manifest)
    }

    /// Returns `common` or the exact owning domain.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns the byte-sorted scenario IDs.
    #[must_use]
    pub fn programs(&self) -> &[QualificationScenarioProgramV1] {
        &self.programs
    }

    /// Looks up one exact executable scenario contract.
    #[must_use]
    pub fn program(&self, id: &str) -> Option<&QualificationScenarioProgramV1> {
        self.programs
            .binary_search_by(|program| program.id.as_str().cmp(id))
            .ok()
            .map(|index| &self.programs[index])
    }
}

/// Resolves one domain or common executable scenario and returns its exact
/// canonical commitment. Domain programs cannot shadow common IDs.
pub fn qualification_scenario_program_sha256(
    common_bytes: &[u8],
    domain_bytes: &[u8],
    expected_domain: &str,
    scenario_id: &str,
) -> Result<String, QualificationError> {
    qualification_scenario_program(common_bytes, domain_bytes, expected_domain, scenario_id)?
        .sha256()
}

/// Resolves and clones one exact executable scenario program.
pub fn qualification_scenario_program(
    common_bytes: &[u8],
    domain_bytes: &[u8],
    expected_domain: &str,
    scenario_id: &str,
) -> Result<QualificationScenarioProgramV1, QualificationError> {
    let common = QualificationScenarioManifest::from_json(common_bytes)?;
    let domain = QualificationScenarioManifest::from_json(domain_bytes)?;
    if common.domain != "common"
        || domain.domain != expected_domain
        || !lower_token(expected_domain)
        || common
            .programs
            .iter()
            .any(|program| domain.program(&program.id).is_some())
    {
        return Err(QualificationError::InvalidScenarios);
    }
    Ok(domain
        .program(scenario_id)
        .or_else(|| common.program(scenario_id))
        .ok_or(QualificationError::InvalidScenarios)?
        .clone())
}

impl QualificationScenarioProgramV1 {
    fn validate(&self) -> Result<(), QualificationError> {
        if !registered_token(&self.id)
            || self.cases.is_empty()
            || self.cases.len() > 32
            || self.hooks.len() > 16
            || !self.cases.windows(2).all(|pair| {
                (pair[0].group, pair[0].role, pair[0].case_id.as_str())
                    < (pair[1].group, pair[1].role, pair[1].case_id.as_str())
            })
            || self.cases.iter().any(|case| {
                !registered_token(&case.case_id)
                    || !registered_token(&case.intent_id)
                    || !registered_token(&case.stimulus)
                    || case.group == 0
                    || case.expected_provider_calls > 1
            })
            || self
                .cases
                .windows(2)
                .any(|pair| pair[0].expectation != pair[1].expectation)
            || !self
                .hooks
                .windows(2)
                .all(|pair| hook_order(&self.cases, &pair[0]) < hook_order(&self.cases, &pair[1]))
            || self.hooks.iter().any(|hook| {
                !registered_token(&hook.case_id)
                    || !registered_token(&hook.hook)
                    || !self.cases.iter().any(|case| case.case_id == hook.case_id)
            })
        {
            return Err(QualificationError::InvalidScenarios);
        }
        for group in self.cases.iter().map(|case| case.group) {
            let mut cases = self.cases.iter().filter(|case| case.group == group);
            let Some(first) = cases.next() else {
                return Err(QualificationError::InvalidScenarios);
            };
            if cases.any(|case| case.topology != first.topology)
                || (first.topology == QualificationScenarioTopology::Parallel
                    && self.cases.iter().filter(|case| case.group == group).count() < 2)
            {
                return Err(QualificationError::InvalidScenarios);
            }
        }
        Ok(())
    }

    /// Stable scenario ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Ordered installed-client case roster.
    #[must_use]
    pub fn cases(&self) -> &[QualificationScenarioCaseV1] {
        &self.cases
    }

    /// Ordered protected hook schedule.
    #[must_use]
    pub fn hooks(&self) -> &[QualificationScenarioHookV1] {
        &self.hooks
    }

    /// SHA-256 of this exact canonical executable contract.
    pub fn sha256(&self) -> Result<String, QualificationError> {
        self.validate()?;
        let canonical =
            serde_json_canonicalizer::to_vec(self).map_err(|_| QualificationError::Malformed)?;
        Ok(hex::encode(Sha256::digest(canonical)))
    }
}

impl QualificationScenarioCaseV1 {
    #[must_use]
    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    /// Stable logical request identity. Replay and changed-input cases may
    /// intentionally share this value.
    #[must_use]
    pub fn intent_id(&self) -> &str {
        &self.intent_id
    }

    /// Closed domain-owned stimulus selected by protected setup and hooks.
    #[must_use]
    pub fn stimulus(&self) -> &str {
        &self.stimulus
    }

    #[must_use]
    pub const fn role(&self) -> QualificationOperationRole {
        self.role
    }

    #[must_use]
    pub const fn group(&self) -> u8 {
        self.group
    }

    #[must_use]
    pub const fn topology(&self) -> QualificationScenarioTopology {
        self.topology
    }

    #[must_use]
    pub const fn expectation(&self) -> QualificationScenarioExpectation {
        self.expectation
    }

    #[must_use]
    pub const fn expected_outcome(&self) -> QualificationOutcomeKind {
        self.expected_outcome
    }

    #[must_use]
    pub const fn expected_effect(&self) -> QualificationEffect {
        self.expected_effect
    }

    #[must_use]
    pub const fn expected_provider_calls(&self) -> u32 {
        self.expected_provider_calls
    }
}

impl QualificationScenarioHookV1 {
    /// Exact installed-client case to which this protected hook belongs.
    #[must_use]
    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    #[must_use]
    pub const fn stage(&self) -> QualificationScenarioHookStage {
        self.stage
    }

    #[must_use]
    pub fn hook(&self) -> &str {
        &self.hook
    }
}

fn hook_order<'a>(
    cases: &[QualificationScenarioCaseV1],
    hook: &'a QualificationScenarioHookV1,
) -> (u8, usize, &'a str) {
    let stage = match hook.stage {
        QualificationScenarioHookStage::Setup => 0,
        QualificationScenarioHookStage::BeforeCall => 1,
        QualificationScenarioHookStage::BeforeProvider => 2,
        QualificationScenarioHookStage::AfterProviderBeforeResponse => 3,
        QualificationScenarioHookStage::BeforeObserver => 4,
        QualificationScenarioHookStage::StateFileCorruption => 5,
    };
    let case = cases
        .iter()
        .position(|case| case.case_id == hook.case_id)
        .unwrap_or(usize::MAX);
    (stage, case, hook.hook.as_str())
}

impl QualificationReceiptVerification {
    fn validate(&self) -> Result<(), QualificationError> {
        if self.rust == "passed"
            && self.python == "passed"
            && self.typescript == "passed"
            && self.portable_receipt_schema == "auths.portable-receipt/1"
            && digest(&self.receipt_trust_anchor_sha256)
            && printable(&self.decision_verification_method, 512)
            && printable(&self.execution_verification_method, 512)
            && self.decision_verification_method != self.execution_verification_method
        {
            Ok(())
        } else {
            Err(QualificationError::InvalidReceiptEvidence)
        }
    }
}

impl QualificationProposalReceiptVerification {
    fn validate(&self) -> Result<(), QualificationError> {
        if self.rust == "passed"
            && self.python == "passed"
            && self.typescript == "passed"
            && self.portable_receipt_schema == "auths.portable-receipt/1"
        {
            Ok(())
        } else {
            Err(QualificationError::InvalidReceiptEvidence)
        }
    }
}

impl QualificationSecretScan {
    fn validate(&self) -> Result<(), QualificationError> {
        if self.tool == "gitleaks-8.28.0" && self.status == "passed" && digest(&self.report_sha256)
        {
            Ok(())
        } else {
            Err(QualificationError::InvalidSecretScan)
        }
    }
}

impl QualificationAttestation {
    /// Signs a finalized record inside the protected release signer.
    pub fn sign_json(
        record: QualificationRecord,
        key_id: &str,
        seed_base64url: &str,
    ) -> Result<Vec<u8>, QualificationError> {
        record.validate()?;
        if !registered_token(key_id) {
            return Err(QualificationError::InvalidAttestation);
        }
        let seed = decode_fixed::<32>(seed_base64url)?;
        let signature = SigningKey::from_bytes(&seed)
            .sign(&record.signature_preimage()?)
            .to_bytes();
        canonical_bytes(&Self {
            schema: "auths.profile-qualification-attestation/1".into(),
            record,
            signing: QualificationSigning {
                algorithm: "Ed25519".into(),
                key_id: key_id.into(),
                signature_base64url: Base64UrlUnpadded::encode_string(&signature),
            },
        })
    }

    /// Parses canonical bounded attestation JSON without trusting its signature.
    pub fn from_json(bytes: &[u8]) -> Result<Self, QualificationError> {
        canonical_parse(bytes, MAX_ATTESTATION_BYTES).and_then(|attestation: Self| {
            if attestation.schema != "auths.profile-qualification-attestation/1"
                || attestation.signing.algorithm != "Ed25519"
                || !registered_token(&attestation.signing.key_id)
            {
                return Err(QualificationError::InvalidAttestation);
            }
            attestation.record.validate()?;
            let _ = decode_fixed::<64>(&attestation.signing.signature_base64url)?;
            Ok(attestation)
        })
    }

    /// Verifies a canonical attestation against a trusted, current public key.
    pub fn verify_json(
        bytes: &[u8],
        registry: &QualificationTrustRegistry,
        now_unix_seconds: u64,
    ) -> Result<VerifiedQualification, QualificationError> {
        let attestation = Self::from_json(bytes)?;
        let key = registry.find(&attestation.signing.key_id)?;
        let completed = attestation.record.completed_at_unix_seconds;
        if !key.valid_at(completed) || !key.valid_at(now_unix_seconds) {
            return Err(QualificationError::TrustKeyNotCurrent);
        }
        if key
            .allowed_domains
            .binary_search_by(|domain| domain.as_str().cmp(attestation.record.domain()))
            .is_err()
        {
            return Err(QualificationError::TrustKeyDomainMismatch);
        }
        let public_key = decode_fixed::<32>(&key.public_key_base64url)?;
        let signature = decode_fixed::<64>(&attestation.signing.signature_base64url)?;
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| QualificationError::InvalidTrustKey)?
            .verify_strict(
                &attestation.record.signature_preimage()?,
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| QualificationError::InvalidSignature)?;
        Ok(VerifiedQualification {
            record: attestation.record,
            key_id: key.key_id.clone(),
        })
    }

    /// Returns the enclosed qualification record.
    #[must_use]
    pub const fn record(&self) -> &QualificationRecord {
        &self.record
    }
}

impl QualificationObservationRecord {
    /// Parses one exact canonical protected-observation record.
    pub fn from_json(bytes: &[u8]) -> Result<Self, QualificationError> {
        canonical_parse(bytes, MAX_OBSERVATION_BYTES).and_then(|record: Self| {
            record.validate()?;
            Ok(record)
        })
    }

    /// Returns exact canonical record bytes for signing or comparison.
    pub fn canonical_json(&self) -> Result<Vec<u8>, QualificationError> {
        canonical_bytes(self)
    }

    fn validate(&self) -> Result<(), QualificationError> {
        if !decimal_token(&self.repository_id, 32)
            || !safe_path(&self.workflow_path)
            || !self
                .workflow_path
                .starts_with(".github/workflows/profile-qualification-")
            || !self.workflow_path.ends_with(".yml")
            || !lower_hex(&self.workflow_revision, 40)
            || !decimal_token(&self.run_id, 32)
            || self.run_attempt == 0
            || !lower_hex(&self.candidate_revision, 40)
            || !lower_token(&self.domain)
            || !digest(&self.release_build_sha256)
            || !digest(&self.attester_tools_sha256)
            || self.ledgers.is_empty()
            || self.ledgers.len() > 16
            || self.operation_ids.is_empty()
            || self.operation_ids.len() > 256
            || !sorted_unique_tokens(&self.operation_ids)
            || self.connection_generations.is_empty()
            || self.connection_generations.len() > 256
            || !sorted_unique_decimal_tokens(&self.connection_generations)
            || self.external_provider_call_counts.is_empty()
            || self.external_provider_call_counts.len() > 256
            || !digest(&self.provider_truth_sha256)
            || !digest(&self.counter_report_sha256)
            || !digest(&self.cleanup_report_sha256)
            || !digest(&self.receipt_trust_anchor_sha256)
            || QualificationTrustIdentity::parse(
                &self.recovery_key_id,
                &self.recovery_public_key_base64url,
            )
            .is_err()
            || self.observed_report_digests.is_empty()
            || self.observed_report_digests.len() > 512
            || self.started_at_unix_seconds >= self.completed_at_unix_seconds
            || self
                .completed_at_unix_seconds
                .checked_sub(self.started_at_unix_seconds)
                .is_none_or(|duration| duration > MAX_QUALIFICATION_SECONDS)
        {
            return Err(QualificationError::InvalidObservation);
        }
        validate_profiles(&self.domain, &self.profiles)?;
        validate_provider_runs(&self.provider_runs)?;
        if self.ledgers.len() != self.provider_runs.len()
            || self
                .ledgers
                .iter()
                .zip(&self.provider_runs)
                .any(|(ledger, run)| {
                    ledger.provider_run_id != run.id
                        || !digest(&ledger.ledger_sha256)
                        || !registered_token(&ledger.sealer_key_id)
                        || !digest(&ledger.source_trust_sha256)
                        || !digest(&ledger.ledger_trust_sha256)
                })
        {
            return Err(QualificationError::InvalidObservation);
        }
        validate_call_counts(&self.external_provider_call_counts, &self.operation_ids)?;
        validate_named_digests(&self.observed_report_digests)?;
        Ok(())
    }

    fn signature_preimage(&self) -> Result<Vec<u8>, QualificationError> {
        let canonical = canonical_bytes(self)?;
        let mut preimage =
            Vec::with_capacity(OBSERVATION_SIGNATURE_DOMAIN.len() + 1 + canonical.len());
        preimage.extend_from_slice(OBSERVATION_SIGNATURE_DOMAIN);
        preimage.push(0);
        preimage.extend_from_slice(&canonical);
        Ok(preimage)
    }

    /// Returns the observed provider domain.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns the observed target.
    #[must_use]
    pub const fn target(&self) -> QualificationTarget {
        self.target
    }

    /// Returns the exact candidate revision observed.
    #[must_use]
    pub fn candidate_revision(&self) -> &str {
        &self.candidate_revision
    }

    /// Returns the public receipt-anchor commitment used by the run.
    #[must_use]
    pub fn receipt_trust_anchor_sha256(&self) -> &str {
        &self.receipt_trust_anchor_sha256
    }

    /// Returns the deployment recovery-handle verification key ID.
    #[must_use]
    pub fn recovery_key_id(&self) -> &str {
        &self.recovery_key_id
    }

    /// Returns the deployment recovery-handle Ed25519 public key.
    #[must_use]
    pub fn recovery_public_key_base64url(&self) -> &str {
        &self.recovery_public_key_base64url
    }

    /// Returns the immutable GitHub repository identifier.
    #[must_use]
    pub fn repository_id(&self) -> &str {
        &self.repository_id
    }

    /// Returns the generated domain workflow path.
    #[must_use]
    pub fn workflow_path(&self) -> &str {
        &self.workflow_path
    }

    /// Returns the protected workflow revision.
    #[must_use]
    pub fn workflow_revision(&self) -> &str {
        &self.workflow_revision
    }

    /// Returns the immutable workflow run identifier.
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Returns the workflow run attempt.
    #[must_use]
    pub const fn run_attempt(&self) -> u32 {
        self.run_attempt
    }

    /// Returns the exact qualified profile family.
    #[must_use]
    pub fn profiles(&self) -> &[QualificationProfile] {
        &self.profiles
    }

    /// Returns the protected provider-version runs.
    #[must_use]
    pub fn provider_runs(&self) -> &[QualificationProviderRun] {
        &self.provider_runs
    }

    /// Returns the independently verified release-build projection digest.
    #[must_use]
    pub fn release_build_sha256(&self) -> &str {
        &self.release_build_sha256
    }

    /// Returns the digest of the exact hosted eighteen-member protected tool binding.
    #[must_use]
    pub fn attester_tools_sha256(&self) -> &str {
        &self.attester_tools_sha256
    }

    /// Returns one exact signed common-ledger commitment per provider run.
    #[must_use]
    pub fn ledgers(&self) -> &[QualificationEvidenceLedgerReference] {
        &self.ledgers
    }

    /// Returns byte-sorted operation IDs observed in the run.
    #[must_use]
    pub fn operation_ids(&self) -> &[String] {
        &self.operation_ids
    }

    /// Returns byte-sorted connection generations observed in the run.
    #[must_use]
    pub fn connection_generations(&self) -> &[String] {
        &self.connection_generations
    }

    /// Returns one exact external provider-call count per operation.
    #[must_use]
    pub fn external_provider_call_counts(&self) -> &[QualificationProviderCallCount] {
        &self.external_provider_call_counts
    }

    /// Returns the protected provider-truth report digest.
    #[must_use]
    pub fn provider_truth_sha256(&self) -> &str {
        &self.provider_truth_sha256
    }

    /// Returns the protected counter report digest.
    #[must_use]
    pub fn counter_report_sha256(&self) -> &str {
        &self.counter_report_sha256
    }

    /// Returns the protected cleanup report digest.
    #[must_use]
    pub fn cleanup_report_sha256(&self) -> &str {
        &self.cleanup_report_sha256
    }

    /// Returns byte-sorted commitments to all protected reports.
    #[must_use]
    pub fn observed_report_digests(&self) -> &[QualificationNamedDigest] {
        &self.observed_report_digests
    }

    /// Returns the protected observation start time.
    #[must_use]
    pub const fn started_at_unix_seconds(&self) -> u64 {
        self.started_at_unix_seconds
    }

    /// Returns the protected observation completion time.
    #[must_use]
    pub const fn completed_at_unix_seconds(&self) -> u64 {
        self.completed_at_unix_seconds
    }
}

impl QualificationProviderCallCount {
    /// Returns the operation whose provider calls were counted.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Returns the independently observed provider mutation count.
    #[must_use]
    pub const fn count(&self) -> u32 {
        self.count
    }
}

impl QualificationNamedDigest {
    /// Returns the stable report identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the report SHA-256 digest.
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

impl QualificationEvidenceLedgerReference {
    /// Returns the exact provider-matrix row owning this ledger.
    #[must_use]
    pub fn provider_run_id(&self) -> &str {
        &self.provider_run_id
    }

    /// Returns SHA-256 of the retained signed ledger bytes.
    #[must_use]
    pub fn ledger_sha256(&self) -> &str {
        &self.ledger_sha256
    }

    /// Returns the verified ledger-sealer key identifier.
    #[must_use]
    pub fn sealer_key_id(&self) -> &str {
        &self.sealer_key_id
    }

    /// Returns SHA-256 of the retained source-trust registry snapshot.
    #[must_use]
    pub fn source_trust_sha256(&self) -> &str {
        &self.source_trust_sha256
    }

    /// Returns SHA-256 of the retained ledger-trust registry snapshot.
    #[must_use]
    pub fn ledger_trust_sha256(&self) -> &str {
        &self.ledger_trust_sha256
    }
}

impl QualificationObservation {
    /// Signs one validated protected observation with a domain observer key.
    pub fn sign_json(
        record: QualificationObservationRecord,
        key_id: &str,
        seed_base64url: &str,
    ) -> Result<Vec<u8>, QualificationError> {
        record.validate()?;
        if !registered_token(key_id) {
            return Err(QualificationError::InvalidObservation);
        }
        let seed = decode_fixed::<32>(seed_base64url)?;
        let signature = SigningKey::from_bytes(&seed)
            .sign(&record.signature_preimage()?)
            .to_bytes();
        canonical_bytes(&Self {
            schema: "auths.profile-qualification-observation/1".into(),
            record,
            signing: QualificationSigning {
                algorithm: "Ed25519".into(),
                key_id: key_id.into(),
                signature_base64url: Base64UrlUnpadded::encode_string(&signature),
            },
        })
    }

    /// Parses exact canonical protected-observation JSON without trusting it.
    pub fn from_json(bytes: &[u8]) -> Result<Self, QualificationError> {
        canonical_parse(bytes, MAX_OBSERVATION_BYTES).and_then(|observation: Self| {
            if observation.schema != "auths.profile-qualification-observation/1"
                || observation.signing.algorithm != "Ed25519"
                || !registered_token(&observation.signing.key_id)
            {
                return Err(QualificationError::InvalidObservation);
            }
            observation.record.validate()?;
            let _ = decode_fixed::<64>(&observation.signing.signature_base64url)?;
            Ok(observation)
        })
    }

    /// Verifies a protected observation against a domain-scoped current key.
    pub fn verify_json(
        bytes: &[u8],
        registry: &QualificationObserverTrustRegistry,
        now_unix_seconds: u64,
    ) -> Result<VerifiedQualificationObservation, QualificationError> {
        let observation = Self::from_json(bytes)?;
        let key = registry.find(&observation.signing.key_id)?;
        let completed = observation.record.completed_at_unix_seconds;
        if !key.valid_at(completed) || !key.valid_at(now_unix_seconds) {
            return Err(QualificationError::ObserverTrustKeyNotCurrent);
        }
        if key
            .allowed_domains
            .binary_search_by(|domain| domain.as_str().cmp(observation.record.domain()))
            .is_err()
        {
            return Err(QualificationError::ObserverTrustKeyDomainMismatch);
        }
        let public_key = decode_fixed::<32>(&key.public_key_base64url)?;
        let signature = decode_fixed::<64>(&observation.signing.signature_base64url)?;
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| QualificationError::InvalidTrustKey)?
            .verify_strict(
                &observation.record.signature_preimage()?,
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| QualificationError::InvalidObservationSignature)?;
        Ok(VerifiedQualificationObservation {
            record: observation.record,
            key_id: key.key_id.clone(),
        })
    }
}

impl VerifiedQualificationObservation {
    /// Returns the independently verified observation record.
    #[must_use]
    pub const fn record(&self) -> &QualificationObservationRecord {
        &self.record
    }

    /// Returns the observer key that verified the record.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl QualificationTrustKey {
    fn valid_at(&self, unix_seconds: u64) -> bool {
        unix_seconds >= self.not_before_unix_seconds
            && (self.not_after_unix_seconds == 0 || unix_seconds <= self.not_after_unix_seconds)
    }
}

impl VerifiedQualification {
    /// Returns the verified qualification record.
    #[must_use]
    pub const fn record(&self) -> &QualificationRecord {
        &self.record
    }

    /// Returns the trust key that verified the record.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Consumes the wrapper and returns the trusted record.
    #[must_use]
    pub fn into_record(self) -> QualificationRecord {
        self.record
    }
}

fn canonical_parse<T>(bytes: &[u8], maximum: usize) -> Result<T, QualificationError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(QualificationError::Limit);
    }
    let parsed: T = serde_json::from_slice(bytes).map_err(|_| QualificationError::Malformed)?;
    if canonical_bytes(&parsed)?.as_slice() != bytes {
        return Err(QualificationError::NonCanonical);
    }
    Ok(parsed)
}

fn validate_profiles(
    domain: &str,
    profiles: &[QualificationProfile],
) -> Result<(), QualificationError> {
    if profiles.is_empty() || profiles.len() > 8 {
        return Err(QualificationError::InvalidProfileSet);
    }
    let prefix = format!("auths.{domain}.");
    let mut previous: Option<(&str, u16)> = None;
    for profile in profiles {
        let identity = (profile.id.as_str(), profile.version);
        if profile.version == 0
            || !profile.id.starts_with(&prefix)
            || !semantic_id(&profile.id)
            || previous.is_some_and(|value| value >= identity)
        {
            return Err(QualificationError::InvalidProfileSet);
        }
        previous = Some(identity);
    }
    Ok(())
}

fn validate_runtime_digests(
    profiles: &[QualificationProfile],
    runtime_digests: &[ProfileRuntimeDigest],
) -> Result<(), QualificationError> {
    if runtime_digests.len() != profiles.len() {
        return Err(QualificationError::InvalidRuntimeDigests);
    }
    for (profile, runtime) in profiles.iter().zip(runtime_digests) {
        if runtime.profile != profile.semantic_subject() || !digest(&runtime.sha256) {
            return Err(QualificationError::InvalidRuntimeDigests);
        }
    }
    Ok(())
}

fn validate_provider_runs(runs: &[QualificationProviderRun]) -> Result<(), QualificationError> {
    if runs.is_empty() || runs.len() > 16 {
        return Err(QualificationError::InvalidProviderRuns);
    }
    let mut previous: Option<&str> = None;
    for run in runs {
        run.validate()?;
        if previous.is_some_and(|value| value >= run.id.as_str()) {
            return Err(QualificationError::InvalidProviderRuns);
        }
        previous = Some(&run.id);
    }
    Ok(())
}

fn validate_candidate_artifacts(
    artifacts: &[QualificationCandidateArtifact],
) -> Result<(), QualificationError> {
    if artifacts.len() != RELEASE_BUILD_ARTIFACT_ROLES.len()
        || artifacts
            .iter()
            .zip(RELEASE_BUILD_ARTIFACT_ROLES)
            .any(|(artifact, expected_role)| {
                artifact.role != expected_role
                    || !digest(&artifact.member_sha256)
                    || !(1..=MAX_ARTIFACT_BYTES).contains(&artifact.bytes)
            })
    {
        return Err(QualificationError::InvalidProposal);
    }
    Ok(())
}

fn validate_scenarios(
    scenarios: &[QualificationScenario],
    provider_runs: &[QualificationProviderRun],
) -> Result<(), QualificationError> {
    if scenarios.is_empty() || scenarios.len() > 256 {
        return Err(QualificationError::InvalidScenarios);
    }
    let mut previous: Option<&str> = None;
    for scenario in scenarios {
        if !registered_token(&scenario.id)
            || scenario.status != "passed"
            || !(1..=100_000).contains(&scenario.assertions)
            || !digest(&scenario.report_sha256)
            || scenario.provider_run_ids.is_empty()
            || scenario.provider_run_ids.len() > 16
            || !sorted_unique_tokens(&scenario.provider_run_ids)
            || scenario.provider_run_ids.iter().any(|run| {
                provider_runs
                    .binary_search_by(|candidate| candidate.id.as_str().cmp(run))
                    .is_err()
            })
            || previous.is_some_and(|value| value >= scenario.id.as_str())
        {
            return Err(QualificationError::InvalidScenarios);
        }
        previous = Some(&scenario.id);
    }
    Ok(())
}

fn canonical_document_parse<T>(bytes: &[u8], maximum: usize) -> Result<T, QualificationError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let document = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if document.ends_with(b"\n") {
        return Err(QualificationError::NonCanonical);
    }
    canonical_parse(document, maximum)
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, QualificationError> {
    serde_json_canonicalizer::to_vec(value).map_err(|_| QualificationError::Malformed)
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], QualificationError> {
    let mut decoded = [0_u8; N];
    let bytes = Base64UrlUnpadded::decode(value, &mut decoded)
        .map_err(|_| QualificationError::InvalidBase64)?;
    if bytes.len() != N || Base64UrlUnpadded::encode_string(bytes) != value {
        return Err(QualificationError::InvalidBase64);
    }
    Ok(decoded)
}

fn decimal_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

fn registered_token(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn sorted_unique_tokens(values: &[String]) -> bool {
    let mut previous: Option<&str> = None;
    for value in values {
        if !registered_token(value) || previous.is_some_and(|item| item >= value.as_str()) {
            return false;
        }
        previous = Some(value);
    }
    true
}

fn sorted_unique_decimal_tokens(values: &[String]) -> bool {
    let mut previous: Option<&str> = None;
    for value in values {
        if !decimal_token(value, 32) || previous.is_some_and(|item| item >= value.as_str()) {
            return false;
        }
        previous = Some(value);
    }
    true
}

fn validate_call_counts(
    counts: &[QualificationProviderCallCount],
    operation_ids: &[String],
) -> Result<(), QualificationError> {
    if counts.len() != operation_ids.len() {
        return Err(QualificationError::InvalidObservation);
    }
    for (count, operation_id) in counts.iter().zip(operation_ids) {
        if !registered_token(&count.operation_id) || count.operation_id != *operation_id {
            return Err(QualificationError::InvalidObservation);
        }
    }
    Ok(())
}

fn validate_named_digests(values: &[QualificationNamedDigest]) -> Result<(), QualificationError> {
    let mut previous: Option<&str> = None;
    for value in values {
        if !registered_token(&value.id)
            || !digest(&value.sha256)
            || previous.is_some_and(|item| item >= value.id.as_str())
        {
            return Err(QualificationError::InvalidObservation);
        }
        previous = Some(&value.id);
    }
    Ok(())
}

fn profile_reference(value: &str) -> bool {
    let Some((profile, version)) = value.rsplit_once('/') else {
        return false;
    };
    semantic_id(profile)
        && profile.starts_with("auths.")
        && version
            .parse::<u16>()
            .is_ok_and(|parsed| parsed != 0 && parsed.to_string() == version)
}

fn qualification_id(value: &str) -> bool {
    let Some(encoded) = value.strip_prefix("qlf_") else {
        return false;
    };
    decode_fixed::<32>(encoded).is_ok()
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

fn printable(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

/// Closed qualification parsing or verification failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum QualificationError {
    /// Input is empty or exceeds its declared hard byte limit.
    #[error("qualification input exceeds its bound")]
    Limit,
    /// JSON could not be parsed into the closed schema.
    #[error("qualification JSON is malformed")]
    Malformed,
    /// JSON is valid but is not the exact canonical JCS encoding.
    #[error("qualification JSON is not canonical")]
    NonCanonical,
    /// Trust registry identity, ordering, or bounds are invalid.
    #[error("qualification trust registry is invalid")]
    InvalidTrustRegistry,
    /// Protected-observer trust registry identity or ordering is invalid.
    #[error("qualification observer trust registry is invalid")]
    InvalidObserverTrustRegistry,
    /// A trust key has invalid metadata or public-key bytes.
    #[error("qualification trust key is invalid")]
    InvalidTrustKey,
    /// The signing key is absent from the trusted registry.
    #[error("qualification trust key is unknown")]
    UnknownTrustKey,
    /// The protected-observer signing key is absent from its registry.
    #[error("qualification observer trust key is unknown")]
    UnknownObserverTrustKey,
    /// The trust key is not valid at completion or verification time.
    #[error("qualification trust key is not current")]
    TrustKeyNotCurrent,
    /// The trust key is not authorized for the attested provider domain.
    #[error("qualification trust key is not authorized for this domain")]
    TrustKeyDomainMismatch,
    /// The protected-observer key is not current at observation/verification.
    #[error("qualification observer trust key is not current")]
    ObserverTrustKeyNotCurrent,
    /// The protected-observer key is not authorized for this provider domain.
    #[error("qualification observer trust key is not authorized for this domain")]
    ObserverTrustKeyDomainMismatch,
    /// Observer and final attestation trust roots are not independent.
    #[error("qualification observer and attestation trust roots overlap")]
    TrustZonesNotDisjoint,
    /// A base64url field is malformed or non-canonical.
    #[error("qualification base64url field is invalid")]
    InvalidBase64,
    /// A qualification record violates a closed field invariant.
    #[error("qualification record is invalid")]
    InvalidRecord,
    /// The candidate proposal violates its distinct closed schema.
    #[error("qualification proposal is invalid")]
    InvalidProposal,
    /// Candidate claims differ from independently reconstructed final facts.
    #[error("qualification proposal differs from protected evidence")]
    ProposalMismatch,
    /// The atomic profile family is invalid or unsorted.
    #[error("qualification profile family is invalid")]
    InvalidProfileSet,
    /// Runtime digests do not exactly cover the profile family.
    #[error("qualification runtime digests are invalid")]
    InvalidRuntimeDigests,
    /// Workflow provenance is invalid.
    #[error("qualification workflow provenance is invalid")]
    InvalidWorkflow,
    /// Authoritative release-build identity or artifact rows are invalid.
    #[error("qualification release-build provenance is invalid")]
    InvalidReleaseBuild,
    /// The no-secret verifier handoff does not exactly bind its record.
    #[error("qualification verified-record binding is invalid")]
    InvalidVerifiedBinding,
    /// Raw artifact metadata violates the retention or byte contract.
    #[error("qualification artifact metadata is invalid")]
    InvalidArtifact,
    /// Provider-version runs are invalid, incomplete, duplicated, or failed.
    #[error("qualification provider runs are invalid")]
    InvalidProviderRuns,
    /// Protected provider observation metadata is invalid.
    #[error("qualification protected observation is invalid")]
    InvalidObservation,
    /// Protected provider observation signature verification failed.
    #[error("qualification protected observation signature is invalid")]
    InvalidObservationSignature,
    /// Scenario evidence is missing, duplicated, unsorted, or failed.
    #[error("qualification scenarios are invalid")]
    InvalidScenarios,
    /// Receipt verification did not pass in every required language.
    #[error("qualification receipt evidence is invalid")]
    InvalidReceiptEvidence,
    /// Secret scanning did not pass with a bounded report.
    #[error("qualification secret-scan evidence is invalid")]
    InvalidSecretScan,
    /// The content-derived qualification identifier does not match.
    #[error("qualification identifier does not match record content")]
    QualificationIdMismatch,
    /// Attestation metadata is invalid.
    #[error("qualification attestation is invalid")]
    InvalidAttestation,
    /// Attestation signature verification failed.
    #[error("qualification attestation signature is invalid")]
    InvalidSignature,
    /// Target is not in the closed qualification target set.
    #[error("qualification target is unsupported")]
    InvalidTarget,
    /// Qualification index ordering, identity, or evidence binding is invalid.
    #[error("qualification index is invalid")]
    InvalidIndex,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn record_value() -> Value {
        json!({
            "schema":"auths.profile-qualification/1",
            "qualificationId":"",
            "domain":"stripe",
            "profiles":[{"id":"auths.stripe.refund","version":1}],
            "target":"linux-x86_64",
            "candidateRevision":"1111111111111111111111111111111111111111",
            "semanticClosureSha256":"2222222222222222222222222222222222222222222222222222222222222222",
            "packageManifestSha256":"3333333333333333333333333333333333333333333333333333333333333333",
            "profileRuntimeDigests":[{"profile":"auths.stripe.refund/1","sha256":"4444444444444444444444444444444444444444444444444444444444444444"}],
            "errorRegistrySha256":"5555555555555555555555555555555555555555555555555555555555555555",
            "providerMatrixSha256":"5656565656565656565656565656565656565656565656565656565656565656",
            "proposalSha256":"5757575757575757575757575757575757575757575757575757575757575757",
            "toolchain":{"rust":"1.97.1","node":"22.23.1","python":"3.13.5"},
            "environmentClass":"disposable-provider-test",
            "startedAtUnixSeconds":100,
            "completedAtUnixSeconds":200,
            "workflow":{"provider":"github-actions","repositoryId":"42","workflowPath":".github/workflows/profile-qualification-stripe.yml","workflowRevision":"1212121212121212121212121212121212121212","attesterRevision":"1313131313131313131313131313131313131313","runId":"12","runAttempt":1,"protectedEnvironment":"qualification-stripe"},
            "releaseBuild":{"provider":"github-actions","repositoryId":"42","workflowPath":".github/workflows/release-builder.yml","workflowRevision":"1414141414141414141414141414141414141414","runId":"11","runAttempt":1,"runLabel":"official","qualificationSurfaceSha256":"1515151515151515151515151515151515151515151515151515151515151515","artifacts":[
                {"role":"production-agent","artifactId":"100","uploadedArchiveSha256":"1616161616161616161616161616161616161616161616161616161616161616","memberPath":"agents/auths","memberSha256":"1717171717171717171717171717171717171717171717171717171717171717","bytes":1},
                {"role":"python-native","artifactId":"101","uploadedArchiveSha256":"1818181818181818181818181818181818181818181818181818181818181818","memberPath":"python/auths_native.so","memberSha256":"1919191919191919191919191919191919191919191919191919191919191919","bytes":1},
                {"role":"python-profile-opentofu","artifactId":"102","uploadedArchiveSha256":"2020202020202020202020202020202020202020202020202020202020202020","memberPath":"python/auths-profile-opentofu.tar.zst","memberSha256":"2121212121212121212121212121212121212121212121212121212121212121","bytes":1},
                {"role":"python-profile-postgresql","artifactId":"103","uploadedArchiveSha256":"2222222222222222222222222222222222222222222222222222222222222222","memberPath":"python/auths-profile-postgresql.tar.zst","memberSha256":"2323232323232323232323232323232323232323232323232323232323232323","bytes":1},
                {"role":"python-profile-stripe","artifactId":"104","uploadedArchiveSha256":"2424242424242424242424242424242424242424242424242424242424242424","memberPath":"python/auths-profile-stripe.tar.zst","memberSha256":"2525252525252525252525252525252525252525252525252525252525252525","bytes":1},
                {"role":"python-wheel","artifactId":"105","uploadedArchiveSha256":"2626262626262626262626262626262626262626262626262626262626262626","memberPath":"python/auths.whl","memberSha256":"2727272727272727272727272727272727272727272727272727272727272727","bytes":1},
                {"role":"qualification-agent","artifactId":"106","uploadedArchiveSha256":"2828282828282828282828282828282828282828282828282828282828282828","memberPath":"agents/auths-qualification","memberSha256":"2929292929292929292929292929292929292929292929292929292929292929","bytes":1},
                {"role":"typescript-native","artifactId":"107","uploadedArchiveSha256":"3030303030303030303030303030303030303030303030303030303030303030","memberPath":"typescript/auths.node","memberSha256":"3131313131313131313131313131313131313131313131313131313131313131","bytes":1},
                {"role":"typescript-package","artifactId":"108","uploadedArchiveSha256":"3232323232323232323232323232323232323232323232323232323232323232","memberPath":"typescript/auths.tgz","memberSha256":"3333333333333333333333333333333333333333333333333333333333333333","bytes":1}
            ]},
            "artifact":{"evidenceTarSha256":"6666666666666666666666666666666666666666666666666666666666666666","evidenceTarBytes":1,"retentionDays":90,"createdAtUnixSeconds":100,"expiresAtUnixSeconds":7776100,"redactionReportSha256":"7777777777777777777777777777777777777777777777777777777777777777","storageProvider":"github-actions","artifactId":"123","uploadedArchiveSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            "providerRuns":[{"id":"stripe-test","providerVersion":"2026-08-18","providerArtifactSha256":"abababababababababababababababababababababababababababababababab","scenarioSetSha256":"acacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacac","status":"passed"}],
            "protectedObservation":{"schema":"auths.profile-qualification-observation/1","keyId":"stripe-observer","sha256":"adadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadad"},
            "scenarios":[{"id":"happy-path","status":"passed","assertions":1,"reportSha256":"8888888888888888888888888888888888888888888888888888888888888888","providerRunIds":["stripe-test"]}],
            "receiptVerification":{"rust":"passed","python":"passed","typescript":"passed","portableReceiptSchema":"auths.portable-receipt/1","receiptTrustAnchorSha256":"8989898989898989898989898989898989898989898989898989898989898989","decisionVerificationMethod":"did:key:decision","executionVerificationMethod":"did:key:execution"},
            "secretScan":{"tool":"gitleaks-8.28.0","status":"passed","reportSha256":"9999999999999999999999999999999999999999999999999999999999999999"}
        })
    }

    fn signed_fixture() -> (Vec<u8>, Vec<u8>) {
        let record = QualificationRecord::finalize_json(
            &serde_json_canonicalizer::to_vec(&record_value()).unwrap(),
        )
        .unwrap();
        let signing = SigningKey::from_bytes(&[7_u8; 32]);
        let attestation = QualificationAttestation::sign_json(
            record,
            "qualification-test",
            &Base64UrlUnpadded::encode_string(&[7_u8; 32]),
        )
        .unwrap();
        let registry = json!({
            "schema":"auths.profile-qualification-trust/1",
            "keys":[{"keyId":"qualification-test","algorithm":"Ed25519","publicKeyBase64url":Base64UrlUnpadded::encode_string(signing.verifying_key().as_bytes()),"allowedDomains":["stripe"],"notBeforeUnixSeconds":1,"notAfterUnixSeconds":1000}]
        });
        (
            attestation,
            serde_json_canonicalizer::to_vec(&registry).unwrap(),
        )
    }

    fn observation_record_value() -> Value {
        json!({
            "repositoryId":"42",
            "workflowPath":".github/workflows/profile-qualification-stripe.yml",
            "workflowRevision":"1212121212121212121212121212121212121212",
            "runId":"12",
            "runAttempt":1,
            "candidateRevision":"1111111111111111111111111111111111111111",
            "domain":"stripe",
            "target":"linux-x86_64",
            "profiles":[{"id":"auths.stripe.refund","version":1}],
            "providerRuns":[{"id":"stripe-test","providerVersion":"2026-08-18","providerArtifactSha256":"abababababababababababababababababababababababababababababababab","scenarioSetSha256":"acacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacac","status":"passed"}],
            "releaseBuildSha256":"6060606060606060606060606060606060606060606060606060606060606060",
            "attesterToolsSha256":"6666666666666666666666666666666666666666666666666666666666666666",
            "ledgers":[{"providerRunId":"stripe-test","ledgerSha256":"6767676767676767676767676767676767676767676767676767676767676767","sealerKeyId":"stripe-ledger","sourceTrustSha256":"6868686868686868686868686868686868686868686868686868686868686868","ledgerTrustSha256":"6969696969696969696969696969696969696969696969696969696969696969"}],
            "operationIds":["op-1","op-2"],
            "connectionGenerations":["1"],
            "externalProviderCallCounts":[{"operationId":"op-1","count":1},{"operationId":"op-2","count":1}],
            "providerTruthSha256":"6161616161616161616161616161616161616161616161616161616161616161",
            "counterReportSha256":"6262626262626262626262626262626262626262626262626262626262626262",
            "cleanupReportSha256":"6363636363636363636363636363636363636363636363636363636363636363",
            "receiptTrustAnchorSha256":"6464646464646464646464646464646464646464646464646464646464646464",
            "recoveryKeyId":"stripe-recovery",
            "recoveryPublicKeyBase64url":Base64UrlUnpadded::encode_string(SigningKey::from_bytes(&[13_u8; 32]).verifying_key().as_bytes()),
            "observedReportDigests":[{"id":"provider-truth","sha256":"6565656565656565656565656565656565656565656565656565656565656565"}],
            "startedAtUnixSeconds":100,
            "completedAtUnixSeconds":200
        })
    }

    #[test]
    fn verifies_canonical_signed_attestation() {
        let (attestation, registry) = signed_fixture();
        let registry = QualificationTrustRegistry::from_json(&registry).unwrap();
        let verified = QualificationAttestation::verify_json(&attestation, &registry, 300).unwrap();
        assert_eq!(verified.record().domain(), "stripe");
        assert_eq!(verified.key_id(), "qualification-test");
    }

    #[test]
    fn rejects_noncanonical_and_mutated_attestations() {
        let (attestation, registry) = signed_fixture();
        let registry = QualificationTrustRegistry::from_json(&registry).unwrap();
        let pretty: Value = serde_json::from_slice(&attestation).unwrap();
        assert_eq!(
            QualificationAttestation::verify_json(
                &serde_json::to_vec_pretty(&pretty).unwrap(),
                &registry,
                300,
            ),
            Err(QualificationError::NonCanonical)
        );
        let mut mutated: Value = serde_json::from_slice(&attestation).unwrap();
        mutated["record"]["artifact"]["evidenceTarBytes"] = json!(2);
        assert_eq!(
            QualificationAttestation::verify_json(
                &serde_json_canonicalizer::to_vec(&mutated).unwrap(),
                &registry,
                300,
            ),
            Err(QualificationError::QualificationIdMismatch)
        );
    }

    #[test]
    fn rejects_expired_key_and_unknown_target_alias() {
        let (attestation, registry) = signed_fixture();
        let registry = QualificationTrustRegistry::from_json(&registry).unwrap();
        assert_eq!(
            QualificationAttestation::verify_json(&attestation, &registry, 1001),
            Err(QualificationError::TrustKeyNotCurrent)
        );
        assert_eq!(
            QualificationTarget::parse("x86_64-unknown-linux-gnu"),
            Err(QualificationError::InvalidTarget)
        );
    }

    #[test]
    fn rejects_key_for_another_domain() {
        let (attestation, registry) = signed_fixture();
        let mut registry: Value = serde_json::from_slice(&registry).unwrap();
        registry["keys"][0]["allowedDomains"] = json!(["postgresql"]);
        let registry = QualificationTrustRegistry::from_json(
            &serde_json_canonicalizer::to_vec(&registry).unwrap(),
        )
        .unwrap();
        assert_eq!(
            QualificationAttestation::verify_json(&attestation, &registry, 300),
            Err(QualificationError::TrustKeyDomainMismatch)
        );
    }

    #[test]
    fn protected_signer_accepts_only_a_complete_final_record() {
        let record = QualificationRecord::finalize_json(
            &serde_json_canonicalizer::to_vec(&record_value()).unwrap(),
        )
        .unwrap();
        assert_eq!(record.artifact().artifact_id(), "123");

        let seed = Base64UrlUnpadded::encode_string(&[7_u8; 32]);
        let attestation =
            QualificationAttestation::sign_json(record, "qualification-test", &seed).unwrap();
        let (_, registry) = signed_fixture();
        let registry = QualificationTrustRegistry::from_json(&registry).unwrap();
        QualificationAttestation::verify_json(&attestation, &registry, 300).unwrap();

        let mut incomplete = record_value();
        incomplete["artifact"]
            .as_object_mut()
            .unwrap()
            .remove("artifactId");
        assert_eq!(
            QualificationRecord::finalize_json(
                &serde_json_canonicalizer::to_vec(&incomplete).unwrap()
            ),
            Err(QualificationError::Malformed)
        );
    }

    #[test]
    fn observation_requires_one_counter_per_operation() {
        let canonical = serde_json_canonicalizer::to_vec(&observation_record_value()).unwrap();
        QualificationObservationRecord::from_json(&canonical).unwrap();

        let mut missing = observation_record_value();
        missing["externalProviderCallCounts"] = json!([{"operationId":"op-1","count":1}]);
        assert_eq!(
            QualificationObservationRecord::from_json(
                &serde_json_canonicalizer::to_vec(&missing).unwrap()
            ),
            Err(QualificationError::InvalidObservation)
        );

        let mut missing_ledger = observation_record_value();
        missing_ledger["ledgers"] = json!([]);
        assert_eq!(
            QualificationObservationRecord::from_json(
                &serde_json_canonicalizer::to_vec(&missing_ledger).unwrap()
            ),
            Err(QualificationError::InvalidObservation)
        );
    }

    #[test]
    fn release_build_requires_the_exact_nine_role_roster() {
        let mut value = record_value();
        value["releaseBuild"]["artifacts"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        assert_eq!(
            QualificationRecord::finalize_json(&serde_json_canonicalizer::to_vec(&value).unwrap()),
            Err(QualificationError::InvalidReleaseBuild)
        );
    }

    #[test]
    fn verified_binding_exactly_commits_the_record_and_protected_context() {
        let record = QualificationRecord::finalize_json(
            &serde_json_canonicalizer::to_vec(&record_value()).unwrap(),
        )
        .unwrap();
        let binding = QualificationVerifiedRecordBinding::from_record(&record).unwrap();
        let bytes = binding.canonical_json().unwrap();
        let parsed = QualificationVerifiedRecordBinding::from_json(&bytes).unwrap();
        parsed.require_matches_record(&record).unwrap();

        let mut mutated: Value = serde_json::from_slice(&bytes).unwrap();
        mutated["artifactId"] = json!("124");
        let mutated = QualificationVerifiedRecordBinding::from_json(
            &serde_json_canonicalizer::to_vec(&mutated).unwrap(),
        )
        .unwrap();
        assert_eq!(
            mutated.require_matches_record(&record),
            Err(QualificationError::InvalidVerifiedBinding)
        );
    }

    #[test]
    fn observer_and_attester_trust_roots_must_be_disjoint() {
        let signing = SigningKey::from_bytes(&[7_u8; 32]);
        let public = Base64UrlUnpadded::encode_string(signing.verifying_key().as_bytes());
        let attestation = json!({
            "schema":"auths.profile-qualification-trust/1",
            "keys":[{"keyId":"attester","algorithm":"Ed25519","publicKeyBase64url":public,"allowedDomains":["stripe"],"notBeforeUnixSeconds":1,"notAfterUnixSeconds":1000}]
        });
        let observer = json!({
            "schema":"auths.profile-qualification-observer-trust/1",
            "keys":[{"keyId":"observer","algorithm":"Ed25519","publicKeyBase64url":Base64UrlUnpadded::encode_string(signing.verifying_key().as_bytes()),"allowedDomains":["stripe"],"notBeforeUnixSeconds":1,"notAfterUnixSeconds":1000}]
        });
        let attestation = QualificationTrustRegistry::from_json(
            &serde_json_canonicalizer::to_vec(&attestation).unwrap(),
        )
        .unwrap();
        let observer = QualificationObserverTrustRegistry::from_json(
            &serde_json_canonicalizer::to_vec(&observer).unwrap(),
        )
        .unwrap();
        assert_eq!(
            validate_qualification_trust_separation(&attestation, &observer),
            Err(QualificationError::TrustZonesNotDisjoint)
        );
    }

    #[test]
    fn every_qualification_role_requires_distinct_ids_and_public_keys() {
        let first = Base64UrlUnpadded::encode_string(
            SigningKey::from_bytes(&[11_u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        let second = Base64UrlUnpadded::encode_string(
            SigningKey::from_bytes(&[12_u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        assert_eq!(
            validate_qualification_key_separation([
                QualificationTrustIdentity::new("source", &first),
                QualificationTrustIdentity::new("ledger", &second),
            ]),
            Ok(())
        );
        assert_eq!(
            validate_qualification_key_separation([
                QualificationTrustIdentity::new("shared", &first),
                QualificationTrustIdentity::new("shared", &second),
            ]),
            Err(QualificationError::TrustZonesNotDisjoint)
        );
        assert_eq!(
            validate_qualification_key_separation([
                QualificationTrustIdentity::new("source", &first),
                QualificationTrustIdentity::new("recovery", &first),
            ]),
            Err(QualificationError::TrustZonesNotDisjoint)
        );
    }
}
