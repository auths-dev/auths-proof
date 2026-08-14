use auths_model::Digest;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeSet, fmt};

const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 256;
const MAX_CUSTODY_ADAPTERS: usize = 8;
const MAX_PRODUCTION_PROFILES: usize = 16;
const MAX_EVIDENCE_REQUIREMENTS: usize = 16;
const MAX_EXCLUSIONS: usize = 16;
const COMMITMENT_DOMAIN: &[u8] = b"AUTHS-OPEN-PRODUCTION-CANDIDATE\0\x01";

/// Strict, non-secret input for one open production candidate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProductionCandidateInput {
    release: ReleaseCandidateInput,
    topology: ProductionTopologyInput,
    lifecycle_store: LifecycleStoreInput,
    custody: Vec<CustodyAdapterInput>,
    profiles: Vec<ProductionProfileInput>,
    sdks: SdkMatrixInput,
    operations: OperationsObjectivesInput,
    evidence: Vec<EvidenceRequirement>,
    exclusions: Vec<ProductionExclusion>,
}

/// Open production topology supported by the first candidate.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum ProductionTopologyClass {
    CustomerOperated,
}

/// Qualified custody adapters supported by the first candidate.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum CustodyAdapterFamily {
    AwsKmsP256V1,
    Pkcs11P256V1,
}

impl CustodyAdapterFamily {
    fn expected(self) -> CustodyContract {
        match self {
            Self::AwsKmsP256V1 => CustodyContract {
                suite: "p256-sha256-v1",
                key_policy: "aws-kms-account-region-version-v1",
            },
            Self::Pkcs11P256V1 => CustodyContract {
                suite: "p256-sha256-v1",
                key_policy: "pkcs11-module-token-object-v1",
            },
        }
    }
}

/// Exact product profiles qualified by the first candidate.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum ProductionProfileId {
    OpentofuSavedPlanApplyV1,
    PostgresqlBoundedUpdateV1,
    GithubIssueAddressV1,
}

impl ProductionProfileId {
    fn expected(self) -> ProfileContract {
        match self {
            Self::OpentofuSavedPlanApplyV1 => ProfileContract {
                package: "product/integrations/auths-opentofu",
                provider_contracts: &["auths.opentofu.fixed-argv-saved-plan-apply/1"],
                receipt_schema: "auths.opentofu.decision-receipt/1",
                fixture_suite: "product/fixtures/v1/opentofu",
            },
            Self::PostgresqlBoundedUpdateV1 => ProfileContract {
                package: "product/integrations/auths-postgresql",
                provider_contracts: &["auths.postgresql.serializable-ledger-update/1"],
                receipt_schema: "auths.postgresql.decision-receipt/1",
                fixture_suite: "product/fixtures/v1/postgresql",
            },
            Self::GithubIssueAddressV1 => ProfileContract {
                package: "product/integrations/auths-github",
                provider_contracts: &[
                    "auths.github.fixed-refspec-branch-publish/1",
                    "auths.github.rest-draft-pull-request-create/1",
                ],
                receipt_schema: "auths.github.decision-receipt/1",
                fixture_suite: "product/fixtures/v1/github",
            },
        }
    }
}

/// Supported SDK language artifacts.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum SdkLanguage {
    Rust,
    Typescript,
    Python,
}

/// Required evidence classes for the bounded production claim.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceRequirement {
    MultiHostStore,
    RuntimeRecovery,
    CustodyConformance,
    OperationsPrivacy,
    ExactEffectProfiles,
    SdkDifferential,
    ReferenceDeployment,
    SustainedQualification,
    IndependentReview,
}

/// Explicit exclusions from the bounded production claim.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum ProductionExclusion {
    HostedControlPlane,
    GenericExecutor,
    ArbitraryProviderRequest,
    RegulatoryCompliance,
    UniversalExactlyOnce,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ReleaseCandidateInput {
    candidate: String,
    version: String,
    source_commit_slot: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ProductionTopologyInput {
    class: ProductionTopologyClass,
    runtime_instances: u8,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum LifecycleStoreFamily {
    PostgresqlV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum TlsRequirement {
    Required,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct LifecycleStoreInput {
    family: LifecycleStoreFamily,
    tls: TlsRequirement,
    schema: String,
    secret_slot: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CustodyAdapterInput {
    family: CustodyAdapterFamily,
    suite: String,
    key_policy: String,
    fixture_suite: String,
    secret_slot: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ProductionProfileInput {
    id: ProductionProfileId,
    package: String,
    provider_contracts: Vec<String>,
    receipt_schema: String,
    fixture_suite: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct SdkMatrixInput {
    artifacts: Vec<SdkArtifactInput>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct SdkArtifactInput {
    language: SdkLanguage,
    package: String,
    version: String,
    abi: String,
    public_api_snapshot: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct OperationsObjectivesInput {
    availability_basis_points: u16,
    decision_p95_milliseconds: u32,
    decision_p99_milliseconds: u32,
    recovery_p95_seconds: u32,
    maximum_possible_effect_age_seconds: u32,
    maximum_reconciliation_backlog: u32,
    reconciliation_drain_p95_seconds: u32,
    receipt_availability_basis_points: u16,
    store_rpo_seconds: u32,
    store_rto_seconds: u32,
    custody_availability_basis_points: u16,
    maximum_concurrent_workflows: u32,
}

#[derive(Clone, Copy)]
struct ProfileContract {
    package: &'static str,
    provider_contracts: &'static [&'static str],
    receipt_schema: &'static str,
    fixture_suite: &'static str,
}

#[derive(Clone, Copy)]
struct CustodyContract {
    suite: &'static str,
    key_policy: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalManifest {
    schema: &'static str,
    release: CanonicalRelease,
    topology: CanonicalTopology,
    lifecycle_store: CanonicalLifecycleStore,
    custody: Vec<CanonicalCustody>,
    profiles: Vec<CanonicalProfile>,
    sdks: Vec<CanonicalSdk>,
    operations: CanonicalOperations,
    evidence: Vec<EvidenceRequirement>,
    exclusions: Vec<ProductionExclusion>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalRelease {
    candidate: String,
    version: String,
    source_commit_slot: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalTopology {
    class: ProductionTopologyClass,
    runtime_instances: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalLifecycleStore {
    family: LifecycleStoreFamily,
    tls: TlsRequirement,
    schema: String,
    secret_slot: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalCustody {
    family: CustodyAdapterFamily,
    suite: String,
    key_policy: String,
    fixture_suite: String,
    secret_slot: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalProfile {
    id: ProductionProfileId,
    package: String,
    provider_contracts: Vec<String>,
    receipt_schema: String,
    fixture_suite: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalSdk {
    language: SdkLanguage,
    package: String,
    version: String,
    abi: String,
    public_api_snapshot: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalOperations {
    availability_basis_points: u16,
    decision_p95_milliseconds: u32,
    decision_p99_milliseconds: u32,
    recovery_p95_seconds: u32,
    maximum_possible_effect_age_seconds: u32,
    maximum_reconciliation_backlog: u32,
    reconciliation_drain_p95_seconds: u32,
    receipt_availability_basis_points: u16,
    store_rpo_seconds: u32,
    store_rto_seconds: u32,
    custody_availability_basis_points: u16,
    maximum_concurrent_workflows: u32,
}

/// Validated immutable production candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionCandidate {
    manifest: CanonicalManifest,
    commitment: Digest,
}

/// Bounded safe diagnostic projection for operators.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionCandidateSummary {
    candidate: String,
    version: String,
    runtime_instances: u8,
    custody: Vec<CustodyAdapterFamily>,
    profiles: Vec<ProductionProfileId>,
    evidence_required: usize,
    exclusions: Vec<ProductionExclusion>,
}

impl ProductionCandidateInput {
    /// Parses a strict production-candidate TOML document.
    ///
    /// # Errors
    ///
    /// Returns a bounded error when the document is malformed or contains an
    /// unknown field.
    pub fn parse_toml(input: &str) -> Result<Self, ProductionConfigError> {
        if input.len() > 64 * 1024 {
            return Err(ProductionConfigError::invalid(
                "document",
                "keep the production candidate below 64 KiB",
            ));
        }
        toml::from_str(input).map_err(|_| {
            ProductionConfigError::new(
                ProductionConfigErrorCode::Malformed,
                "document",
                "use only the documented production-candidate fields",
            )
        })
    }

    /// Compiles input into one immutable, canonical, non-secret candidate.
    ///
    /// # Errors
    ///
    /// Returns the first closed validation failure.
    pub fn compile(self) -> Result<ProductionCandidate, ProductionConfigError> {
        validate_identifier("release.candidate", &self.release.candidate)?;
        validate_version("release.version", &self.release.version)?;
        validate_identifier(
            "release.source_commit_slot",
            &self.release.source_commit_slot,
        )?;
        if self.topology.runtime_instances < 3 || self.topology.runtime_instances > 32 {
            return Err(ProductionConfigError::invalid(
                "topology.runtime_instances",
                "choose between 3 and 32 runtime instances",
            ));
        }
        validate_identifier("lifecycle_store.schema", &self.lifecycle_store.schema)?;
        validate_secret_slot(
            "lifecycle_store.secret_slot",
            &self.lifecycle_store.secret_slot,
        )?;
        let custody = compile_custody(self.custody)?;
        let profiles = compile_profiles(self.profiles)?;
        let sdks = compile_sdks(self.sdks.artifacts)?;

        validate_objectives(&self.operations)?;
        let evidence = unique_complete(
            "evidence",
            &self.evidence,
            MAX_EVIDENCE_REQUIREMENTS,
            &BTreeSet::from([
                EvidenceRequirement::MultiHostStore,
                EvidenceRequirement::RuntimeRecovery,
                EvidenceRequirement::CustodyConformance,
                EvidenceRequirement::OperationsPrivacy,
                EvidenceRequirement::ExactEffectProfiles,
                EvidenceRequirement::SdkDifferential,
                EvidenceRequirement::ReferenceDeployment,
                EvidenceRequirement::SustainedQualification,
                EvidenceRequirement::IndependentReview,
            ]),
        )?;
        let exclusions = unique_complete(
            "exclusions",
            &self.exclusions,
            MAX_EXCLUSIONS,
            &BTreeSet::from([
                ProductionExclusion::HostedControlPlane,
                ProductionExclusion::GenericExecutor,
                ProductionExclusion::ArbitraryProviderRequest,
                ProductionExclusion::RegulatoryCompliance,
                ProductionExclusion::UniversalExactlyOnce,
            ]),
        )?;

        let manifest = CanonicalManifest {
            schema: "auths.open-production-candidate/1",
            release: CanonicalRelease {
                candidate: self.release.candidate,
                version: self.release.version,
                source_commit_slot: self.release.source_commit_slot,
            },
            topology: CanonicalTopology {
                class: self.topology.class,
                runtime_instances: self.topology.runtime_instances,
            },
            lifecycle_store: CanonicalLifecycleStore {
                family: self.lifecycle_store.family,
                tls: self.lifecycle_store.tls,
                schema: self.lifecycle_store.schema,
                secret_slot: self.lifecycle_store.secret_slot,
            },
            custody,
            profiles,
            sdks,
            operations: CanonicalOperations {
                availability_basis_points: self.operations.availability_basis_points,
                decision_p95_milliseconds: self.operations.decision_p95_milliseconds,
                decision_p99_milliseconds: self.operations.decision_p99_milliseconds,
                recovery_p95_seconds: self.operations.recovery_p95_seconds,
                maximum_possible_effect_age_seconds: self
                    .operations
                    .maximum_possible_effect_age_seconds,
                maximum_reconciliation_backlog: self.operations.maximum_reconciliation_backlog,
                reconciliation_drain_p95_seconds: self.operations.reconciliation_drain_p95_seconds,
                receipt_availability_basis_points: self
                    .operations
                    .receipt_availability_basis_points,
                store_rpo_seconds: self.operations.store_rpo_seconds,
                store_rto_seconds: self.operations.store_rto_seconds,
                custody_availability_basis_points: self
                    .operations
                    .custody_availability_basis_points,
                maximum_concurrent_workflows: self.operations.maximum_concurrent_workflows,
            },
            evidence,
            exclusions,
        };
        let bytes = canonical_bytes(&manifest)?;
        let mut digest = Sha256::new();
        digest.update(COMMITMENT_DOMAIN);
        digest.update(&bytes);
        Ok(ProductionCandidate {
            manifest,
            commitment: Digest::new(digest.finalize().into()),
        })
    }
}

impl ProductionCandidate {
    /// Returns the domain-separated commitment to the canonical manifest.
    #[must_use]
    pub const fn commitment(&self) -> Digest {
        self.commitment
    }

    /// Returns canonical JSON bytes with one terminating newline.
    ///
    /// # Errors
    ///
    /// Returns a bounded serialization error if the internal manifest cannot
    /// be encoded.
    pub fn canonical_manifest(&self) -> Result<Vec<u8>, ProductionConfigError> {
        canonical_bytes(&self.manifest)
    }

    /// Returns the safe operator-facing summary.
    #[must_use]
    pub fn summary(&self) -> ProductionCandidateSummary {
        ProductionCandidateSummary {
            candidate: self.manifest.release.candidate.clone(),
            version: self.manifest.release.version.clone(),
            runtime_instances: self.manifest.topology.runtime_instances,
            custody: self
                .manifest
                .custody
                .iter()
                .map(|item| item.family)
                .collect(),
            profiles: self.manifest.profiles.iter().map(|item| item.id).collect(),
            evidence_required: self.manifest.evidence.len(),
            exclusions: self.manifest.exclusions.clone(),
        }
    }

    /// Returns the generated schema for the canonical manifest.
    #[must_use]
    pub fn canonical_schema() -> Value {
        generated_schema()
    }
}

impl ProductionCandidateSummary {
    #[must_use]
    pub fn candidate(&self) -> &str {
        &self.candidate
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub const fn runtime_instances(&self) -> u8 {
        self.runtime_instances
    }

    #[must_use]
    pub fn custody(&self) -> &[CustodyAdapterFamily] {
        &self.custody
    }

    #[must_use]
    pub fn profiles(&self) -> &[ProductionProfileId] {
        &self.profiles
    }

    #[must_use]
    pub const fn evidence_required(&self) -> usize {
        self.evidence_required
    }

    #[must_use]
    pub fn exclusions(&self) -> &[ProductionExclusion] {
        &self.exclusions
    }
}

impl fmt::Display for ProductionCandidateSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "Auths production candidate")?;
        writeln!(
            formatter,
            "  release:          {} / {}",
            self.version, self.candidate
        )?;
        writeln!(
            formatter,
            "  topology:         customer-operated / {} runtime instances",
            self.runtime_instances
        )?;
        writeln!(
            formatter,
            "  lifecycle store:  PostgreSQL / TLS required / schema v1"
        )?;
        writeln!(
            formatter,
            "  custody:          {} qualified adapters",
            self.custody.len()
        )?;
        writeln!(
            formatter,
            "  profiles:         {} qualified profiles",
            self.profiles.len()
        )?;
        writeln!(formatter, "  SDKs:             Rust, TypeScript, Python")?;
        writeln!(
            formatter,
            "  evidence:         {} required bundles",
            self.evidence_required
        )?;
        write!(
            formatter,
            "  exclusions:       {} explicit exclusions",
            self.exclusions.len()
        )
    }
}

/// Stable production-candidate configuration failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionConfigErrorCode {
    Malformed,
    InvalidValue,
    Duplicate,
    MissingParity,
    SecretMaterial,
    Serialization,
}

/// Bounded production-candidate configuration failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionConfigError {
    code: ProductionConfigErrorCode,
    field: &'static str,
    fix: &'static str,
}

impl ProductionConfigError {
    const fn new(code: ProductionConfigErrorCode, field: &'static str, fix: &'static str) -> Self {
        Self { code, field, fix }
    }

    const fn invalid(field: &'static str, fix: &'static str) -> Self {
        Self::new(ProductionConfigErrorCode::InvalidValue, field, fix)
    }

    const fn duplicate(field: &'static str) -> Self {
        Self::new(
            ProductionConfigErrorCode::Duplicate,
            field,
            "remove the duplicate entry",
        )
    }

    #[must_use]
    pub const fn code(&self) -> ProductionConfigErrorCode {
        self.code
    }

    #[must_use]
    pub const fn field(&self) -> &'static str {
        self.field
    }

    #[must_use]
    pub const fn fix(&self) -> &'static str {
        self.fix
    }
}

impl fmt::Display for ProductionConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid {}: {}", self.field, self.fix)
    }
}

impl std::error::Error for ProductionConfigError {}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), ProductionConfigError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@' | b'/' | b':')
        })
    {
        return Err(ProductionConfigError::invalid(
            field,
            "use a non-empty bounded identifier",
        ));
    }
    reject_secret_material(field, value)
}

fn validate_version(field: &'static str, value: &str) -> Result<(), ProductionConfigError> {
    validate_identifier(field, value)?;
    if !value.bytes().any(|byte| byte == b'.') {
        return Err(ProductionConfigError::invalid(
            field,
            "use an explicit dotted release version",
        ));
    }
    Ok(())
}

fn validate_path(field: &'static str, value: &str) -> Result<(), ProductionConfigError> {
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || value.starts_with('/')
        || value.contains("..")
        || value.contains('\\')
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ProductionConfigError::invalid(
            field,
            "use a bounded repository-relative path",
        ));
    }
    reject_secret_material(field, value)
}

fn validate_secret_slot(field: &'static str, value: &str) -> Result<(), ProductionConfigError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(ProductionConfigError::invalid(
            field,
            "use an uppercase environment or secret-store slot name",
        ));
    }
    Ok(())
}

fn validate_exact(
    field: &'static str,
    actual: &str,
    expected: &'static str,
) -> Result<(), ProductionConfigError> {
    if actual != expected {
        return Err(ProductionConfigError::invalid(
            field,
            "use the registered contract value for this profile",
        ));
    }
    validate_path_or_identifier(field, actual)
}

fn validate_path_or_identifier(
    field: &'static str,
    value: &str,
) -> Result<(), ProductionConfigError> {
    if value.contains('/') && !value.contains("/1") {
        validate_path(field, value)
    } else {
        validate_identifier(field, value)
    }
}

fn validate_count(
    field: &'static str,
    count: usize,
    minimum: usize,
    maximum: usize,
) -> Result<(), ProductionConfigError> {
    if count < minimum || count > maximum {
        return Err(ProductionConfigError::invalid(
            field,
            "use the bounded number of required entries",
        ));
    }
    Ok(())
}

fn validate_objectives(
    objectives: &OperationsObjectivesInput,
) -> Result<(), ProductionConfigError> {
    if !(9_000..=10_000).contains(&objectives.availability_basis_points) {
        return Err(ProductionConfigError::invalid(
            "operations.availability_basis_points",
            "choose a qualification objective between 9000 and 10000 basis points",
        ));
    }
    if objectives.decision_p95_milliseconds == 0
        || objectives.decision_p95_milliseconds > 60_000
        || objectives.decision_p99_milliseconds < objectives.decision_p95_milliseconds
        || objectives.decision_p99_milliseconds > 60_000
        || objectives.recovery_p95_seconds == 0
        || objectives.recovery_p95_seconds > 86_400
        || objectives.maximum_possible_effect_age_seconds == 0
        || objectives.maximum_possible_effect_age_seconds > 604_800
        || objectives.maximum_reconciliation_backlog == 0
        || objectives.maximum_reconciliation_backlog > 1_000_000
        || objectives.reconciliation_drain_p95_seconds == 0
        || objectives.reconciliation_drain_p95_seconds > 86_400
        || !(9_000..=10_000).contains(&objectives.receipt_availability_basis_points)
        || objectives.store_rpo_seconds > 86_400
        || objectives.store_rto_seconds == 0
        || objectives.store_rto_seconds > 86_400
        || !(9_000..=10_000).contains(&objectives.custody_availability_basis_points)
        || objectives.maximum_concurrent_workflows == 0
        || objectives.maximum_concurrent_workflows > 1_000_000
    {
        return Err(ProductionConfigError::invalid(
            "operations",
            "use positive bounded qualification objectives",
        ));
    }
    Ok(())
}

fn compile_custody(
    adapters: Vec<CustodyAdapterInput>,
) -> Result<Vec<CanonicalCustody>, ProductionConfigError> {
    validate_count("custody", adapters.len(), 1, MAX_CUSTODY_ADAPTERS)?;
    let mut families = BTreeSet::new();
    let mut custody = adapters
        .into_iter()
        .map(|adapter| {
            if !families.insert(adapter.family) {
                return Err(ProductionConfigError::duplicate("custody.family"));
            }
            let expected = adapter.family.expected();
            validate_exact("custody.suite", &adapter.suite, expected.suite)?;
            validate_exact(
                "custody.key_policy",
                &adapter.key_policy,
                expected.key_policy,
            )?;
            validate_exact(
                "custody.fixture_suite",
                &adapter.fixture_suite,
                "product/fixtures/v1/custody",
            )?;
            validate_secret_slot("custody.secret_slot", &adapter.secret_slot)?;
            Ok(CanonicalCustody {
                family: adapter.family,
                suite: adapter.suite,
                key_policy: adapter.key_policy,
                fixture_suite: adapter.fixture_suite,
                secret_slot: adapter.secret_slot,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    custody.sort_by_key(|adapter| adapter.family);
    Ok(custody)
}

fn compile_profiles(
    values: Vec<ProductionProfileInput>,
) -> Result<Vec<CanonicalProfile>, ProductionConfigError> {
    validate_count("profiles", values.len(), 3, MAX_PRODUCTION_PROFILES)?;
    let mut ids = BTreeSet::new();
    let mut profiles = values
        .into_iter()
        .map(|profile| {
            if !ids.insert(profile.id) {
                return Err(ProductionConfigError::duplicate("profiles.id"));
            }
            let expected = profile.id.expected();
            validate_exact("profiles.package", &profile.package, expected.package)?;
            validate_count(
                "profiles.provider_contracts",
                profile.provider_contracts.len(),
                expected.provider_contracts.len(),
                expected.provider_contracts.len(),
            )?;
            for (actual, expected) in profile
                .provider_contracts
                .iter()
                .zip(expected.provider_contracts)
            {
                validate_exact("profiles.provider_contracts", actual, expected)?;
            }
            validate_exact(
                "profiles.receipt_schema",
                &profile.receipt_schema,
                expected.receipt_schema,
            )?;
            validate_exact(
                "profiles.fixture_suite",
                &profile.fixture_suite,
                expected.fixture_suite,
            )?;
            Ok(CanonicalProfile {
                id: profile.id,
                package: profile.package,
                provider_contracts: profile.provider_contracts,
                receipt_schema: profile.receipt_schema,
                fixture_suite: profile.fixture_suite,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if ids
        != BTreeSet::from([
            ProductionProfileId::OpentofuSavedPlanApplyV1,
            ProductionProfileId::PostgresqlBoundedUpdateV1,
            ProductionProfileId::GithubIssueAddressV1,
        ])
    {
        return Err(ProductionConfigError::invalid(
            "profiles",
            "configure exactly the three qualified open production profiles",
        ));
    }
    profiles.sort_by_key(|profile| profile.id);
    Ok(profiles)
}

fn compile_sdks(values: Vec<SdkArtifactInput>) -> Result<Vec<CanonicalSdk>, ProductionConfigError> {
    validate_count("sdks.artifacts", values.len(), 3, 3)?;
    let mut languages = BTreeSet::new();
    let mut sdks = values
        .into_iter()
        .map(|sdk| {
            if !languages.insert(sdk.language) {
                return Err(ProductionConfigError::duplicate("sdks.language"));
            }
            validate_identifier("sdks.package", &sdk.package)?;
            validate_version("sdks.version", &sdk.version)?;
            validate_path("sdks.abi", &sdk.abi)?;
            validate_path("sdks.public_api_snapshot", &sdk.public_api_snapshot)?;
            Ok(CanonicalSdk {
                language: sdk.language,
                package: sdk.package,
                version: sdk.version,
                abi: sdk.abi,
                public_api_snapshot: sdk.public_api_snapshot,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if languages
        != BTreeSet::from([
            SdkLanguage::Rust,
            SdkLanguage::Typescript,
            SdkLanguage::Python,
        ])
    {
        return Err(ProductionConfigError::new(
            ProductionConfigErrorCode::MissingParity,
            "sdks.artifacts",
            "include Rust, TypeScript, and Python artifacts",
        ));
    }
    sdks.sort_by_key(|sdk| sdk.language);
    Ok(sdks)
}

fn unique_complete<T: Copy + Ord>(
    field: &'static str,
    values: &[T],
    maximum: usize,
    required: &BTreeSet<T>,
) -> Result<Vec<T>, ProductionConfigError> {
    validate_count(field, values.len(), required.len(), maximum)?;
    let actual = values.iter().copied().collect::<BTreeSet<_>>();
    if actual.len() != values.len() {
        return Err(ProductionConfigError::duplicate(field));
    }
    if &actual != required {
        return Err(ProductionConfigError::invalid(
            field,
            "include exactly the required closed values",
        ));
    }
    Ok(actual.into_iter().collect())
}

fn reject_secret_material(field: &'static str, value: &str) -> Result<(), ProductionConfigError> {
    let uppercase = value.to_ascii_uppercase();
    if value.contains("://")
        || value.contains("-----BEGIN")
        || uppercase.starts_with("AKIA")
        || value.contains('\n')
        || value.contains('\r')
    {
        return Err(ProductionConfigError::new(
            ProductionConfigErrorCode::SecretMaterial,
            field,
            "reference a stable non-secret identity or secret slot instead of secret material",
        ));
    }
    Ok(())
}

fn canonical_bytes(manifest: &CanonicalManifest) -> Result<Vec<u8>, ProductionConfigError> {
    let mut bytes = serde_json::to_vec(manifest).map_err(|_| {
        ProductionConfigError::new(
            ProductionConfigErrorCode::Serialization,
            "manifest",
            "report the internal canonical serialization failure",
        )
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn generated_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://auths.dev/spec/open-production-candidate-v1.schema.json",
        "title": "Auths open production candidate V1",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema", "release", "topology", "lifecycleStore", "custody", "profiles", "sdks", "operations", "evidence", "exclusions"],
        "properties": {
            "schema": { "const": "auths.open-production-candidate/1" },
            "release": closed_object(["candidate", "version", "sourceCommitSlot"]),
            "topology": closed_object(["class", "runtimeInstances"]),
            "lifecycleStore": closed_object(["family", "tls", "schema", "secretSlot"]),
            "custody": { "type": "array", "minItems": 1, "maxItems": MAX_CUSTODY_ADAPTERS, "items": closed_object(["family", "suite", "keyPolicy", "fixtureSuite", "secretSlot"]) },
            "profiles": { "type": "array", "minItems": 3, "maxItems": MAX_PRODUCTION_PROFILES, "items": closed_object(["id", "package", "providerContract", "receiptSchema", "fixtureSuite"]) },
            "sdks": { "type": "array", "minItems": 3, "maxItems": 3, "items": closed_object(["language", "package", "version", "abi", "publicApiSnapshot"]) },
            "operations": closed_object(["availabilityBasisPoints", "decisionP95Milliseconds", "decisionP99Milliseconds", "recoveryP95Seconds", "maximumPossibleEffectAgeSeconds", "maximumReconciliationBacklog", "reconciliationDrainP95Seconds", "receiptAvailabilityBasisPoints", "storeRpoSeconds", "storeRtoSeconds", "custodyAvailabilityBasisPoints", "maximumConcurrentWorkflows"]),
            "evidence": { "type": "array", "minItems": 9, "maxItems": MAX_EVIDENCE_REQUIREMENTS, "uniqueItems": true },
            "exclusions": { "type": "array", "minItems": 5, "maxItems": MAX_EXCLUSIONS, "uniqueItems": true }
        }
    })
}

fn closed_object<const N: usize>(required: [&str; N]) -> Value {
    let required = required.map(str::to_owned).to_vec();
    let properties = required
        .iter()
        .map(|field| (field.clone(), json!({})))
        .collect::<serde_json::Map<_, _>>();
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANDIDATE: &str = include_str!("../../../../release/open-production-candidate.toml");

    #[test]
    fn candidate_is_strict_deterministic_and_safe_to_summarize() {
        let first = ProductionCandidateInput::parse_toml(CANDIDATE)
            .unwrap()
            .compile()
            .unwrap();
        let second = ProductionCandidateInput::parse_toml(CANDIDATE)
            .unwrap()
            .compile()
            .unwrap();
        assert_eq!(first.commitment(), second.commitment());
        assert_eq!(
            first.canonical_manifest().unwrap(),
            second.canonical_manifest().unwrap()
        );
        let summary = first.summary().to_string();
        assert!(summary.contains("3 runtime instances"));
        for forbidden in ["AUTHS_POSTGRES_URL", "AUTHS_KMS_KEY", "://", "-----BEGIN"] {
            assert!(!summary.contains(forbidden));
        }
    }

    #[test]
    fn unknown_fields_and_invalid_topology_fail_closed() {
        let unknown = CANDIDATE.replace(
            "candidate = \"open-production-candidate-1\"",
            "candidate = \"open-production-candidate-1\"\nunknown = true",
        );
        assert_eq!(
            ProductionCandidateInput::parse_toml(&unknown)
                .unwrap_err()
                .code(),
            ProductionConfigErrorCode::Malformed
        );
        let too_small = CANDIDATE.replace("runtime_instances = 3", "runtime_instances = 2");
        let error = ProductionCandidateInput::parse_toml(&too_small)
            .unwrap()
            .compile()
            .unwrap_err();
        assert_eq!(error.field(), "topology.runtime_instances");
    }

    #[test]
    fn duplicate_profile_and_missing_sdk_parity_fail_closed() {
        let duplicate = CANDIDATE.replace(
            "id = \"github-issue-address-v1\"",
            "id = \"opentofu-saved-plan-apply-v1\"",
        );
        assert_eq!(
            ProductionCandidateInput::parse_toml(&duplicate)
                .unwrap()
                .compile()
                .unwrap_err()
                .code(),
            ProductionConfigErrorCode::Duplicate
        );
        let missing = CANDIDATE.replace("language = \"python\"", "language = \"typescript\"");
        assert_eq!(
            ProductionCandidateInput::parse_toml(&missing)
                .unwrap()
                .compile()
                .unwrap_err()
                .code(),
            ProductionConfigErrorCode::Duplicate
        );
    }

    #[test]
    fn different_candidates_have_different_bytes() {
        let first = ProductionCandidateInput::parse_toml(CANDIDATE)
            .unwrap()
            .compile()
            .unwrap();
        let changed = CANDIDATE.replace(
            "decision_p95_milliseconds = 250",
            "decision_p95_milliseconds = 251",
        );
        let second = ProductionCandidateInput::parse_toml(&changed)
            .unwrap()
            .compile()
            .unwrap();
        assert_ne!(
            first.canonical_manifest().unwrap(),
            second.canonical_manifest().unwrap()
        );
        assert_ne!(first.commitment(), second.commitment());
    }

    #[test]
    fn raw_secret_material_is_rejected() {
        let leaked = CANDIDATE.replace(
            "source_commit_slot = \"AUTHS_CANDIDATE_COMMIT\"",
            "source_commit_slot = \"https://user:password@example.com\"",
        );
        let error = ProductionCandidateInput::parse_toml(&leaked)
            .unwrap()
            .compile()
            .unwrap_err();
        assert_eq!(error.code(), ProductionConfigErrorCode::SecretMaterial);
    }
}
