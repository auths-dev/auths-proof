use crate::*;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserializer, Serializer, de::Error as _};
use std::collections::BTreeSet;

const MANIFEST_SCHEMA: &str = "auths.assurance-manifest/1";
const CANDIDATE_INPUT_SCHEMA: &str = "auths.assurance-candidate-input/1";
const EVIDENCE_SCHEMA: &str = "auths.assurance-evidence/1";
const QUALIFICATION_RECORD_SCHEMA: &str = "auths.assurance-qualification/1";
const REVIEW_RECORD_SCHEMA: &str = "auths.assurance-review/1";
const TRUSTED_SIGNERS_SCHEMA: &str = "auths.assurance-signers/1";
const DEFAULT_MANIFEST: &str = "release/assurance/open-production-candidate-1/manifest.json";
const TRUSTED_SIGNERS: &str = "release/assurance/trusted-signers.json";
const MINIMUM_QUALIFICATION_SECONDS: u64 = 30 * 24 * 60 * 60;
const REQUIRED_PROFILES: [&str; 3] = [
    "auths.github.issue-address/1",
    "auths.opentofu.saved-plan-apply/1",
    "auths.postgresql.bounded-update/1",
];
const REQUIRED_EVIDENCE: [EvidenceKind; 7] = [
    EvidenceKind::Custody,
    EvidenceKind::Lifecycle,
    EvidenceKind::OperationsPrivacy,
    EvidenceKind::ProviderProfiles,
    EvidenceKind::RestoreFailover,
    EvidenceKind::SdkMatrix,
    EvidenceKind::SupplyChain,
];

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct HexBytes<const N: usize>([u8; N]);

impl<const N: usize> HexBytes<N> {
    fn parse(value: &str) -> Result<Self, String> {
        let bytes = hex::decode(value).map_err(|_| "value is not lowercase hexadecimal")?;
        let bytes: [u8; N] = bytes
            .try_into()
            .map_err(|_| format!("value must contain exactly {} bytes", N))?;
        if hex::encode(bytes) != value {
            return Err("value is not canonical lowercase hexadecimal".to_owned());
        }
        Ok(Self(bytes))
    }

    fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> Serialize for HexBytes<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de, const N: usize> Deserialize<'de> for HexBytes<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

type Sha256Digest = HexBytes<32>;
type Ed25519PublicKey = HexBytes<32>;
type Ed25519Signature = HexBytes<64>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AssuranceManifestV1 {
    schema: String,
    candidate: CandidateBinding,
    supported_runtime_matrix: Vec<String>,
    qualified_profiles: Vec<String>,
    qualification: QualificationStatus,
    independent_review: ReviewStatus,
    test_evidence: Vec<EvidenceRecordV1>,
    known_limitations: Vec<String>,
    statement: Option<SignedStatement>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CandidateInputV1 {
    schema: String,
    source_commit: String,
    build_provenance_digest: Sha256Digest,
    image_digest: Sha256Digest,
    package_digests: BTreeMap<String, Sha256Digest>,
    configuration_commitment: Sha256Digest,
    schema_version: String,
    semantic_freeze_digest: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "status"
)]
enum CandidateBinding {
    #[serde(rename = "pending")]
    Pending { reason: String },
    #[serde(rename = "bound")]
    Bound(Box<BoundCandidateBinding>),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct BoundCandidateBinding {
    candidate_digest: Sha256Digest,
    source_commit: String,
    build_provenance_digest: Sha256Digest,
    image_digest: Sha256Digest,
    package_digests: BTreeMap<String, Sha256Digest>,
    configuration_commitment: Sha256Digest,
    schema_version: String,
    semantic_freeze_digest: Sha256Digest,
}

impl CandidateBinding {
    fn digest(&self) -> Option<&Sha256Digest> {
        match self {
            Self::Pending { .. } => None,
            Self::Bound(binding) => Some(&binding.candidate_digest),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "status"
)]
enum QualificationStatus {
    #[serde(rename = "in-progress")]
    InProgress {
        required_seconds: u64,
        observed_seconds: u64,
        note: String,
    },
    #[serde(rename = "complete")]
    Complete {
        required_seconds: u64,
        observed_seconds: u64,
        started_at: UtcTimestamp,
        completed_at: UtcTimestamp,
        continuous: bool,
        disclosed_gaps: Vec<QualificationGap>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct QualificationGap {
    started_at: UtcTimestamp,
    completed_at: UtcTimestamp,
    reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "status"
)]
enum ReviewStatus {
    #[serde(rename = "pending")]
    Pending { scope: Vec<String>, note: String },
    #[serde(rename = "complete")]
    Complete {
        scope: Vec<String>,
        reviews: Vec<IndependentReview>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct IndependentReview {
    reviewer: String,
    affiliation: String,
    completed_at: UtcTimestamp,
    report: EvidenceArtifact,
    findings: Vec<ReviewFinding>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ReviewFinding {
    id: String,
    severity: FindingSeverity,
    status: FindingStatus,
    summary: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum FindingStatus {
    Open,
    Resolved,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
enum EvidenceKind {
    Custody,
    Lifecycle,
    OperationsPrivacy,
    ProviderProfiles,
    RestoreFailover,
    SdkMatrix,
    SupplyChain,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum EvidenceOutcome {
    Passed,
    Failed,
    NotTested,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct EvidenceRecordV1 {
    schema: String,
    id: String,
    kind: EvidenceKind,
    candidate_digest: Sha256Digest,
    outcome: EvidenceOutcome,
    started_at: UtcTimestamp,
    completed_at: UtcTimestamp,
    artifact: EvidenceArtifact,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct EvidenceArtifact {
    path: String,
    sha256: Sha256Digest,
    retained_until: UtcTimestamp,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct QualificationRecordV1 {
    schema: String,
    candidate_digest: Sha256Digest,
    qualification: QualificationStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ReviewRecordV1 {
    schema: String,
    candidate_digest: Sha256Digest,
    independent_review: ReviewStatus,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct UtcTimestamp(String);

impl Serialize for UtcTimestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for UtcTimestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if utc_seconds(&value).is_some() {
            Ok(Self(value))
        } else {
            Err(D::Error::custom("timestamp must be an exact UTC second"))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SignedStatement {
    signer: String,
    algorithm: SignatureAlgorithm,
    statement_digest: Sha256Digest,
    public_key: Ed25519PublicKey,
    signature: Ed25519Signature,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SignatureAlgorithm {
    Ed25519,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TrustedSignerCatalogue {
    schema: String,
    signers: Vec<TrustedSigner>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TrustedSigner {
    id: String,
    public_key: Ed25519PublicKey,
    purpose: String,
}

pub(crate) fn assurance(arguments: Vec<String>) -> Result<(), String> {
    match arguments.as_slice() {
        [command] if command == "candidate" => write_candidate(Path::new(DEFAULT_MANIFEST)),
        [command, output] if command == "candidate" => write_candidate(Path::new(output)),
        [command, bind, binding] if command == "candidate" && bind == "--bind" => {
            write_bound_candidate(Path::new(binding), Path::new(DEFAULT_MANIFEST))
        }
        [command, bind, binding, output] if command == "candidate" && bind == "--bind" => {
            write_bound_candidate(Path::new(binding), Path::new(output))
        }
        [command, evidence] if command == "record" => {
            record_assurance(Path::new(DEFAULT_MANIFEST), Path::new(evidence))
        }
        [command, evidence, manifest] if command == "record" => {
            record_assurance(Path::new(manifest), Path::new(evidence))
        }
        [command, manifest] if command == "verify" => {
            verify_manifest_file(Path::new(manifest), true)?;
            println!("assurance manifest is complete, signed, and release-eligible");
            Ok(())
        }
        [command, manifest] if command == "summarize" => summarize(Path::new(manifest)),
        [command, manifest] if command == "sign" => sign_manifest(Path::new(manifest)),
        _ => Err(
            "usage: cargo xtask assurance <candidate [--bind <binding>] [output]|record <evidence> [manifest]|sign <manifest>|verify <manifest>|summarize <manifest>>"
                .to_owned(),
        ),
    }
}

pub(crate) fn validate_checked_in_assurance_candidate() -> Result<(), String> {
    let manifest = root().join(DEFAULT_MANIFEST);
    verify_manifest_file(&manifest, false)?;
    let schema: Value = serde_json::from_slice(
        &fs::read(root().join("product/spec/v1/assurance-manifest.schema.json"))
            .map_err(|error| format!("could not read assurance schema: {error}"))?,
    )
    .map_err(|error| format!("assurance schema is not valid JSON: {error}"))?;
    if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema"
        || schema["properties"]["schema"]["const"] != MANIFEST_SCHEMA
        || schema["additionalProperties"] != false
    {
        return Err("assurance manifest schema identity drifted".to_owned());
    }
    let candidate_schema: Value = serde_json::from_slice(
        &fs::read(root().join("product/spec/v1/assurance-candidate.schema.json"))
            .map_err(|error| format!("could not read assurance candidate schema: {error}"))?,
    )
    .map_err(|error| format!("assurance candidate schema is not valid JSON: {error}"))?;
    if candidate_schema["$schema"] != "https://json-schema.org/draft/2020-12/schema"
        || candidate_schema["properties"]["schema"]["const"] != CANDIDATE_INPUT_SCHEMA
        || candidate_schema["additionalProperties"] != false
    {
        return Err("assurance candidate schema identity drifted".to_owned());
    }
    let record_schema: Value = serde_json::from_slice(
        &fs::read(root().join("product/spec/v1/assurance-record.schema.json"))
            .map_err(|error| format!("could not read assurance record schema: {error}"))?,
    )
    .map_err(|error| format!("assurance record schema is not valid JSON: {error}"))?;
    if record_schema["$schema"] != "https://json-schema.org/draft/2020-12/schema"
        || record_schema["oneOf"]
            .as_array()
            .is_none_or(|records| records.len() != 3)
    {
        return Err("assurance record schema identity drifted".to_owned());
    }
    validate_trusted_signers(&read_trusted_signers()?)?;
    let signer_schema: Value = serde_json::from_slice(
        &fs::read(root().join("product/spec/v1/assurance-signers.schema.json"))
            .map_err(|error| format!("could not read assurance signer schema: {error}"))?,
    )
    .map_err(|error| format!("assurance signer schema is not valid JSON: {error}"))?;
    if signer_schema["$schema"] != "https://json-schema.org/draft/2020-12/schema"
        || signer_schema["properties"]["schema"]["const"] != TRUSTED_SIGNERS_SCHEMA
        || signer_schema["additionalProperties"] != false
    {
        return Err("assurance signer schema identity drifted".to_owned());
    }
    Ok(())
}

fn write_candidate(path: &Path) -> Result<(), String> {
    let manifest = pending_manifest();
    write_manifest(path, &manifest)?;
    println!("wrote pending assurance candidate to {}", path.display());
    Ok(())
}

fn pending_manifest() -> AssuranceManifestV1 {
    AssuranceManifestV1 {
        schema: MANIFEST_SCHEMA.to_owned(),
        candidate: CandidateBinding::Pending {
            reason: "Bind the immutable image, packages, provenance, configuration, schema, and semantic freeze after the release builder completes."
                .to_owned(),
        },
        supported_runtime_matrix: vec![
            "browser-chromium-current".to_owned(),
            "cpython-3.9-through-3.14".to_owned(),
            "node-20.19.6-and-22.23.1".to_owned(),
        ],
        qualified_profiles: REQUIRED_PROFILES.map(str::to_owned).to_vec(),
        qualification: QualificationStatus::InProgress {
            required_seconds: MINIMUM_QUALIFICATION_SECONDS,
            observed_seconds: 0,
            note: "No sustained qualification duration has been claimed.".to_owned(),
        },
        independent_review: ReviewStatus::Pending {
            scope: required_review_scope(),
            note: "No independent review has been claimed.".to_owned(),
        },
        test_evidence: Vec::new(),
        known_limitations: vec![
            "Assurance applies only to the exact candidate, configuration, profiles, and runtime matrix named here.".to_owned(),
            "Assurance does not replace deployment-specific security engineering or operational ownership.".to_owned(),
            "Enterprise control-plane, compliance automation, and fleet-governance claims are excluded.".to_owned(),
        ],
        statement: None,
    }
}

fn write_bound_candidate(binding_path: &Path, output: &Path) -> Result<(), String> {
    let input: CandidateInputV1 = serde_json::from_slice(
        &fs::read(binding_path)
            .map_err(|error| format!("could not read candidate binding: {error}"))?,
    )
    .map_err(|error| format!("candidate binding is malformed: {error}"))?;
    if input.schema != CANDIDATE_INPUT_SCHEMA {
        return Err("unknown assurance candidate input schema".to_owned());
    }
    let candidate = candidate_from_input(input)?;
    validate_candidate(&candidate)?;
    let mut manifest = pending_manifest();
    manifest.candidate = candidate;
    validate_manifest(&manifest, output, false)?;
    write_manifest(output, &manifest)?;
    println!("wrote bound assurance candidate to {}", output.display());
    Ok(())
}

fn sign_manifest(path: &Path) -> Result<(), String> {
    let mut manifest = read_manifest(path)?;
    manifest.statement = None;
    let seed = env::var("AUTHS_ASSURANCE_SIGNING_SEED_HEX")
        .map_err(|_| "AUTHS_ASSURANCE_SIGNING_SEED_HEX is unavailable")?;
    let seed = HexBytes::<32>::parse(&seed)?;
    let signing = SigningKey::from_bytes(seed.as_bytes());
    let signers = read_trusted_signers()?;
    validate_trusted_signers(&signers)?;
    let public_key = HexBytes(signing.verifying_key().to_bytes());
    let signer = signers
        .signers
        .iter()
        .find(|signer| signer.public_key == public_key)
        .ok_or("assurance signing key is not in the checked-in trusted signer catalogue")?;
    let digest = statement_digest(&manifest)?;
    manifest.statement = Some(SignedStatement {
        signer: signer.id.clone(),
        algorithm: SignatureAlgorithm::Ed25519,
        statement_digest: digest.clone(),
        public_key,
        signature: HexBytes(signing.sign(digest.as_bytes()).to_bytes()),
    });
    validate_manifest(&manifest, path, true)?;
    write_manifest(path, &manifest)?;
    println!("signed complete assurance manifest");
    Ok(())
}

fn record_assurance(manifest_path: &Path, record_path: &Path) -> Result<(), String> {
    let mut manifest = read_manifest(manifest_path)?;
    validate_manifest(&manifest, manifest_path, false)?;
    let expected = manifest
        .candidate
        .digest()
        .cloned()
        .ok_or("bind the immutable candidate before recording assurance")?;
    let bytes = fs::read(record_path)
        .map_err(|error| format!("could not read assurance record: {error}"))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("assurance record is malformed: {error}"))?;
    let schema = value
        .get("schema")
        .and_then(Value::as_str)
        .ok_or("assurance record has no string schema")?;
    match schema {
        EVIDENCE_SCHEMA => {
            let evidence: EvidenceRecordV1 = serde_json::from_slice(&bytes)
                .map_err(|error| format!("assurance evidence is malformed: {error}"))?;
            validate_evidence(&evidence, &expected, manifest_path, false)?;
            if manifest
                .test_evidence
                .iter()
                .any(|entry| entry.id == evidence.id)
            {
                return Err(format!("duplicate assurance evidence id: {}", evidence.id));
            }
            manifest.test_evidence.push(evidence);
            manifest
                .test_evidence
                .sort_by(|left, right| left.id.cmp(&right.id));
        }
        QUALIFICATION_RECORD_SCHEMA => {
            let record: QualificationRecordV1 = serde_json::from_slice(&bytes)
                .map_err(|error| format!("qualification record is malformed: {error}"))?;
            if record.schema != QUALIFICATION_RECORD_SCHEMA
                || record.candidate_digest != expected
                || !matches!(record.qualification, QualificationStatus::Complete { .. })
            {
                return Err(
                    "qualification record is not complete and bound to the exact candidate"
                        .to_owned(),
                );
            }
            validate_qualification(&record.qualification, true)?;
            manifest.qualification = record.qualification;
        }
        REVIEW_RECORD_SCHEMA => {
            let record: ReviewRecordV1 = serde_json::from_slice(&bytes)
                .map_err(|error| format!("review record is malformed: {error}"))?;
            if record.schema != REVIEW_RECORD_SCHEMA
                || record.candidate_digest != expected
                || !matches!(record.independent_review, ReviewStatus::Complete { .. })
            {
                return Err(
                    "review record is not complete and bound to the exact candidate".to_owned(),
                );
            }
            validate_reviews(&record.independent_review, manifest_path, true)?;
            manifest.independent_review = record.independent_review;
        }
        _ => return Err(format!("unknown assurance record schema: {schema}")),
    }
    manifest.statement = None;
    write_manifest(manifest_path, &manifest)?;
    println!("recorded assurance and invalidated the prior statement");
    Ok(())
}

fn verify_manifest_file(path: &Path, require_release: bool) -> Result<AssuranceManifestV1, String> {
    let manifest = read_manifest(path)?;
    validate_manifest(&manifest, path, require_release)?;
    Ok(manifest)
}

fn read_manifest(path: &Path) -> Result<AssuranceManifestV1, String> {
    serde_json::from_slice(
        &fs::read(path).map_err(|error| format!("could not read assurance manifest: {error}"))?,
    )
    .map_err(|error| format!("assurance manifest is malformed: {error}"))
}

fn write_manifest(path: &Path, manifest: &AssuranceManifestV1) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("could not create assurance directory: {error}"))?;
    }
    let mut bytes = serde_json::to_vec_pretty(manifest)
        .map_err(|error| format!("could not encode assurance manifest: {error}"))?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|error| format!("could not write assurance manifest: {error}"))
}

fn validate_manifest(
    manifest: &AssuranceManifestV1,
    manifest_path: &Path,
    require_release: bool,
) -> Result<(), String> {
    if manifest.schema != MANIFEST_SCHEMA {
        return Err("unknown assurance manifest schema".to_owned());
    }
    validate_candidate(&manifest.candidate)?;
    validate_string_set(
        &manifest.supported_runtime_matrix,
        64,
        128,
        "runtime matrix",
    )?;
    if !["browser-", "cpython-", "node-"].iter().all(|prefix| {
        manifest
            .supported_runtime_matrix
            .iter()
            .any(|item| item.starts_with(prefix))
    }) {
        return Err("assurance runtime matrix must cover browser, CPython, and Node".to_owned());
    }
    validate_string_set(&manifest.qualified_profiles, 16, 128, "qualified profiles")?;
    if manifest
        .qualified_profiles
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != REQUIRED_PROFILES.into_iter().collect()
    {
        return Err("assurance manifest has the wrong qualified profile set".to_owned());
    }
    validate_string_set(&manifest.known_limitations, 64, 512, "known limitations")?;
    validate_qualification(&manifest.qualification, require_release)?;
    validate_reviews(&manifest.independent_review, manifest_path, require_release)?;
    if manifest.test_evidence.len() > 128 {
        return Err("assurance evidence exceeds its item bound".to_owned());
    }
    let mut ids = BTreeSet::new();
    let mut prior_id: Option<&str> = None;
    let expected_digest = manifest.candidate.digest();
    for evidence in &manifest.test_evidence {
        if !ids.insert(evidence.id.as_str()) {
            return Err(format!("duplicate assurance evidence id: {}", evidence.id));
        }
        if prior_id.is_some_and(|prior| prior >= evidence.id.as_str()) {
            return Err("assurance evidence must be sorted by unique id".to_owned());
        }
        prior_id = Some(&evidence.id);
        let expected_digest =
            expected_digest.ok_or("an unbound candidate cannot carry qualification evidence")?;
        validate_evidence(evidence, expected_digest, manifest_path, require_release)?;
    }
    if require_release {
        let _binding = expected_digest.ok_or("assurance candidate binding is incomplete")?;
        let kinds = manifest
            .test_evidence
            .iter()
            .filter(|entry| entry.outcome == EvidenceOutcome::Passed)
            .map(|entry| entry.kind)
            .collect::<BTreeSet<_>>();
        if !REQUIRED_EVIDENCE.iter().all(|kind| kinds.contains(kind)) {
            return Err("assurance manifest is missing passed required evidence".to_owned());
        }
        if manifest
            .test_evidence
            .iter()
            .any(|entry| entry.outcome != EvidenceOutcome::Passed)
        {
            return Err("assurance manifest contains failed or untested evidence".to_owned());
        }
        verify_statement(manifest, &read_trusted_signers()?)?;
    } else if manifest.candidate.digest().is_none() && manifest.statement.is_some() {
        return Err("an unbound candidate cannot carry a signed statement".to_owned());
    }
    Ok(())
}

fn validate_candidate(candidate: &CandidateBinding) -> Result<(), String> {
    match candidate {
        CandidateBinding::Pending { reason } => validate_text(reason, 512, "pending reason"),
        CandidateBinding::Bound(binding) => {
            let BoundCandidateBinding {
                candidate_digest,
                source_commit,
                build_provenance_digest,
                image_digest,
                package_digests,
                configuration_commitment,
                schema_version,
                semantic_freeze_digest,
            } = binding.as_ref();
            if source_commit.len() != 40
                || !source_commit
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err("candidate source commit must be a full lowercase Git SHA".to_owned());
            }
            if package_digests.is_empty()
                || package_digests.len() > 64
                || package_digests
                    .keys()
                    .any(|name| validate_identifier(name, 256).is_err())
            {
                return Err("candidate package digest set is invalid".to_owned());
            }
            validate_identifier(schema_version, 128)?;
            let input = CandidateInputV1 {
                schema: CANDIDATE_INPUT_SCHEMA.to_owned(),
                source_commit: source_commit.clone(),
                build_provenance_digest: build_provenance_digest.clone(),
                image_digest: image_digest.clone(),
                package_digests: package_digests.clone(),
                configuration_commitment: configuration_commitment.clone(),
                schema_version: schema_version.clone(),
                semantic_freeze_digest: semantic_freeze_digest.clone(),
            };
            if candidate_input_digest(&input)? != *candidate_digest {
                return Err(
                    "candidate digest does not commit the complete candidate input".to_owned(),
                );
            }
            Ok(())
        }
    }
}

fn candidate_from_input(input: CandidateInputV1) -> Result<CandidateBinding, String> {
    if input.schema != CANDIDATE_INPUT_SCHEMA {
        return Err("unknown assurance candidate input schema".to_owned());
    }
    let candidate_digest = candidate_input_digest(&input)?;
    Ok(CandidateBinding::Bound(Box::new(BoundCandidateBinding {
        candidate_digest,
        source_commit: input.source_commit,
        build_provenance_digest: input.build_provenance_digest,
        image_digest: input.image_digest,
        package_digests: input.package_digests,
        configuration_commitment: input.configuration_commitment,
        schema_version: input.schema_version,
        semantic_freeze_digest: input.semantic_freeze_digest,
    })))
}

fn candidate_input_digest(input: &CandidateInputV1) -> Result<Sha256Digest, String> {
    let bytes = serde_json::to_vec(input)
        .map_err(|error| format!("could not canonicalize assurance candidate input: {error}"))?;
    Ok(HexBytes(Sha256::digest(bytes).into()))
}

fn validate_qualification(
    qualification: &QualificationStatus,
    require_release: bool,
) -> Result<(), String> {
    match qualification {
        QualificationStatus::InProgress {
            required_seconds,
            observed_seconds,
            note,
        } => {
            if *required_seconds != MINIMUM_QUALIFICATION_SECONDS
                || observed_seconds > required_seconds
            {
                return Err("in-progress qualification duration is invalid".to_owned());
            }
            validate_text(note, 512, "qualification note")?;
            if require_release {
                return Err("thirty-day qualification is incomplete".to_owned());
            }
        }
        QualificationStatus::Complete {
            required_seconds,
            observed_seconds,
            started_at,
            completed_at,
            continuous,
            disclosed_gaps,
        } => {
            let started = utc_seconds(&started_at.0).ok_or("qualification start is invalid")?;
            let completed = utc_seconds(&completed_at.0).ok_or("qualification end is invalid")?;
            if *required_seconds != MINIMUM_QUALIFICATION_SECONDS
                || *observed_seconds < *required_seconds
                || *continuous != disclosed_gaps.is_empty()
                || disclosed_gaps.len() > 128
            {
                return Err("completed qualification duration is invalid".to_owned());
            }
            let elapsed = completed
                .checked_sub(started)
                .ok_or("qualification interval is invalid")?;
            let mut excluded = 0_u64;
            let mut prior_end = started;
            for gap in disclosed_gaps {
                let gap_start =
                    utc_seconds(&gap.started_at.0).ok_or("qualification gap start is invalid")?;
                let gap_end =
                    utc_seconds(&gap.completed_at.0).ok_or("qualification gap end is invalid")?;
                if gap_start < started
                    || gap_start < prior_end
                    || gap_end <= gap_start
                    || gap_end > completed
                {
                    return Err("qualification gap has an invalid interval".to_owned());
                }
                excluded = excluded
                    .checked_add(gap_end - gap_start)
                    .ok_or("qualification gap duration overflowed")?;
                prior_end = gap_end;
                validate_text(&gap.reason, 512, "qualification gap reason")?;
            }
            if elapsed.checked_sub(excluded) != Some(*observed_seconds) {
                return Err(
                    "observed qualification seconds do not match the declared window and gaps"
                        .to_owned(),
                );
            }
        }
    }
    Ok(())
}

fn validate_reviews(
    review: &ReviewStatus,
    manifest_path: &Path,
    require_release: bool,
) -> Result<(), String> {
    match review {
        ReviewStatus::Pending { scope, note } => {
            validate_review_scope(scope)?;
            validate_text(note, 512, "review note")?;
            if require_release {
                return Err("independent review is incomplete".to_owned());
            }
        }
        ReviewStatus::Complete { scope, reviews } => {
            validate_review_scope(scope)?;
            if reviews.is_empty() || reviews.len() > 16 {
                return Err("independent review set is invalid".to_owned());
            }
            for review in reviews {
                validate_text(&review.reviewer, 128, "reviewer")?;
                validate_text(&review.affiliation, 256, "reviewer affiliation")?;
                validate_artifact(&review.report, manifest_path, require_release)?;
                if review.findings.len() > 256 {
                    return Err("independent review findings exceed their item bound".to_owned());
                }
                let mut prior_finding: Option<&str> = None;
                for finding in &review.findings {
                    validate_identifier(&finding.id, 128)?;
                    validate_text(&finding.summary, 512, "finding summary")?;
                    if prior_finding.is_some_and(|prior| prior >= finding.id.as_str()) {
                        return Err(
                            "independent review findings must be sorted and unique".to_owned()
                        );
                    }
                    prior_finding = Some(&finding.id);
                    if finding.status == FindingStatus::Open
                        && matches!(
                            finding.severity,
                            FindingSeverity::Critical | FindingSeverity::High
                        )
                    {
                        return Err(format!(
                            "release-blocking review finding remains open: {}",
                            finding.id
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_review_scope(scope: &[String]) -> Result<(), String> {
    validate_string_set(scope, 64, 256, "review scope")?;
    if scope != required_review_scope() {
        return Err("independent review scope is incomplete".to_owned());
    }
    Ok(())
}

fn validate_evidence(
    evidence: &EvidenceRecordV1,
    expected: &Sha256Digest,
    manifest_path: &Path,
    require_release: bool,
) -> Result<(), String> {
    if evidence.schema != EVIDENCE_SCHEMA || &evidence.candidate_digest != expected {
        return Err("evidence is not bound to the exact assurance candidate".to_owned());
    }
    validate_identifier(&evidence.id, 128)?;
    if evidence.started_at >= evidence.completed_at {
        return Err(format!("evidence has an invalid interval: {}", evidence.id));
    }
    validate_artifact(&evidence.artifact, manifest_path, require_release)
}

fn validate_artifact(
    artifact: &EvidenceArtifact,
    manifest_path: &Path,
    require_release: bool,
) -> Result<(), String> {
    let relative = Path::new(&artifact.path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err("assurance artifact path must remain below the manifest directory".to_owned());
    }
    let base = manifest_path
        .parent()
        .ok_or("assurance manifest has no parent directory")?;
    let path = base.join(relative);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("could not inspect assurance artifact: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err("assurance artifact must be a regular file".to_owned());
    }
    if sha256_path(&path)? != artifact.sha256 {
        return Err(format!(
            "assurance artifact digest differs: {}",
            artifact.path
        ));
    }
    if require_release {
        let retained_until = utc_seconds(&artifact.retained_until.0)
            .ok_or("assurance artifact retention timestamp is invalid")?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "system time is before the Unix epoch")?
            .as_secs();
        if retained_until <= now {
            return Err(format!(
                "assurance artifact retention expired: {}",
                artifact.path
            ));
        }
    }
    Ok(())
}

fn verify_statement(
    manifest: &AssuranceManifestV1,
    signers: &TrustedSignerCatalogue,
) -> Result<(), String> {
    validate_trusted_signers(signers)?;
    let statement = manifest
        .statement
        .as_ref()
        .ok_or("assurance manifest has no signed statement")?;
    validate_identifier(&statement.signer, 128)?;
    if !signers
        .signers
        .iter()
        .any(|signer| signer.id == statement.signer && signer.public_key == statement.public_key)
    {
        return Err("assurance statement signer is not trusted".to_owned());
    }
    let digest = statement_digest(manifest)?;
    if statement.statement_digest != digest {
        return Err("assurance statement digest differs from the manifest".to_owned());
    }
    let key = VerifyingKey::from_bytes(statement.public_key.as_bytes())
        .map_err(|_| "assurance statement public key is invalid")?;
    let signature = Signature::from_bytes(statement.signature.as_bytes());
    key.verify(digest.as_bytes(), &signature)
        .map_err(|_| "assurance statement signature is invalid".to_owned())
}

fn read_trusted_signers() -> Result<TrustedSignerCatalogue, String> {
    serde_json::from_slice(
        &fs::read(root().join(TRUSTED_SIGNERS))
            .map_err(|error| format!("could not read assurance trusted signers: {error}"))?,
    )
    .map_err(|error| format!("assurance trusted signers are malformed: {error}"))
}

fn validate_trusted_signers(catalogue: &TrustedSignerCatalogue) -> Result<(), String> {
    if catalogue.schema != TRUSTED_SIGNERS_SCHEMA || catalogue.signers.len() > 16 {
        return Err("assurance trusted signer catalogue is invalid".to_owned());
    }
    let mut prior: Option<&str> = None;
    let mut public_keys = BTreeSet::new();
    for signer in &catalogue.signers {
        validate_identifier(&signer.id, 128)?;
        validate_text(&signer.purpose, 256, "signer purpose")?;
        if prior.is_some_and(|prior| prior >= signer.id.as_str()) {
            return Err("assurance trusted signers must be sorted and unique".to_owned());
        }
        if !public_keys.insert(&signer.public_key) {
            return Err("assurance trusted signer keys must be unique".to_owned());
        }
        prior = Some(&signer.id);
    }
    Ok(())
}

fn statement_digest(manifest: &AssuranceManifestV1) -> Result<Sha256Digest, String> {
    let mut unsigned = manifest.clone();
    unsigned.statement = None;
    let bytes = serde_json::to_vec(&unsigned)
        .map_err(|error| format!("could not canonicalize assurance statement: {error}"))?;
    Ok(HexBytes(Sha256::digest(bytes).into()))
}

fn summarize(path: &Path) -> Result<(), String> {
    let manifest = verify_manifest_file(path, false)?;
    let (candidate, binding) = match &manifest.candidate {
        CandidateBinding::Pending { .. } => ("pending".to_owned(), "incomplete"),
        CandidateBinding::Bound(binding) => {
            (hex::encode(binding.candidate_digest.as_bytes()), "bound")
        }
    };
    let (observed, qualification) = match manifest.qualification {
        QualificationStatus::InProgress {
            observed_seconds, ..
        } => (observed_seconds, "in progress"),
        QualificationStatus::Complete {
            observed_seconds, ..
        } => (observed_seconds, "complete"),
    };
    let review = match manifest.independent_review {
        ReviewStatus::Pending { .. } => "pending",
        ReviewStatus::Complete { .. } => "complete",
    };
    println!("# Auths open production assurance\n");
    println!("- Candidate: `{candidate}` ({binding})");
    println!("- Qualification: {qualification} ({observed} seconds recorded)");
    println!("- Independent review: {review}");
    println!("- Evidence records: {}", manifest.test_evidence.len());
    println!("- Known limitations: {}", manifest.known_limitations.len());
    println!(
        "- Signed statement: {}",
        if manifest.statement.is_some() {
            "present"
        } else {
            "absent"
        }
    );
    Ok(())
}

fn validate_string_set(
    values: &[String],
    maximum_items: usize,
    maximum_bytes: usize,
    name: &str,
) -> Result<(), String> {
    if values.is_empty() || values.len() > maximum_items {
        return Err(format!("{name} is empty or exceeds its item bound"));
    }
    let mut prior: Option<&str> = None;
    for value in values {
        validate_text(value, maximum_bytes, name)?;
        if prior.is_some_and(|prior| prior >= value.as_str()) {
            return Err(format!("{name} must be sorted and unique"));
        }
        prior = Some(value);
    }
    Ok(())
}

fn validate_text(value: &str, maximum: usize, name: &str) -> Result<(), String> {
    if value.trim() != value || value.is_empty() || value.len() > maximum || value.contains('\0') {
        return Err(format!("{name} is malformed or exceeds its byte bound"));
    }
    Ok(())
}

fn validate_identifier(value: &str, maximum: usize) -> Result<(), String> {
    if value.is_empty()
        || value.len() > maximum
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/' | b'@')
        })
    {
        return Err("assurance identifier is malformed".to_owned());
    }
    Ok(())
}

fn sha256_path(path: &Path) -> Result<Sha256Digest, String> {
    let bytes = fs::read(path).map_err(|error| {
        format!(
            "could not read assurance artifact {}: {error}",
            path.display()
        )
    })?;
    Ok(HexBytes(Sha256::digest(bytes).into()))
}

fn utc_seconds(value: &str) -> Option<u64> {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || bytes.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit()
        })
    {
        return None;
    }
    let component = |start: usize, end: usize| value[start..end].parse::<u64>().ok();
    let year = component(0, 4)?;
    let month = component(5, 7)?;
    let day = component(8, 10)?;
    let hour = component(11, 13)?;
    let minute = component(14, 16)?;
    let second = component(17, 19)?;
    if year < 2020 || !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let leap = |year: u64| {
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
    };
    let month_days = [
        31_u64,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0 || day > month_days[(month - 1) as usize] {
        return None;
    }
    let prior_year_days = (1970..year)
        .map(|year| if leap(year) { 366 } else { 365 })
        .sum::<u64>();
    let prior_month_days = month_days[..(month - 1) as usize].iter().sum::<u64>();
    Some(
        (prior_year_days + prior_month_days + day - 1) * 86_400
            + hour * 3_600
            + minute * 60
            + second,
    )
}

fn required_review_scope() -> Vec<String> {
    [
        "authority-and-attenuation",
        "custody-and-key-lifecycle",
        "deployment-and-postgresql",
        "lifecycle-replay-and-recovery",
        "receipt-disclosure-and-telemetry",
        "rust-wasm-pyo3-and-client-boundaries",
        "three-exact-effect-profile-gateways",
    ]
    .map(str::to_owned)
    .to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn pending() -> AssuranceManifestV1 {
        AssuranceManifestV1 {
            schema: MANIFEST_SCHEMA.into(),
            candidate: CandidateBinding::Pending {
                reason: "candidate is not frozen".into(),
            },
            supported_runtime_matrix: vec![
                "browser-chromium-current".into(),
                "cpython-3.9-through-3.14".into(),
                "node-20.19.6-and-22.23.1".into(),
            ],
            qualified_profiles: REQUIRED_PROFILES.map(str::to_owned).to_vec(),
            qualification: QualificationStatus::InProgress {
                required_seconds: MINIMUM_QUALIFICATION_SECONDS,
                observed_seconds: 0,
                note: "qualification has not started".into(),
            },
            independent_review: ReviewStatus::Pending {
                scope: required_review_scope(),
                note: "review has not started".into(),
            },
            test_evidence: Vec::new(),
            known_limitations: vec!["candidate is incomplete".into()],
            statement: None,
        }
    }

    fn bound() -> AssuranceManifestV1 {
        let mut manifest = pending();
        manifest.candidate = candidate_from_input(CandidateInputV1 {
            schema: CANDIDATE_INPUT_SCHEMA.into(),
            source_commit: "1".repeat(40),
            build_provenance_digest: HexBytes([2; 32]),
            image_digest: HexBytes([3; 32]),
            package_digests: BTreeMap::from([("auths-sdk".into(), HexBytes([4; 32]))]),
            configuration_commitment: HexBytes([5; 32]),
            schema_version: "auths.production-schema/1".into(),
            semantic_freeze_digest: HexBytes([6; 32]),
        })
        .unwrap();
        manifest
    }

    #[test]
    fn pending_candidate_is_structural_but_never_release_eligible() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("manifest.json");
        let manifest = pending();
        validate_manifest(&manifest, &path, false).unwrap();
        let error = validate_manifest(&manifest, &path, true).unwrap_err();
        assert!(error.contains("qualification is incomplete"));
    }

    #[test]
    fn hex_and_timestamp_types_reject_noncanonical_inputs() {
        assert!(Sha256Digest::parse(&"A".repeat(64)).is_err());
        assert!(Sha256Digest::parse("00").is_err());
        assert!(utc_seconds("2026-08-14T12:00:00Z").is_some());
        assert!(utc_seconds("2026-02-29T12:00:00Z").is_none());
        assert!(utc_seconds("2028-02-29T12:00:00Z").is_some());
        assert!(utc_seconds("2026-08-14T12:00:00.1Z").is_none());
    }

    #[test]
    fn statement_binds_every_manifest_field() {
        let mut manifest = pending();
        let signing = SigningKey::from_bytes(&[9; 32]);
        let digest = statement_digest(&manifest).unwrap();
        manifest.statement = Some(SignedStatement {
            signer: "release-assurance-test".into(),
            algorithm: SignatureAlgorithm::Ed25519,
            statement_digest: digest.clone(),
            public_key: HexBytes(signing.verifying_key().to_bytes()),
            signature: HexBytes(signing.sign(digest.as_bytes()).to_bytes()),
        });
        let signers = TrustedSignerCatalogue {
            schema: TRUSTED_SIGNERS_SCHEMA.into(),
            signers: vec![TrustedSigner {
                id: "release-assurance-test".into(),
                public_key: HexBytes(signing.verifying_key().to_bytes()),
                purpose: "test assurance statements".into(),
            }],
        };
        verify_statement(&manifest, &signers).unwrap();
        manifest.known_limitations.push("changed".into());
        assert!(verify_statement(&manifest, &signers).is_err());
    }

    #[test]
    fn qualification_record_requires_the_exact_complete_window() {
        let directory = tempdir().unwrap();
        let manifest_path = directory.path().join("manifest.json");
        let record_path = directory.path().join("qualification.json");
        let manifest = bound();
        let candidate_digest = manifest.candidate.digest().unwrap().clone();
        write_manifest(&manifest_path, &manifest).unwrap();
        let record = QualificationRecordV1 {
            schema: QUALIFICATION_RECORD_SCHEMA.into(),
            candidate_digest,
            qualification: QualificationStatus::Complete {
                required_seconds: MINIMUM_QUALIFICATION_SECONDS,
                observed_seconds: MINIMUM_QUALIFICATION_SECONDS,
                started_at: UtcTimestamp("2026-01-01T00:00:00Z".into()),
                completed_at: UtcTimestamp("2026-01-31T00:00:00Z".into()),
                continuous: true,
                disclosed_gaps: Vec::new(),
            },
        };
        fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
        record_assurance(&manifest_path, &record_path).unwrap();
        assert!(matches!(
            read_manifest(&manifest_path).unwrap().qualification,
            QualificationStatus::Complete { .. }
        ));
    }

    #[test]
    fn assurance_record_rejects_unknown_schemas() {
        let directory = tempdir().unwrap();
        let manifest_path = directory.path().join("manifest.json");
        let record_path = directory.path().join("record.json");
        write_manifest(&manifest_path, &bound()).unwrap();
        fs::write(&record_path, br#"{"schema":"auths.unknown/1"}"#).unwrap();
        assert!(
            record_assurance(&manifest_path, &record_path)
                .unwrap_err()
                .contains("unknown assurance record schema")
        );
    }
}
