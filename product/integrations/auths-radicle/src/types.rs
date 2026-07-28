//! Validated Radicle workflow identifiers and closed profile objects.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize};

use crate::canonical::{CanonicalError, canonical_digest, canonical_json};

/// Exact profile identifier.
pub const PROFILE_ID: &str = "auths.radicle.issue-address";
/// Exact profile semantic version.
pub const PROFILE_VERSION: u16 = 1;
/// Exact patch-open capability.
pub const PATCH_OPEN_CAPABILITY: &str = "radicle.patch/open";
/// Exact canonical media type.
pub const MEDIA_TYPE: &str = "application/vnd.auths.radicle.patch-open.v1+json";
/// Maximum canonical exact-action bytes.
pub const MAX_ACTION_BYTES: usize = 256 * 1024;
/// Maximum canonical workflow-grant bytes.
pub const MAX_GRANT_BYTES: usize = 256 * 1024;
/// Hard maximum candidate bundle bytes.
pub const HARD_MAX_BUNDLE_BYTES: u64 = 16 * 1024 * 1024;
/// Hard maximum expanded candidate bytes.
pub const HARD_MAX_EXPANDED_BYTES: u64 = 64 * 1024 * 1024;
/// Hard maximum candidate object count.
pub const HARD_MAX_OBJECTS: u32 = 20_000;
/// Hard maximum candidate tree depth.
pub const HARD_MAX_TREE_DEPTH: u16 = 64;
/// Hard maximum path bytes.
pub const HARD_MAX_PATH_BYTES: u16 = 1024;

macro_rules! validated_string {
    ($name:ident, $validator:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Parses and validates one canonical identifier.
            ///
            /// # Errors
            ///
            /// Returns a typed validation failure for malformed input.
            pub fn parse(value: impl Into<String>) -> Result<Self, TypeError> {
                let value = value.into();
                if !$validator(&value) {
                    return Err(TypeError::$name);
                }
                Ok(Self(value))
            }

            /// Returns the canonical string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = TypeError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

fn valid_rid(value: &str) -> bool {
    value.len() >= 12
        && value.len() <= 128
        && value.starts_with("rad:z")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b':')
}

fn valid_git_oid(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_radicle_did(value: &str) -> bool {
    value.starts_with("did:key:z")
        && value.len() <= 196
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_' | b'.'))
}

fn valid_node_id(value: &str) -> bool {
    value.starts_with('z')
        && (32..=128).contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn valid_workflow_id(value: &str) -> bool {
    (8..=96).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_audience(value: &str) -> bool {
    value.len() <= 256 && auths_model::Audience::parse(value).is_ok()
}

validated_string!(Rid, valid_rid);
validated_string!(CobId, valid_git_oid);
validated_string!(GitOid, valid_git_oid);
validated_string!(DigestHex, valid_digest);
validated_string!(RadicleDid, valid_radicle_did);
validated_string!(NodeId, valid_node_id);
validated_string!(WorkflowId, valid_workflow_id);
validated_string!(ExecutorAudience, valid_audience);

impl DigestHex {
    /// Constructs a lowercase digest from exact SHA-256 bytes.
    #[must_use]
    pub fn from_digest_bytes(bytes: [u8; 32]) -> Self {
        Self(hex::encode(bytes))
    }

    /// Decodes the digest.
    ///
    /// # Errors
    ///
    /// Returns a typed error if an invariant was violated in memory.
    pub fn to_bytes(&self) -> Result<[u8; 32], TypeError> {
        hex::decode(&self.0)
            .map_err(|_| TypeError::DigestHex)?
            .try_into()
            .map_err(|_| TypeError::DigestHex)
    }
}

/// Closed identifier validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TypeError {
    /// Invalid RID.
    #[error("invalid Radicle repository identifier")]
    Rid,
    /// Invalid COB identifier.
    #[error("invalid Radicle collaborative-object identifier")]
    CobId,
    /// Invalid Git OID.
    #[error("invalid Git object identifier")]
    GitOid,
    /// Invalid digest.
    #[error("invalid lowercase SHA-256 digest")]
    DigestHex,
    /// Invalid Radicle DID.
    #[error("invalid Radicle DID")]
    RadicleDid,
    /// Invalid node identifier.
    #[error("invalid Radicle node identifier")]
    NodeId,
    /// Invalid workflow identifier.
    #[error("invalid workflow identifier")]
    WorkflowId,
    /// Invalid Auths audience.
    #[error("invalid executor audience")]
    ExecutorAudience,
}

/// Exact verifier configuration required by a grant and loaded by an executor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierConfiguration {
    profile: String,
    candidate_inspector: String,
    radicle_adapter: String,
    canonical_reference: String,
    observation_peers: Vec<NodeId>,
    minimum_successful_peers: u16,
    maximum_evidence_age_seconds: u64,
    synchronization_timeout_seconds: u16,
    maximum_bundle_bytes: u64,
    maximum_expanded_bytes: u64,
    maximum_objects: u32,
    maximum_tree_depth: u16,
    maximum_path_bytes: u16,
    expected_signer_did: RadicleDid,
    executor_audience: ExecutorAudience,
    receipt_schema: String,
}

/// Input for constructing one verifier configuration.
pub struct VerifierConfigurationInput {
    /// Candidate inspector implementation/version.
    pub candidate_inspector: String,
    /// Radicle adapter compatibility/version.
    pub radicle_adapter: String,
    /// Canonical reference derivation/version.
    pub canonical_reference: String,
    /// Configured evidence peers.
    pub observation_peers: Vec<NodeId>,
    /// Minimum successful peers.
    pub minimum_successful_peers: u16,
    /// Maximum evidence age.
    pub maximum_evidence_age_seconds: u64,
    /// Synchronization timeout.
    pub synchronization_timeout_seconds: u16,
    /// Candidate bundle hard limit.
    pub maximum_bundle_bytes: u64,
    /// Expanded candidate hard limit.
    pub maximum_expanded_bytes: u64,
    /// Candidate object hard limit.
    pub maximum_objects: u32,
    /// Tree depth hard limit.
    pub maximum_tree_depth: u16,
    /// Path-byte hard limit.
    pub maximum_path_bytes: u16,
    /// Required signer.
    pub expected_signer_did: RadicleDid,
    /// Required executor.
    pub executor_audience: ExecutorAudience,
    /// Receipt schema.
    pub receipt_schema: String,
}

impl VerifierConfiguration {
    /// Constructs and validates an exact executor configuration.
    ///
    /// # Errors
    ///
    /// Returns a closed validation failure for unsafe or inconsistent limits.
    pub fn new(mut input: VerifierConfigurationInput) -> Result<Self, ValidationError> {
        input.observation_peers.sort();
        if input
            .observation_peers
            .windows(2)
            .any(|window| window[0] == window[1])
            || input.observation_peers.is_empty()
            || input.minimum_successful_peers == 0
            || usize::from(input.minimum_successful_peers) > input.observation_peers.len()
            || input.maximum_evidence_age_seconds == 0
            || input.synchronization_timeout_seconds == 0
            || input.maximum_bundle_bytes == 0
            || input.maximum_bundle_bytes > HARD_MAX_BUNDLE_BYTES
            || input.maximum_expanded_bytes < input.maximum_bundle_bytes
            || input.maximum_expanded_bytes > HARD_MAX_EXPANDED_BYTES
            || input.maximum_objects == 0
            || input.maximum_objects > HARD_MAX_OBJECTS
            || input.maximum_tree_depth == 0
            || input.maximum_tree_depth > HARD_MAX_TREE_DEPTH
            || input.maximum_path_bytes == 0
            || input.maximum_path_bytes > HARD_MAX_PATH_BYTES
            || !valid_component_version(&input.candidate_inspector)
            || !valid_component_version(&input.radicle_adapter)
            || !valid_component_version(&input.canonical_reference)
            || !valid_component_version(&input.receipt_schema)
        {
            return Err(ValidationError::InvalidConfiguration);
        }
        Ok(Self {
            profile: format!("{PROFILE_ID}/{PROFILE_VERSION}"),
            candidate_inspector: input.candidate_inspector,
            radicle_adapter: input.radicle_adapter,
            canonical_reference: input.canonical_reference,
            observation_peers: input.observation_peers,
            minimum_successful_peers: input.minimum_successful_peers,
            maximum_evidence_age_seconds: input.maximum_evidence_age_seconds,
            synchronization_timeout_seconds: input.synchronization_timeout_seconds,
            maximum_bundle_bytes: input.maximum_bundle_bytes,
            maximum_expanded_bytes: input.maximum_expanded_bytes,
            maximum_objects: input.maximum_objects,
            maximum_tree_depth: input.maximum_tree_depth,
            maximum_path_bytes: input.maximum_path_bytes,
            expected_signer_did: input.expected_signer_did,
            executor_audience: input.executor_audience,
            receipt_schema: input.receipt_schema,
        })
    }

    /// Validates a deserialized configuration.
    ///
    /// # Errors
    ///
    /// Returns a closed configuration failure.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let rebuilt = Self::new(VerifierConfigurationInput {
            candidate_inspector: self.candidate_inspector.clone(),
            radicle_adapter: self.radicle_adapter.clone(),
            canonical_reference: self.canonical_reference.clone(),
            observation_peers: self.observation_peers.clone(),
            minimum_successful_peers: self.minimum_successful_peers,
            maximum_evidence_age_seconds: self.maximum_evidence_age_seconds,
            synchronization_timeout_seconds: self.synchronization_timeout_seconds,
            maximum_bundle_bytes: self.maximum_bundle_bytes,
            maximum_expanded_bytes: self.maximum_expanded_bytes,
            maximum_objects: self.maximum_objects,
            maximum_tree_depth: self.maximum_tree_depth,
            maximum_path_bytes: self.maximum_path_bytes,
            expected_signer_did: self.expected_signer_did.clone(),
            executor_audience: self.executor_audience.clone(),
            receipt_schema: self.receipt_schema.clone(),
        })?;
        if &rebuilt != self {
            return Err(ValidationError::InvalidConfiguration);
        }
        Ok(())
    }

    /// Returns the canonical configuration digest.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }

    /// Returns the maximum candidate bundle bytes.
    #[must_use]
    pub const fn maximum_bundle_bytes(&self) -> u64 {
        self.maximum_bundle_bytes
    }

    /// Returns the maximum expanded candidate bytes.
    #[must_use]
    pub const fn maximum_expanded_bytes(&self) -> u64 {
        self.maximum_expanded_bytes
    }

    /// Returns the maximum candidate object count.
    #[must_use]
    pub const fn maximum_objects(&self) -> u32 {
        self.maximum_objects
    }

    /// Returns the maximum candidate tree depth.
    #[must_use]
    pub const fn maximum_tree_depth(&self) -> u16 {
        self.maximum_tree_depth
    }

    /// Returns the maximum candidate path bytes.
    #[must_use]
    pub const fn maximum_path_bytes(&self) -> u16 {
        self.maximum_path_bytes
    }

    /// Returns the maximum evidence age.
    #[must_use]
    pub const fn maximum_evidence_age_seconds(&self) -> u64 {
        self.maximum_evidence_age_seconds
    }

    /// Returns the synchronization timeout.
    #[must_use]
    pub const fn synchronization_timeout_seconds(&self) -> u16 {
        self.synchronization_timeout_seconds
    }

    /// Returns the configured evidence peers.
    #[must_use]
    pub fn observation_peers(&self) -> &[NodeId] {
        &self.observation_peers
    }

    /// Returns the minimum successful evidence peers.
    #[must_use]
    pub const fn minimum_successful_peers(&self) -> u16 {
        self.minimum_successful_peers
    }

    /// Returns the expected signer.
    #[must_use]
    pub const fn expected_signer_did(&self) -> &RadicleDid {
        &self.expected_signer_did
    }

    /// Returns the exact executor audience.
    #[must_use]
    pub const fn executor_audience(&self) -> &ExecutorAudience {
        &self.executor_audience
    }

    /// Returns the candidate inspector implementation/version.
    #[must_use]
    pub fn candidate_inspector(&self) -> &str {
        &self.candidate_inspector
    }

    /// Returns the Radicle adapter compatibility/version.
    #[must_use]
    pub fn radicle_adapter(&self) -> &str {
        &self.radicle_adapter
    }

    /// Returns the canonical-reference derivation/version.
    #[must_use]
    pub fn canonical_reference(&self) -> &str {
        &self.canonical_reference
    }

    /// Returns the receipt schema version.
    #[must_use]
    pub fn receipt_schema(&self) -> &str {
        &self.receipt_schema
    }
}

fn valid_component_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/'))
}

/// One normalized changed path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathChange {
    path: String,
    old_oid: Option<GitOid>,
    new_oid: Option<GitOid>,
    old_mode: Option<u32>,
    new_mode: Option<u32>,
    conservative_changed_bytes: u64,
}

impl PathChange {
    /// Constructs one bounded normalized path change.
    ///
    /// # Errors
    ///
    /// Returns a validation failure for a non-canonical path or forbidden mode.
    pub fn new(
        path: impl Into<String>,
        old_oid: Option<GitOid>,
        new_oid: Option<GitOid>,
        old_mode: Option<u32>,
        new_mode: Option<u32>,
        conservative_changed_bytes: u64,
    ) -> Result<Self, ValidationError> {
        let path = path.into();
        validate_repo_path(&path, false)?;
        for mode in [old_mode, new_mode].into_iter().flatten() {
            if !matches!(mode, 0o100_644 | 0o100_755) {
                return Err(ValidationError::ForbiddenFileMode);
            }
        }
        Ok(Self {
            path,
            old_oid,
            new_oid,
            old_mode,
            new_mode,
            conservative_changed_bytes,
        })
    }

    /// Returns the repository-relative path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the conservative byte count.
    #[must_use]
    pub const fn conservative_changed_bytes(&self) -> u64 {
        self.conservative_changed_bytes
    }
}

/// Facts derived by the trusted candidate inspector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateFacts {
    base_oid: GitOid,
    candidate_oid: GitOid,
    commit_oids: Vec<GitOid>,
    changes: Vec<PathChange>,
    bundle_digest: DigestHex,
    commit_set_digest: DigestHex,
    tree_delta_digest: DigestHex,
    expanded_bytes: u64,
    object_count: u32,
}

impl CandidateFacts {
    /// Constructs sorted, duplicate-free candidate facts and their commitments.
    ///
    /// # Errors
    ///
    /// Returns a closed validation or canonicalization failure.
    pub fn new(
        base_oid: GitOid,
        candidate_oid: GitOid,
        mut commit_oids: Vec<GitOid>,
        mut changes: Vec<PathChange>,
        bundle_digest: DigestHex,
        expanded_bytes: u64,
        object_count: u32,
    ) -> Result<Self, ValidationError> {
        commit_oids.sort();
        changes.sort_by(|left, right| left.path.cmp(&right.path));
        if commit_oids.is_empty()
            || commit_oids.windows(2).any(|window| window[0] == window[1])
            || changes.is_empty()
            || changes
                .windows(2)
                .any(|window| window[0].path == window[1].path)
            || object_count == 0
            || object_count > HARD_MAX_OBJECTS
            || expanded_bytes == 0
            || expanded_bytes > HARD_MAX_EXPANDED_BYTES
        {
            return Err(ValidationError::InvalidCandidate);
        }
        let commit_set_digest =
            canonical_digest(&commit_oids).map_err(|_| ValidationError::Canonicalization)?;
        let tree_delta_digest =
            canonical_digest(&changes).map_err(|_| ValidationError::Canonicalization)?;
        Ok(Self {
            base_oid,
            candidate_oid,
            commit_oids,
            changes,
            bundle_digest,
            commit_set_digest,
            tree_delta_digest,
            expanded_bytes,
            object_count,
        })
    }

    /// Returns the base OID.
    #[must_use]
    pub const fn base_oid(&self) -> &GitOid {
        &self.base_oid
    }

    /// Returns the candidate OID.
    #[must_use]
    pub const fn candidate_oid(&self) -> &GitOid {
        &self.candidate_oid
    }

    /// Returns commit OIDs.
    #[must_use]
    pub fn commit_oids(&self) -> &[GitOid] {
        &self.commit_oids
    }

    /// Returns changed paths.
    #[must_use]
    pub fn changes(&self) -> &[PathChange] {
        &self.changes
    }

    /// Returns the bundle digest.
    #[must_use]
    pub const fn bundle_digest(&self) -> &DigestHex {
        &self.bundle_digest
    }

    /// Returns the commit-set digest.
    #[must_use]
    pub const fn commit_set_digest(&self) -> &DigestHex {
        &self.commit_set_digest
    }

    /// Returns the tree-delta digest.
    #[must_use]
    pub const fn tree_delta_digest(&self) -> &DigestHex {
        &self.tree_delta_digest
    }

    /// Returns conservative total changed bytes.
    #[must_use]
    pub fn changed_bytes(&self) -> Option<u64> {
        self.changes.iter().try_fold(0_u64, |total, change| {
            total.checked_add(change.conservative_changed_bytes)
        })
    }
}

/// Hostile candidate submission accepted at the product boundary.
#[derive(Clone, Debug)]
pub struct CandidateSubmission {
    /// Bounded Git bundle bytes.
    pub bundle: Vec<u8>,
    /// Declared base OID.
    pub base_oid: GitOid,
    /// Declared candidate OID.
    pub candidate_oid: GitOid,
    /// Proposed patch title.
    pub patch_title: String,
    /// Proposed patch description before the deterministic issue trailer.
    pub patch_body: String,
}

impl CandidateSubmission {
    /// Returns the exact deterministic patch message.
    #[must_use]
    pub fn patch_message(&self, issue: &CobId, workflow: &WorkflowId) -> String {
        format!(
            "{}\n\n{}\n\nRadicle-Issue: {}\nAuths-Workflow: {}",
            self.patch_title, self.patch_body, issue, workflow
        )
    }
}

/// Human-issued workflow constraints bound by digest into the Auths resource.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueAddressGrantV1 {
    profile: String,
    workflow_id: WorkflowId,
    rid: Rid,
    issue_id: CobId,
    repository_identity_revision: GitOid,
    canonical_base_oid: GitOid,
    allowed_path_prefixes: Vec<String>,
    denied_path_prefixes: Vec<String>,
    maximum_changed_files: u32,
    maximum_changed_bytes: u64,
    maximum_commits: u32,
    expected_signer_did: RadicleDid,
    executor_audience: ExecutorAudience,
    expires_at: u64,
    maximum_patches: u8,
    maximum_revisions: u8,
    allow_canonical_update: bool,
    allow_identity_update: bool,
    allow_delegate_update: bool,
    required_configuration: VerifierConfiguration,
}

/// Construction input for one human workflow grant.
pub struct IssueAddressGrantInput {
    /// Workflow identifier.
    pub workflow_id: WorkflowId,
    /// Repository identifier.
    pub rid: Rid,
    /// Issue identifier.
    pub issue_id: CobId,
    /// Repository identity revision.
    pub repository_identity_revision: GitOid,
    /// Canonical base.
    pub canonical_base_oid: GitOid,
    /// Allowed path prefixes.
    pub allowed_path_prefixes: Vec<String>,
    /// Denied path prefixes.
    pub denied_path_prefixes: Vec<String>,
    /// File budget.
    pub maximum_changed_files: u32,
    /// Byte budget.
    pub maximum_changed_bytes: u64,
    /// Commit budget.
    pub maximum_commits: u32,
    /// Required signer.
    pub expected_signer_did: RadicleDid,
    /// Required executor.
    pub executor_audience: ExecutorAudience,
    /// Expiration.
    pub expires_at: u64,
    /// Required configuration.
    pub required_configuration: VerifierConfiguration,
}

impl IssueAddressGrantV1 {
    /// Constructs exact one-patch workflow constraints.
    ///
    /// # Errors
    ///
    /// Returns a validation failure for unsafe or non-canonical constraints.
    pub fn new(mut input: IssueAddressGrantInput) -> Result<Self, ValidationError> {
        input.allowed_path_prefixes.sort();
        input.denied_path_prefixes.sort();
        validate_path_rules(&input.allowed_path_prefixes)?;
        validate_path_rules(&input.denied_path_prefixes)?;
        input.required_configuration.validate()?;
        if input.allowed_path_prefixes.is_empty()
            || input.maximum_changed_files == 0
            || input.maximum_changed_files > 10_000
            || input.maximum_changed_bytes == 0
            || input.maximum_changed_bytes > HARD_MAX_EXPANDED_BYTES
            || input.maximum_commits == 0
            || input.maximum_commits > 1_000
            || input.expires_at == 0
            || input.expected_signer_did != *input.required_configuration.expected_signer_did()
            || input.executor_audience != *input.required_configuration.executor_audience()
        {
            return Err(ValidationError::InvalidGrant);
        }
        Ok(Self {
            profile: format!("{PROFILE_ID}/{PROFILE_VERSION}"),
            workflow_id: input.workflow_id,
            rid: input.rid,
            issue_id: input.issue_id,
            repository_identity_revision: input.repository_identity_revision,
            canonical_base_oid: input.canonical_base_oid,
            allowed_path_prefixes: input.allowed_path_prefixes,
            denied_path_prefixes: input.denied_path_prefixes,
            maximum_changed_files: input.maximum_changed_files,
            maximum_changed_bytes: input.maximum_changed_bytes,
            maximum_commits: input.maximum_commits,
            expected_signer_did: input.expected_signer_did,
            executor_audience: input.executor_audience,
            expires_at: input.expires_at,
            maximum_patches: 1,
            maximum_revisions: 1,
            allow_canonical_update: false,
            allow_identity_update: false,
            allow_delegate_update: false,
            required_configuration: input.required_configuration,
        })
    }

    /// Parses the unique canonical representation.
    ///
    /// # Errors
    ///
    /// Returns a typed validation failure for malformed, oversized,
    /// non-canonical, or semantically invalid bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        if bytes.is_empty() || bytes.len() > MAX_GRANT_BYTES {
            return Err(ValidationError::LimitExceeded);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| ValidationError::Malformed)?;
        value.validate()?;
        if value
            .canonical_bytes()
            .map_err(|_| ValidationError::Canonicalization)?
            != bytes
        {
            return Err(ValidationError::NonCanonical);
        }
        Ok(value)
    }

    /// Returns canonical grant bytes.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_json(self)
    }

    /// Returns the content-addressed grant digest.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }

    /// Validates a deserialized grant.
    ///
    /// # Errors
    ///
    /// Returns a closed validation failure.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.profile != format!("{PROFILE_ID}/{PROFILE_VERSION}")
            || self.maximum_patches != 1
            || self.maximum_revisions != 1
            || self.allow_canonical_update
            || self.allow_identity_update
            || self.allow_delegate_update
        {
            return Err(ValidationError::InvalidGrant);
        }
        self.required_configuration.validate()?;
        validate_path_rules(&self.allowed_path_prefixes)?;
        validate_path_rules(&self.denied_path_prefixes)?;
        if self.allowed_path_prefixes.is_empty()
            || self.maximum_changed_files == 0
            || self.maximum_changed_files > 10_000
            || self.maximum_changed_bytes == 0
            || self.maximum_changed_bytes > HARD_MAX_EXPANDED_BYTES
            || self.maximum_commits == 0
            || self.maximum_commits > 1_000
            || self.expires_at == 0
            || self.expected_signer_did != *self.required_configuration.expected_signer_did()
            || self.executor_audience != *self.required_configuration.executor_audience()
        {
            return Err(ValidationError::InvalidGrant);
        }
        Ok(())
    }

    /// Returns the workflow ID.
    #[must_use]
    pub const fn workflow_id(&self) -> &WorkflowId {
        &self.workflow_id
    }

    /// Returns the RID.
    #[must_use]
    pub const fn rid(&self) -> &Rid {
        &self.rid
    }

    /// Returns the issue ID.
    #[must_use]
    pub const fn issue_id(&self) -> &CobId {
        &self.issue_id
    }

    /// Returns the identity revision.
    #[must_use]
    pub const fn repository_identity_revision(&self) -> &GitOid {
        &self.repository_identity_revision
    }

    /// Returns the canonical base.
    #[must_use]
    pub const fn canonical_base_oid(&self) -> &GitOid {
        &self.canonical_base_oid
    }

    /// Returns allowed path prefixes.
    #[must_use]
    pub fn allowed_path_prefixes(&self) -> &[String] {
        &self.allowed_path_prefixes
    }

    /// Returns denied path prefixes.
    #[must_use]
    pub fn denied_path_prefixes(&self) -> &[String] {
        &self.denied_path_prefixes
    }

    /// Returns the file budget.
    #[must_use]
    pub const fn maximum_changed_files(&self) -> u32 {
        self.maximum_changed_files
    }

    /// Returns the byte budget.
    #[must_use]
    pub const fn maximum_changed_bytes(&self) -> u64 {
        self.maximum_changed_bytes
    }

    /// Returns the commit budget.
    #[must_use]
    pub const fn maximum_commits(&self) -> u32 {
        self.maximum_commits
    }

    /// Returns the required signer.
    #[must_use]
    pub const fn expected_signer_did(&self) -> &RadicleDid {
        &self.expected_signer_did
    }

    /// Returns the executor audience.
    #[must_use]
    pub const fn executor_audience(&self) -> &ExecutorAudience {
        &self.executor_audience
    }

    /// Returns expiry.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Returns required verifier configuration.
    #[must_use]
    pub const fn required_configuration(&self) -> &VerifierConfiguration {
        &self.required_configuration
    }
}

/// One exact patch-open action generated after trusted inspection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenPatchActionV1 {
    profile: String,
    workflow_id: WorkflowId,
    workflow_grant_digest: DigestHex,
    rid: Rid,
    issue_id: CobId,
    repository_identity_revision: GitOid,
    canonical_base_oid: GitOid,
    candidate_oid: GitOid,
    candidate_bundle_digest: DigestHex,
    candidate_commit_set_digest: DigestHex,
    candidate_tree_delta_digest: DigestHex,
    patch_title_digest: DigestHex,
    patch_body_digest: DigestHex,
    issue_reference_digest: DigestHex,
    draft: bool,
    signer_did: RadicleDid,
    executor_audience: ExecutorAudience,
    required_configuration_digest: DigestHex,
    evidence_snapshot_digest: DigestHex,
    publication_budget_ordinal: u8,
    canonical_transition_requested: bool,
}

/// Construction input for an exact patch action.
pub struct OpenPatchActionInput {
    /// Workflow.
    pub workflow_id: WorkflowId,
    /// Canonical grant commitment.
    pub workflow_grant_digest: DigestHex,
    /// Repository.
    pub rid: Rid,
    /// Issue.
    pub issue_id: CobId,
    /// Identity revision.
    pub repository_identity_revision: GitOid,
    /// Base.
    pub canonical_base_oid: GitOid,
    /// Candidate.
    pub candidate_oid: GitOid,
    /// Candidate bundle digest.
    pub candidate_bundle_digest: DigestHex,
    /// Commit-set digest.
    pub candidate_commit_set_digest: DigestHex,
    /// Tree-delta digest.
    pub candidate_tree_delta_digest: DigestHex,
    /// Patch title digest.
    pub patch_title_digest: DigestHex,
    /// Patch body digest.
    pub patch_body_digest: DigestHex,
    /// Deterministic issue-reference digest.
    pub issue_reference_digest: DigestHex,
    /// Required signer.
    pub signer_did: RadicleDid,
    /// Executor.
    pub executor_audience: ExecutorAudience,
    /// Required configuration.
    pub required_configuration_digest: DigestHex,
    /// Evidence commitment.
    pub evidence_snapshot_digest: DigestHex,
}

impl OpenPatchActionV1 {
    /// Constructs one non-draft, non-canonical patch action.
    #[must_use]
    pub fn new(input: OpenPatchActionInput) -> Self {
        Self {
            profile: format!("{PROFILE_ID}/{PROFILE_VERSION}"),
            workflow_id: input.workflow_id,
            workflow_grant_digest: input.workflow_grant_digest,
            rid: input.rid,
            issue_id: input.issue_id,
            repository_identity_revision: input.repository_identity_revision,
            canonical_base_oid: input.canonical_base_oid,
            candidate_oid: input.candidate_oid,
            candidate_bundle_digest: input.candidate_bundle_digest,
            candidate_commit_set_digest: input.candidate_commit_set_digest,
            candidate_tree_delta_digest: input.candidate_tree_delta_digest,
            patch_title_digest: input.patch_title_digest,
            patch_body_digest: input.patch_body_digest,
            issue_reference_digest: input.issue_reference_digest,
            draft: false,
            signer_did: input.signer_did,
            executor_audience: input.executor_audience,
            required_configuration_digest: input.required_configuration_digest,
            evidence_snapshot_digest: input.evidence_snapshot_digest,
            publication_budget_ordinal: 1,
            canonical_transition_requested: false,
        }
    }

    /// Parses a canonical action.
    ///
    /// # Errors
    ///
    /// Returns a validation failure for malformed, oversized, non-canonical,
    /// or unsupported input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        if bytes.is_empty() || bytes.len() > MAX_ACTION_BYTES {
            return Err(ValidationError::LimitExceeded);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| ValidationError::Malformed)?;
        value.validate()?;
        if value
            .canonical_bytes()
            .map_err(|_| ValidationError::Canonicalization)?
            != bytes
        {
            return Err(ValidationError::NonCanonical);
        }
        Ok(value)
    }

    /// Validates action invariants.
    ///
    /// # Errors
    ///
    /// Returns an unsupported-action failure.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.profile != format!("{PROFILE_ID}/{PROFILE_VERSION}")
            || self.draft
            || self.publication_budget_ordinal != 1
            || self.canonical_transition_requested
        {
            return Err(ValidationError::InvalidAction);
        }
        Ok(())
    }

    /// Returns canonical exact-action bytes.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_json(self)
    }

    /// Returns the canonical action digest.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }

    /// Returns the workflow.
    #[must_use]
    pub const fn workflow_id(&self) -> &WorkflowId {
        &self.workflow_id
    }

    /// Returns the workflow grant digest.
    #[must_use]
    pub const fn workflow_grant_digest(&self) -> &DigestHex {
        &self.workflow_grant_digest
    }

    /// Returns the RID.
    #[must_use]
    pub const fn rid(&self) -> &Rid {
        &self.rid
    }

    /// Returns the issue.
    #[must_use]
    pub const fn issue_id(&self) -> &CobId {
        &self.issue_id
    }

    /// Returns the identity revision.
    #[must_use]
    pub const fn repository_identity_revision(&self) -> &GitOid {
        &self.repository_identity_revision
    }

    /// Returns the canonical base.
    #[must_use]
    pub const fn canonical_base_oid(&self) -> &GitOid {
        &self.canonical_base_oid
    }

    /// Returns the candidate.
    #[must_use]
    pub const fn candidate_oid(&self) -> &GitOid {
        &self.candidate_oid
    }

    /// Returns the candidate bundle digest.
    #[must_use]
    pub const fn candidate_bundle_digest(&self) -> &DigestHex {
        &self.candidate_bundle_digest
    }

    /// Returns the commit-set digest.
    #[must_use]
    pub const fn candidate_commit_set_digest(&self) -> &DigestHex {
        &self.candidate_commit_set_digest
    }

    /// Returns the tree-delta digest.
    #[must_use]
    pub const fn candidate_tree_delta_digest(&self) -> &DigestHex {
        &self.candidate_tree_delta_digest
    }

    /// Returns the title digest.
    #[must_use]
    pub const fn patch_title_digest(&self) -> &DigestHex {
        &self.patch_title_digest
    }

    /// Returns the body digest.
    #[must_use]
    pub const fn patch_body_digest(&self) -> &DigestHex {
        &self.patch_body_digest
    }

    /// Returns the issue-reference digest.
    #[must_use]
    pub const fn issue_reference_digest(&self) -> &DigestHex {
        &self.issue_reference_digest
    }

    /// Returns the signer.
    #[must_use]
    pub const fn signer_did(&self) -> &RadicleDid {
        &self.signer_did
    }

    /// Returns the audience.
    #[must_use]
    pub const fn executor_audience(&self) -> &ExecutorAudience {
        &self.executor_audience
    }

    /// Returns the required configuration digest.
    #[must_use]
    pub const fn required_configuration_digest(&self) -> &DigestHex {
        &self.required_configuration_digest
    }

    /// Returns the evidence digest.
    #[must_use]
    pub const fn evidence_snapshot_digest(&self) -> &DigestHex {
        &self.evidence_snapshot_digest
    }

    /// Returns the exact publication ordinal.
    #[must_use]
    pub const fn publication_budget_ordinal(&self) -> u8 {
        self.publication_budget_ordinal
    }
}

/// Validated local Radicle evidence snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadicleEvidenceV1 {
    rid: Rid,
    repository_identity_revision: GitOid,
    delegates: Vec<RadicleDid>,
    delegate_threshold: u16,
    default_branch: String,
    canonical_head_oid: GitOid,
    canonical_derivation_digest: DigestHex,
    issue_id: CobId,
    issue_tip_ids: Vec<GitOid>,
    issue_materialized_digest: DigestHex,
    issue_open: bool,
    issue_history_complete: bool,
    executor_signer_did: RadicleDid,
    executor_node_id: NodeId,
    synchronized_peers: Vec<NodeId>,
    synchronized_at: u64,
    adapter_version: String,
}

/// Construction input for evidence.
pub struct RadicleEvidenceInput {
    /// Repository.
    pub rid: Rid,
    /// Identity revision.
    pub repository_identity_revision: GitOid,
    /// Delegates.
    pub delegates: Vec<RadicleDid>,
    /// Delegate threshold.
    pub delegate_threshold: u16,
    /// Default branch.
    pub default_branch: String,
    /// Canonical head.
    pub canonical_head_oid: GitOid,
    /// Canonical derivation.
    pub canonical_derivation_digest: DigestHex,
    /// Issue.
    pub issue_id: CobId,
    /// Issue tips.
    pub issue_tip_ids: Vec<GitOid>,
    /// Materialized issue.
    pub issue_materialized_digest: DigestHex,
    /// Whether issue is open.
    pub issue_open: bool,
    /// Whether history is complete.
    pub issue_history_complete: bool,
    /// Executor signer.
    pub executor_signer_did: RadicleDid,
    /// Executor node.
    pub executor_node_id: NodeId,
    /// Successful peers.
    pub synchronized_peers: Vec<NodeId>,
    /// Observation time.
    pub synchronized_at: u64,
    /// Adapter version.
    pub adapter_version: String,
}

impl RadicleEvidenceV1 {
    /// Constructs a canonical evidence snapshot.
    ///
    /// # Errors
    ///
    /// Returns a validation failure for duplicate or inconsistent fields.
    pub fn new(mut input: RadicleEvidenceInput) -> Result<Self, ValidationError> {
        input.delegates.sort();
        input.issue_tip_ids.sort();
        input.synchronized_peers.sort();
        if input.delegates.is_empty()
            || input.delegate_threshold == 0
            || usize::from(input.delegate_threshold) > input.delegates.len()
            || input.issue_tip_ids.is_empty()
            || input
                .delegates
                .windows(2)
                .any(|window| window[0] == window[1])
            || input
                .issue_tip_ids
                .windows(2)
                .any(|window| window[0] == window[1])
            || input
                .synchronized_peers
                .windows(2)
                .any(|window| window[0] == window[1])
            || input.synchronized_at == 0
            || !valid_ref_component(&input.default_branch)
            || !valid_component_version(&input.adapter_version)
        {
            return Err(ValidationError::InvalidEvidence);
        }
        Ok(Self {
            rid: input.rid,
            repository_identity_revision: input.repository_identity_revision,
            delegates: input.delegates,
            delegate_threshold: input.delegate_threshold,
            default_branch: input.default_branch,
            canonical_head_oid: input.canonical_head_oid,
            canonical_derivation_digest: input.canonical_derivation_digest,
            issue_id: input.issue_id,
            issue_tip_ids: input.issue_tip_ids,
            issue_materialized_digest: input.issue_materialized_digest,
            issue_open: input.issue_open,
            issue_history_complete: input.issue_history_complete,
            executor_signer_did: input.executor_signer_did,
            executor_node_id: input.executor_node_id,
            synchronized_peers: input.synchronized_peers,
            synchronized_at: input.synchronized_at,
            adapter_version: input.adapter_version,
        })
    }

    /// Returns the canonical evidence digest.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }

    /// Returns the RID.
    #[must_use]
    pub const fn rid(&self) -> &Rid {
        &self.rid
    }

    /// Returns identity revision.
    #[must_use]
    pub const fn repository_identity_revision(&self) -> &GitOid {
        &self.repository_identity_revision
    }

    /// Returns delegates.
    #[must_use]
    pub fn delegates(&self) -> &[RadicleDid] {
        &self.delegates
    }

    /// Returns the identity-declared canonical branch.
    #[must_use]
    pub fn default_branch(&self) -> &str {
        &self.default_branch
    }

    /// Returns canonical head.
    #[must_use]
    pub const fn canonical_head_oid(&self) -> &GitOid {
        &self.canonical_head_oid
    }

    /// Returns issue.
    #[must_use]
    pub const fn issue_id(&self) -> &CobId {
        &self.issue_id
    }

    /// Reports whether the issue is open.
    #[must_use]
    pub const fn issue_open(&self) -> bool {
        self.issue_open
    }

    /// Reports evidence completeness.
    #[must_use]
    pub const fn issue_history_complete(&self) -> bool {
        self.issue_history_complete
    }

    /// Returns signer.
    #[must_use]
    pub const fn executor_signer_did(&self) -> &RadicleDid {
        &self.executor_signer_did
    }

    /// Returns successful peers.
    #[must_use]
    pub fn synchronized_peers(&self) -> &[NodeId] {
        &self.synchronized_peers
    }

    /// Returns observation time.
    #[must_use]
    pub const fn synchronized_at(&self) -> u64 {
        self.synchronized_at
    }

    /// Returns the executor node ID.
    #[must_use]
    pub const fn executor_node_id(&self) -> &NodeId {
        &self.executor_node_id
    }

    /// Returns the canonical-reference derivation commitment.
    #[must_use]
    pub const fn canonical_derivation_digest(&self) -> &DigestHex {
        &self.canonical_derivation_digest
    }

    /// Returns the evidence adapter version.
    #[must_use]
    pub fn adapter_version(&self) -> &str {
        &self.adapter_version
    }
}

fn valid_ref_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
        && !value.contains("..")
        && !value.starts_with('/')
        && !value.ends_with('/')
}

fn validate_path_rules(paths: &[String]) -> Result<(), ValidationError> {
    if paths.len() > 128 || paths.windows(2).any(|window| window[0] >= window[1]) {
        return Err(ValidationError::InvalidPath);
    }
    for path in paths {
        validate_repo_path(path, true)?;
    }
    Ok(())
}

/// Validates a canonical repository-relative path or prefix.
///
/// # Errors
///
/// Returns a closed path failure.
pub fn validate_repo_path(path: &str, allow_trailing_slash: bool) -> Result<(), ValidationError> {
    if path.is_empty()
        || path.len() > usize::from(HARD_MAX_PATH_BYTES)
        || path.starts_with('/')
        || path.contains('\\')
        || path
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
        || (!allow_trailing_slash && path.ends_with('/'))
    {
        return Err(ValidationError::InvalidPath);
    }
    let trimmed = path.strip_suffix('/').unwrap_or(path);
    if trimmed.is_empty()
        || trimmed
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err(ValidationError::InvalidPath);
    }
    Ok(())
}

/// Closed profile-value validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ValidationError {
    /// Input exceeds a hard limit.
    #[error("profile input exceeds a hard limit")]
    LimitExceeded,
    /// Input is malformed.
    #[error("malformed profile input")]
    Malformed,
    /// Input is not canonical.
    #[error("non-canonical profile input")]
    NonCanonical,
    /// Canonicalization failed.
    #[error("profile canonicalization failed")]
    Canonicalization,
    /// Verifier configuration is inconsistent.
    #[error("invalid verifier configuration")]
    InvalidConfiguration,
    /// Workflow grant is inconsistent.
    #[error("invalid workflow grant")]
    InvalidGrant,
    /// Exact action is inconsistent.
    #[error("invalid exact patch action")]
    InvalidAction,
    /// Candidate facts are inconsistent.
    #[error("invalid candidate facts")]
    InvalidCandidate,
    /// Evidence is inconsistent.
    #[error("invalid Radicle evidence")]
    InvalidEvidence,
    /// Repository-relative path is invalid.
    #[error("invalid repository-relative path")]
    InvalidPath,
    /// File mode is excluded by the MVP.
    #[error("forbidden file mode")]
    ForbiddenFileMode,
}
