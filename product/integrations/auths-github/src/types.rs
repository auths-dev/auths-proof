//! Closed, validated vocabulary for one GitHub issue-address workflow.

#![allow(
    clippy::missing_errors_doc,
    reason = "schema validators return the closed ValidationError described in this module"
)]

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    policy::{PatternError, validate_pattern},
};

/// Exact GitHub profile identifier.
pub const PROFILE_ID: &str = "auths.github.issue-address";
/// Exact GitHub profile version.
pub const PROFILE_VERSION: u16 = 1;
/// Exact branch publication capability.
pub const BRANCH_CAPABILITY: &str = "github.branch.publish";
/// Exact draft pull-request capability.
pub const PULL_REQUEST_CAPABILITY: &str = "github.pull-request.open-draft";
/// Exact canonical media type.
pub const MEDIA_TYPE: &str = "application/vnd.auths.github.issue-workflow.v1+json";
/// Hard maximum canonical action bytes.
pub const MAX_ACTION_BYTES: usize = 256 * 1024;
/// Hard maximum canonical grant bytes.
pub const MAX_GRANT_BYTES: usize = 256 * 1024;
/// Hard ceiling over all accepted candidate bundles.
pub const HARD_MAX_CANDIDATE_BYTES: u64 = 16 * 1024 * 1024;
/// Hard ceiling over all Git objects inspected for one candidate.
pub const HARD_MAX_GIT_OBJECTS: u32 = 20_000;
/// Hard ceiling over commits introduced by one candidate.
pub const HARD_MAX_COMMITS: u16 = 64;
/// Maximum UTF-8 bytes in one Git tree path.
pub const HARD_MAX_PATH_BYTES: usize = 1024;

macro_rules! validated_string {
    ($name:ident, $error:ident, $validator:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Parses and validates one identifier.
            ///
            /// # Errors
            ///
            /// Returns a typed validation failure for malformed input.
            pub fn parse(value: impl Into<String>) -> Result<Self, TypeError> {
                let value = value.into();
                if !$validator(&value) {
                    return Err(TypeError::$error);
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

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_workflow_id(value: &str) -> bool {
    (12..=96).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_node_id(value: &str) -> bool {
    (8..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_owner_or_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_ref(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.ends_with('.')
        && !value.contains("..")
        && !value.contains("@{")
        && !value.contains("//")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
}

fn valid_audience(value: &str) -> bool {
    value.len() <= 256 && auths_model::Audience::parse(value).is_ok()
}

validated_string!(DigestHex, Digest, valid_digest);
validated_string!(GitOid, GitOid, valid_oid);
validated_string!(WorkflowId, WorkflowId, valid_workflow_id);
validated_string!(NodeId, NodeId, valid_node_id);
validated_string!(RepositoryOwner, RepositoryOwner, valid_owner_or_name);
validated_string!(RepositoryName, RepositoryName, valid_owner_or_name);
validated_string!(RefName, RefName, valid_ref);
validated_string!(ExecutorAudience, ExecutorAudience, valid_audience);

impl DigestHex {
    /// Constructs a lowercase digest from exact SHA-256 bytes.
    #[must_use]
    pub fn from_digest_bytes(bytes: [u8; 32]) -> Self {
        Self(hex::encode(bytes))
    }
}

/// Closed identifier validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TypeError {
    /// Invalid digest.
    #[error("invalid lowercase SHA-256 digest")]
    Digest,
    /// Invalid Git SHA-1/SHA-256 object identifier.
    #[error("invalid lowercase Git object identifier")]
    GitOid,
    /// Invalid workflow identifier.
    #[error("invalid workflow identifier")]
    WorkflowId,
    /// Invalid GitHub GraphQL node identifier.
    #[error("invalid GitHub node identifier")]
    NodeId,
    /// Invalid repository owner.
    #[error("invalid GitHub repository owner")]
    RepositoryOwner,
    /// Invalid repository name.
    #[error("invalid GitHub repository name")]
    RepositoryName,
    /// Invalid Git reference name.
    #[error("invalid Git reference name")]
    RefName,
    /// Invalid Auths executor audience.
    #[error("invalid executor audience")]
    ExecutorAudience,
}

/// Immutable GitHub repository identity plus human-readable cross-checks.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryResource {
    host: String,
    repository_id: u64,
    repository_node_id: NodeId,
    owner: RepositoryOwner,
    name: RepositoryName,
}

impl RepositoryResource {
    /// Constructs a GitHub.com repository resource.
    ///
    /// # Errors
    ///
    /// Rejects zero identifiers and non-GitHub hosts.
    pub fn new(
        repository_id: u64,
        repository_node_id: NodeId,
        owner: RepositoryOwner,
        name: RepositoryName,
    ) -> Result<Self, ValidationError> {
        if repository_id == 0 {
            return Err(ValidationError::InvalidGrant);
        }
        Ok(Self {
            host: "github.com".into(),
            repository_id,
            repository_node_id,
            owner,
            name,
        })
    }

    /// Immutable numeric repository identifier.
    #[must_use]
    pub const fn repository_id(&self) -> u64 {
        self.repository_id
    }

    /// Immutable GraphQL node identifier.
    #[must_use]
    pub const fn repository_node_id(&self) -> &NodeId {
        &self.repository_node_id
    }

    /// Repository owner cross-check.
    #[must_use]
    pub const fn owner(&self) -> &RepositoryOwner {
        &self.owner
    }

    /// Repository name cross-check.
    #[must_use]
    pub const fn name(&self) -> &RepositoryName {
        &self.name
    }

    /// `owner/name` display and API coordinate.
    #[must_use]
    pub fn slug(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }

    /// Validates a deserialized resource.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.host != "github.com" || self.repository_id == 0 {
            return Err(ValidationError::InvalidGrant);
        }
        Ok(())
    }
}

/// Immutable GitHub issue identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueResource {
    repository_id: u64,
    issue_node_id: NodeId,
    issue_number: u64,
}

impl IssueResource {
    /// Constructs an issue bound to one immutable repository.
    ///
    /// # Errors
    ///
    /// Rejects zero identifiers.
    pub fn new(
        repository_id: u64,
        issue_node_id: NodeId,
        issue_number: u64,
    ) -> Result<Self, ValidationError> {
        if repository_id == 0 || issue_number == 0 {
            return Err(ValidationError::InvalidGrant);
        }
        Ok(Self {
            repository_id,
            issue_node_id,
            issue_number,
        })
    }

    /// Repository identifier.
    #[must_use]
    pub const fn repository_id(&self) -> u64 {
        self.repository_id
    }

    /// Issue GraphQL node identifier.
    #[must_use]
    pub const fn issue_node_id(&self) -> &NodeId {
        &self.issue_node_id
    }

    /// Repository-local issue number.
    #[must_use]
    pub const fn issue_number(&self) -> u64 {
        self.issue_number
    }

    /// Validates a deserialized issue.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.repository_id == 0 || self.issue_number == 0 {
            return Err(ValidationError::InvalidGrant);
        }
        Ok(())
    }
}

/// Git object format bound by the workflow.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObjectFormat {
    /// Git SHA-1.
    Sha1,
    /// Git SHA-256.
    Sha256,
}

impl ObjectFormat {
    /// Validates that an object identifier matches this format.
    #[must_use]
    pub fn matches(self, oid: &GitOid) -> bool {
        match self {
            Self::Sha1 => oid.as_str().len() == 40,
            Self::Sha256 => oid.as_str().len() == 64,
        }
    }
}

/// Exact candidate containment policy.
#[allow(
    clippy::struct_excessive_bools,
    reason = "the normative V1 schema binds every independent fail-closed Git policy switch"
)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidatePolicy {
    /// Root-anchored allow patterns.
    pub allowed_paths: Vec<String>,
    /// Root-anchored deny patterns.
    pub denied_paths: Vec<String>,
    /// Maximum changed paths.
    pub maximum_changed_files: u32,
    /// Maximum added bytes.
    pub maximum_added_bytes: u64,
    /// Maximum deleted bytes.
    pub maximum_deleted_bytes: u64,
    /// Maximum bundle bytes.
    pub maximum_candidate_bytes: u64,
    /// Maximum Git objects.
    pub maximum_git_objects: u32,
    /// Maximum introduced commits.
    pub maximum_commits: u16,
    /// Whether executable modes may appear or change.
    pub allow_executable_bit_changes: bool,
    /// Whether symlinks may appear.
    pub allow_symlinks: bool,
    /// Whether gitlinks/submodules may appear.
    pub allow_submodules: bool,
    /// Whether merge commits may appear.
    pub allow_merge_commits: bool,
    /// Whether non-UTF-8 tree paths may appear.
    pub allow_non_utf8_paths: bool,
    /// Whether `.gitattributes` may change.
    pub allow_git_attributes_changes: bool,
    /// Whether `.gitmodules` may change.
    pub allow_gitmodules_changes: bool,
    /// Whether repository automation files may change.
    pub allow_repository_automation_changes: bool,
}

impl CandidatePolicy {
    /// Validates patterns, hard limits, and fail-closed MVP switches.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.allowed_paths.is_empty()
            || self.allowed_paths.len() > 128
            || self.denied_paths.len() > 128
            || self.maximum_changed_files == 0
            || self.maximum_added_bytes == 0
            || self.maximum_deleted_bytes == 0
            || self.maximum_candidate_bytes == 0
            || self.maximum_candidate_bytes > HARD_MAX_CANDIDATE_BYTES
            || self.maximum_git_objects == 0
            || self.maximum_git_objects > HARD_MAX_GIT_OBJECTS
            || self.maximum_commits == 0
            || self.maximum_commits > HARD_MAX_COMMITS
            || self.allow_non_utf8_paths
        {
            return Err(ValidationError::InvalidGrant);
        }
        self.allowed_paths
            .iter()
            .chain(&self.denied_paths)
            .try_for_each(|pattern| validate_pattern(pattern).map_err(ValidationError::from))
    }
}

/// Exact one-branch/one-draft-PR publication policy.
#[allow(
    clippy::struct_excessive_bools,
    reason = "the normative V1 schema records independent publication prohibitions explicitly"
)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationPolicy {
    /// Branch budget, exactly one in V1.
    pub maximum_branches: u8,
    /// Pull-request budget, exactly one in V1.
    pub maximum_pull_requests: u8,
    /// Pull requests must remain draft.
    pub must_be_draft: bool,
    /// Existing branches cannot be updated.
    pub allow_branch_updates: bool,
    /// Force/history rewrite is forbidden.
    pub allow_history_rewrite: bool,
    /// Merge is outside this workflow.
    pub allow_merge: bool,
}

impl PublicationPolicy {
    /// Returns the only V1 policy.
    #[must_use]
    pub const fn one_draft_pull_request() -> Self {
        Self {
            maximum_branches: 1,
            maximum_pull_requests: 1,
            must_be_draft: true,
            allow_branch_updates: false,
            allow_history_rewrite: false,
            allow_merge: false,
        }
    }

    /// Validates the closed V1 policy.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self != &Self::one_draft_pull_request() {
            return Err(ValidationError::InvalidGrant);
        }
        Ok(())
    }
}

/// Verifier configuration both demanded and actually loaded.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierConfiguration {
    profile: String,
    candidate_inspector: String,
    github_adapter: String,
    canonical_reference: String,
    repository_automation_policy_digest: DigestHex,
    maximum_evidence_age_seconds: u64,
    executor_audience: ExecutorAudience,
    receipt_schema: String,
}

/// Constructor fields for [`VerifierConfiguration`].
pub struct VerifierConfigurationInput {
    /// Version-pinned candidate inspector.
    pub candidate_inspector: String,
    /// Version-pinned GitHub adapter.
    pub github_adapter: String,
    /// Version-pinned canonicalization implementation.
    pub canonical_reference: String,
    /// Approved repository automation policy commitment.
    pub repository_automation_policy_digest: DigestHex,
    /// Maximum trustworthy evidence age.
    pub maximum_evidence_age_seconds: u64,
    /// Bound executor audience.
    pub executor_audience: ExecutorAudience,
    /// Versioned receipt schema.
    pub receipt_schema: String,
}

impl VerifierConfiguration {
    /// Constructs a closed verifier configuration.
    ///
    /// # Errors
    ///
    /// Rejects missing versions, unsafe evidence ages, or malformed fields.
    pub fn new(input: VerifierConfigurationInput) -> Result<Self, ValidationError> {
        let configuration = Self {
            profile: format!("{PROFILE_ID}/{PROFILE_VERSION}"),
            candidate_inspector: input.candidate_inspector,
            github_adapter: input.github_adapter,
            canonical_reference: input.canonical_reference,
            repository_automation_policy_digest: input.repository_automation_policy_digest,
            maximum_evidence_age_seconds: input.maximum_evidence_age_seconds,
            executor_audience: input.executor_audience,
            receipt_schema: input.receipt_schema,
        };
        configuration.validate()?;
        Ok(configuration)
    }

    /// Validates a deserialized configuration.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.profile != format!("{PROFILE_ID}/{PROFILE_VERSION}")
            || !(1..=30).contains(&self.maximum_evidence_age_seconds)
            || !valid_version(&self.candidate_inspector)
            || !valid_version(&self.github_adapter)
            || !valid_version(&self.canonical_reference)
            || !valid_version(&self.receipt_schema)
        {
            return Err(ValidationError::InvalidConfiguration);
        }
        Ok(())
    }

    /// Canonical configuration commitment.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }

    /// Maximum evidence age.
    #[must_use]
    pub const fn maximum_evidence_age_seconds(&self) -> u64 {
        self.maximum_evidence_age_seconds
    }

    /// Approved repository-automation policy commitment.
    #[must_use]
    pub const fn repository_automation_policy_digest(&self) -> &DigestHex {
        &self.repository_automation_policy_digest
    }

    /// Bound executor audience.
    #[must_use]
    pub const fn executor_audience(&self) -> &ExecutorAudience {
        &self.executor_audience
    }

    /// Receipt schema.
    #[must_use]
    pub fn receipt_schema(&self) -> &str {
        &self.receipt_schema
    }
}

fn valid_version(value: &str) -> bool {
    (3..=96).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Canonical human-issued issue-address workflow grant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowGrant {
    profile_id: String,
    profile_version: u16,
    workflow_id: WorkflowId,
    repository: RepositoryResource,
    issue: IssueResource,
    base_ref: RefName,
    base_revision: GitOid,
    object_format: ObjectFormat,
    candidate_policy: CandidatePolicy,
    publication_policy: PublicationPolicy,
    executor_audience: ExecutorAudience,
    issued_at: u64,
    expires_at: u64,
    remaining_delegation_depth: u8,
    required_configuration: VerifierConfiguration,
}

/// Constructor fields for [`WorkflowGrant`].
pub struct WorkflowGrantInput {
    /// Workflow identifier.
    pub workflow_id: WorkflowId,
    /// Immutable repository resource.
    pub repository: RepositoryResource,
    /// Immutable issue resource.
    pub issue: IssueResource,
    /// Exact base ref.
    pub base_ref: RefName,
    /// Exact base revision.
    pub base_revision: GitOid,
    /// Repository object format.
    pub object_format: ObjectFormat,
    /// Candidate policy.
    pub candidate_policy: CandidatePolicy,
    /// Publication policy.
    pub publication_policy: PublicationPolicy,
    /// Executor audience.
    pub executor_audience: ExecutorAudience,
    /// Trusted issuance time.
    pub issued_at: u64,
    /// Bounded expiry.
    pub expires_at: u64,
    /// Required configuration.
    pub required_configuration: VerifierConfiguration,
}

impl WorkflowGrant {
    /// Constructs and validates one workflow grant.
    ///
    /// # Errors
    ///
    /// Rejects widened publication, inconsistent identity, format, audience,
    /// delegation, or validity.
    pub fn new(input: WorkflowGrantInput) -> Result<Self, ValidationError> {
        let grant = Self {
            profile_id: PROFILE_ID.into(),
            profile_version: PROFILE_VERSION,
            workflow_id: input.workflow_id,
            repository: input.repository,
            issue: input.issue,
            base_ref: input.base_ref,
            base_revision: input.base_revision,
            object_format: input.object_format,
            candidate_policy: input.candidate_policy,
            publication_policy: input.publication_policy,
            executor_audience: input.executor_audience,
            issued_at: input.issued_at,
            expires_at: input.expires_at,
            remaining_delegation_depth: 1,
            required_configuration: input.required_configuration,
        };
        grant.validate()?;
        Ok(grant)
    }

    /// Validates a deserialized grant.
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.repository.validate()?;
        self.issue.validate()?;
        self.candidate_policy.validate()?;
        self.publication_policy.validate()?;
        self.required_configuration.validate()?;
        if self.profile_id != PROFILE_ID
            || self.profile_version != PROFILE_VERSION
            || self.repository.repository_id != self.issue.repository_id
            || !self.object_format.matches(&self.base_revision)
            || self.executor_audience != *self.required_configuration.executor_audience()
            || self.issued_at >= self.expires_at
            || self.expires_at - self.issued_at > 15 * 60
            || self.remaining_delegation_depth != 1
        {
            return Err(ValidationError::InvalidGrant);
        }
        Ok(())
    }

    /// Canonical grant commitment.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }

    /// Canonical grant bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_json(self)
    }

    /// Workflow identifier.
    #[must_use]
    pub const fn workflow_id(&self) -> &WorkflowId {
        &self.workflow_id
    }

    /// Repository resource.
    #[must_use]
    pub const fn repository(&self) -> &RepositoryResource {
        &self.repository
    }

    /// Issue resource.
    #[must_use]
    pub const fn issue(&self) -> &IssueResource {
        &self.issue
    }

    /// Exact base ref.
    #[must_use]
    pub const fn base_ref(&self) -> &RefName {
        &self.base_ref
    }

    /// Exact base revision.
    #[must_use]
    pub const fn base_revision(&self) -> &GitOid {
        &self.base_revision
    }

    /// Repository object format.
    #[must_use]
    pub const fn object_format(&self) -> ObjectFormat {
        self.object_format
    }

    /// Candidate policy.
    #[must_use]
    pub const fn candidate_policy(&self) -> &CandidatePolicy {
        &self.candidate_policy
    }

    /// Executor audience.
    #[must_use]
    pub const fn executor_audience(&self) -> &ExecutorAudience {
        &self.executor_audience
    }

    /// Grant expiry.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Required verifier configuration.
    #[must_use]
    pub const fn required_configuration(&self) -> &VerifierConfiguration {
        &self.required_configuration
    }

    /// Executor-derived branch name.
    ///
    /// # Errors
    ///
    /// Rejects an unexpectedly short workflow identifier.
    pub fn target_ref(&self) -> Result<RefName, ValidationError> {
        let prefix = self
            .workflow_id
            .as_str()
            .get(..12)
            .ok_or(ValidationError::InvalidGrant)?;
        RefName::parse(format!("auths/issue-{}-{prefix}", self.issue.issue_number))
            .map_err(|_| ValidationError::InvalidGrant)
    }

    /// Deterministic draft pull-request title.
    #[must_use]
    pub fn pull_request_title(&self) -> String {
        format!("Auths proposal for issue #{}", self.issue.issue_number())
    }
}

/// Exact external GitHub action category.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GitHubOperation {
    /// Publish an exact candidate commit to an absent derived ref.
    PublishBranch,
    /// Open one exact draft pull request.
    OpenDraftPullRequest,
}

/// Exact branch-publication action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishBranchAction {
    /// Capability identifier.
    pub capability: String,
    /// Profile identifier.
    pub profile_id: String,
    /// Profile version.
    pub profile_version: u16,
    /// Workflow.
    pub workflow_id: WorkflowId,
    /// Human workflow commitment.
    pub workflow_grant_digest: DigestHex,
    /// Repository.
    pub repository: RepositoryResource,
    /// Issue.
    pub issue: IssueResource,
    /// Exact base ref.
    pub base_ref: RefName,
    /// Exact base revision.
    pub base_revision: GitOid,
    /// Executor-derived target ref.
    pub target_ref: RefName,
    /// Target must be absent.
    pub expected_target_state: String,
    /// Exact candidate revision.
    pub candidate_revision: GitOid,
    /// Exact candidate tree.
    pub candidate_tree: GitOid,
    /// Bundle commitment.
    pub candidate_bundle_digest: DigestHex,
    /// Changed-tree commitment.
    pub change_set_digest: DigestHex,
    /// Fresh evidence commitment.
    pub evidence_digest: DigestHex,
    /// Required verifier configuration commitment.
    pub verifier_configuration_digest: DigestHex,
    /// Exact executor audience.
    pub executor_audience: ExecutorAudience,
    /// Grant expiry.
    pub expires_at: u64,
}

/// Exact draft pull-request action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenDraftPullRequestAction {
    /// Capability identifier.
    pub capability: String,
    /// Profile identifier.
    pub profile_id: String,
    /// Profile version.
    pub profile_version: u16,
    /// Workflow.
    pub workflow_id: WorkflowId,
    /// Human workflow commitment.
    pub workflow_grant_digest: DigestHex,
    /// Repository.
    pub repository: RepositoryResource,
    /// Issue.
    pub issue: IssueResource,
    /// Exact base ref.
    pub base_ref: RefName,
    /// Exact base revision.
    pub base_revision: GitOid,
    /// Exact head ref.
    pub head_ref: RefName,
    /// Exact published head.
    pub head_revision: GitOid,
    /// Must remain draft.
    pub draft: bool,
    /// Deterministic title.
    pub exact_title: String,
    /// Deterministic body commitment.
    pub exact_body_digest: DigestHex,
    /// No matching PR may already exist.
    pub expected_existing_pull_requests: u8,
    /// Branch receipt commitment.
    pub branch_execution_receipt_digest: DigestHex,
    /// Fresh evidence commitment.
    pub evidence_digest: DigestHex,
    /// Required verifier configuration commitment.
    pub verifier_configuration_digest: DigestHex,
    /// Exact executor audience.
    pub executor_audience: ExecutorAudience,
    /// Grant expiry.
    pub expires_at: u64,
}

/// Closed exact action union accepted by the profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "action", rename_all = "kebab-case")]
pub enum ExactGitHubAction {
    /// Exact branch publication.
    PublishBranch(PublishBranchAction),
    /// Exact draft pull-request creation.
    OpenDraftPullRequest(OpenDraftPullRequestAction),
}

impl ExactGitHubAction {
    /// Validates closed action semantics.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let common_valid = match self {
            Self::PublishBranch(action) => {
                action.capability == BRANCH_CAPABILITY
                    && action.profile_id == PROFILE_ID
                    && action.profile_version == PROFILE_VERSION
                    && action.repository.repository_id() == action.issue.repository_id()
                    && action.expected_target_state == "absent"
                    && action.expires_at > 0
            }
            Self::OpenDraftPullRequest(action) => {
                action.capability == PULL_REQUEST_CAPABILITY
                    && action.profile_id == PROFILE_ID
                    && action.profile_version == PROFILE_VERSION
                    && action.repository.repository_id() == action.issue.repository_id()
                    && action.draft
                    && action.expected_existing_pull_requests == 0
                    && action.exact_title
                        == format!("Auths proposal for issue #{}", action.issue.issue_number())
                    && action.expires_at > 0
            }
        };
        if !common_valid {
            return Err(ValidationError::InvalidAction);
        }
        Ok(())
    }

    /// Canonical exact-action bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_json(self)
    }

    /// Exact action commitment.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }

    /// Operation category.
    #[must_use]
    pub const fn operation(&self) -> GitHubOperation {
        match self {
            Self::PublishBranch(_) => GitHubOperation::PublishBranch,
            Self::OpenDraftPullRequest(_) => GitHubOperation::OpenDraftPullRequest,
        }
    }

    /// Workflow identifier.
    #[must_use]
    pub const fn workflow_id(&self) -> &WorkflowId {
        match self {
            Self::PublishBranch(action) => &action.workflow_id,
            Self::OpenDraftPullRequest(action) => &action.workflow_id,
        }
    }

    /// Repository resource.
    #[must_use]
    pub const fn repository(&self) -> &RepositoryResource {
        match self {
            Self::PublishBranch(action) => &action.repository,
            Self::OpenDraftPullRequest(action) => &action.repository,
        }
    }

    /// Issue resource.
    #[must_use]
    pub const fn issue(&self) -> &IssueResource {
        match self {
            Self::PublishBranch(action) => &action.issue,
            Self::OpenDraftPullRequest(action) => &action.issue,
        }
    }

    /// Exact audience.
    #[must_use]
    pub const fn executor_audience(&self) -> &ExecutorAudience {
        match self {
            Self::PublishBranch(action) => &action.executor_audience,
            Self::OpenDraftPullRequest(action) => &action.executor_audience,
        }
    }
}

/// Closed validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ValidationError {
    /// Invalid workflow grant.
    #[error("invalid GitHub workflow grant")]
    InvalidGrant,
    /// Invalid verifier configuration.
    #[error("invalid GitHub verifier configuration")]
    InvalidConfiguration,
    /// Invalid exact action.
    #[error("invalid exact GitHub action")]
    InvalidAction,
    /// Invalid path grammar.
    #[error("invalid candidate path pattern")]
    InvalidPath,
}

impl From<PatternError> for ValidationError {
    fn from(_: PatternError) -> Self {
        Self::InvalidPath
    }
}
