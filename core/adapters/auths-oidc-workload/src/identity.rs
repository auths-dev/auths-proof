extern crate alloc;

use alloc::{boxed::Box, string::String, vec::Vec};
use auths_model::{BoundedSet, Digest};
use sha2::{Digest as _, Sha256};

use crate::{ConfigurationError, OidcError};

pub const MAX_POLICIES: usize = 64;

macro_rules! text_type {
    ($name:ident, $max:expr, $validate:expr) => {
        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);
        impl $name {
            /// Parses one bounded OIDC identity field.
            ///
            /// # Errors
            ///
            /// Returns [`OidcError`] when the field is empty, exceeds its
            /// bound, or violates its field-specific syntax.
            pub fn parse(value: &str) -> Result<Self, OidcError> {
                if value.is_empty() || value.len() > $max || !($validate)(value) {
                    return Err(OidcError::Claims(crate::ClaimError::InvalidValue));
                }
                Ok(Self(value.into()))
            }
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

fn no_control(value: &str) -> bool {
    !value.bytes().any(|byte| byte.is_ascii_control())
}

fn issuer_url(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or_default();
    !authority.is_empty()
        && !authority.contains('@')
        && !value.contains(['?', '#'])
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
        && authority.bytes().all(|byte| !byte.is_ascii_uppercase())
        && !authority.ends_with(":443")
}

text_type!(IssuerUrl, 512, issuer_url);
text_type!(Subject, 1024, no_control);

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Repository(String);
impl Repository {
    /// Parses one canonical `owner/repository` name.
    ///
    /// # Errors
    ///
    /// Returns [`OidcError`] when the repository is malformed or exceeds its
    /// bound.
    pub fn parse(value: &str) -> Result<Self, OidcError> {
        let mut parts = value.split('/');
        let owner = parts.next().unwrap_or_default();
        let name = parts.next().unwrap_or_default();
        if value.len() > 256
            || owner.is_empty()
            || name.is_empty()
            || parts.next().is_some()
            || !owner.bytes().all(repo_byte)
            || !name.bytes().all(repo_byte)
        {
            return Err(OidcError::Claims(crate::ClaimError::InvalidValue));
        }
        Ok(Self(value.to_ascii_lowercase()))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
    #[must_use]
    pub fn owner(&self) -> &str {
        self.0.split_once('/').map_or("", |pair| pair.0)
    }
}

fn repo_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RepositoryOwner(String);
impl RepositoryOwner {
    /// Parses one canonical repository owner.
    ///
    /// # Errors
    ///
    /// Returns [`OidcError`] when the owner is malformed or exceeds its bound.
    pub fn parse(value: &str) -> Result<Self, OidcError> {
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(OidcError::Claims(crate::ClaimError::InvalidValue));
        }
        Ok(Self(value.to_ascii_lowercase()))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

macro_rules! numeric_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(u64);
        impl $name {
            /// Parses one positive canonical decimal identifier.
            ///
            /// # Errors
            ///
            /// Returns [`OidcError`] when the value is zero, has a leading
            /// zero, is non-decimal, or exceeds `u64`.
            pub fn parse(value: &str) -> Result<Self, OidcError> {
                if value.is_empty()
                    || value.starts_with('0')
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(OidcError::Claims(crate::ClaimError::InvalidValue));
                }
                let value = value
                    .parse::<u64>()
                    .map_err(|_| OidcError::Claims(crate::ClaimError::InvalidValue))?;
                if value == 0 {
                    return Err(OidcError::Claims(crate::ClaimError::InvalidValue));
                }
                Ok(Self(value))
            }
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }
        }
    };
}
numeric_id!(RepositoryId);
numeric_id!(RepositoryOwnerId);

text_type!(WorkflowPath, 256, |value: &str| {
    (value.starts_with(".github/workflows/")
        && value
            .rsplit_once('.')
            .is_some_and(|(_, extension)| matches!(extension, "yml" | "yaml")))
        && !value.split('/').any(|segment| segment == "..")
});
text_type!(GitRef, 256, |value: &str| {
    value.starts_with("refs/")
        && !value.contains("..")
        && !value.contains("//")
        && !value.bytes().any(|b| b.is_ascii_control() || b == b' ')
});
text_type!(Environment, 256, no_control);
text_type!(Actor, 64, |value: &str| {
    let base = value.strip_suffix("[bot]").unwrap_or(value);
    !base.is_empty() && base.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
});
text_type!(EventName, 64, |value: &str| value
    .bytes()
    .all(|b| b.is_ascii_lowercase() || b == b'_'));

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CommitSha(String);
impl CommitSha {
    /// Parses one lowercase SHA-1 commit identifier.
    ///
    /// # Errors
    ///
    /// Returns [`OidcError`] unless the value is exactly 40 lowercase
    /// hexadecimal digits.
    pub fn parse(value: &str) -> Result<Self, OidcError> {
        if value.len() != 40
            || !value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(OidcError::Claims(crate::ClaimError::InvalidValue));
        }
        Ok(Self(value.into()))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RunnerEnvironment {
    GithubHosted,
    SelfHosted,
}
impl RunnerEnvironment {
    /// Parses one supported GitHub Actions runner environment.
    ///
    /// # Errors
    ///
    /// Returns [`OidcError`] for an unknown environment label.
    pub fn parse(value: &str) -> Result<Self, OidcError> {
        match value {
            "github-hosted" => Ok(Self::GithubHosted),
            "self-hosted" => Ok(Self::SelfHosted),
            _ => Err(OidcError::Claims(crate::ClaimError::InvalidValue)),
        }
    }
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GithubHosted => "github-hosted",
            Self::SelfHosted => "self-hosted",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WorkflowRef {
    pub repository: Repository,
    pub path: WorkflowPath,
    pub git_ref: GitRef,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WorkflowIdentity {
    pub reference: WorkflowRef,
    pub commit: CommitSha,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReusableWorkflow {
    Absent,
    Present(WorkflowIdentity),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GenericIdentity {
    pub issuer: IssuerUrl,
    pub subject: Subject,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GithubIdentity {
    pub issuer: IssuerUrl,
    pub subject: Subject,
    pub repository: Repository,
    pub repository_id: RepositoryId,
    pub owner: RepositoryOwner,
    pub owner_id: RepositoryOwnerId,
    pub workflow: WorkflowIdentity,
    pub job_workflow: ReusableWorkflow,
    pub git_ref: GitRef,
    pub sha: CommitSha,
    pub environment: Option<Environment>,
    pub runner: Option<RunnerEnvironment>,
    pub actor: Option<Actor>,
    pub event: Option<EventName>,
}
impl GithubIdentity {
    /// Validates cross-field invariants for a GitHub workload identity.
    ///
    /// # Errors
    ///
    /// Returns [`OidcError`] when owner, repository, or workflow fields are
    /// inconsistent.
    pub fn new(mut value: Self) -> Result<Self, OidcError> {
        if value.owner.as_str() != value.repository.owner()
            || value.workflow.reference.repository != value.repository
        {
            return Err(OidcError::Claims(crate::ClaimError::InconsistentIdentity));
        }
        if let ReusableWorkflow::Present(job) = &value.job_workflow
            && job.reference.repository.as_str().is_empty()
        {
            return Err(OidcError::Claims(crate::ClaimError::InconsistentIdentity));
        }
        value.repository.0.make_ascii_lowercase();
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WorkloadIdentity {
    Generic(GenericIdentity),
    GithubActions(Box<GithubIdentity>),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WorkflowPin {
    Exact {
        path: WorkflowPath,
        git_ref: GitRef,
        commit: CommitSha,
    },
    AnyRef {
        path: WorkflowPath,
    },
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GenericPolicy {
    pub subject: Subject,
}
impl GenericPolicy {
    #[must_use]
    pub fn admits(&self, identity: &GenericIdentity) -> bool {
        self.subject == identity.subject
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GithubPolicy {
    pub repository_id: RepositoryId,
    pub owner_id: RepositoryOwnerId,
    pub workflow: Option<WorkflowPin>,
    pub git_ref: Option<GitRef>,
    pub environment: Option<Environment>,
}
impl GithubPolicy {
    #[must_use]
    pub fn admits(&self, identity: &GithubIdentity) -> bool {
        self.repository_id == identity.repository_id
            && self.owner_id == identity.owner_id
            && self.workflow.as_ref().is_none_or(|pin| match pin {
                WorkflowPin::Exact {
                    path,
                    git_ref,
                    commit,
                } => {
                    identity.workflow.reference.path == *path
                        && identity.workflow.reference.git_ref == *git_ref
                        && identity.workflow.commit == *commit
                }
                WorkflowPin::AnyRef { path } => identity.workflow.reference.path == *path,
            })
            && self
                .git_ref
                .as_ref()
                .is_none_or(|value| identity.git_ref == *value)
            && self
                .environment
                .as_ref()
                .is_none_or(|value| identity.environment.as_ref() == Some(value))
    }
}

pub type GenericPolicySet = BoundedSet<GenericPolicy, MAX_POLICIES>;
pub type GithubPolicySet = BoundedSet<GithubPolicy, MAX_POLICIES>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IssuerProfile {
    Generic { policies: GenericPolicySet },
    GithubActions { policies: GithubPolicySet },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyRejection {
    ProfileMismatch,
    NoPolicyAdmits,
}

#[derive(Clone, Debug)]
pub struct AdmittedWorkload {
    identity: WorkloadIdentity,
    policy_digest: Digest,
}
impl AdmittedWorkload {
    #[must_use]
    pub const fn identity(&self) -> &WorkloadIdentity {
        &self.identity
    }
    #[must_use]
    pub const fn policy_digest(&self) -> Digest {
        self.policy_digest
    }
}

impl IssuerProfile {
    /// Applies the configured issuer profile to one workload identity.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyRejection`] when the identity kind does not match the
    /// profile or no configured policy admits it.
    pub fn admit(&self, identity: &WorkloadIdentity) -> Result<AdmittedWorkload, PolicyRejection> {
        let encoded = match (self, identity) {
            (Self::Generic { policies }, WorkloadIdentity::Generic(identity)) => policies
                .as_slice()
                .iter()
                .find(|policy| policy.admits(identity))
                .map(|p| p.subject.as_str().as_bytes().to_vec()),
            (Self::GithubActions { policies }, WorkloadIdentity::GithubActions(identity)) => {
                policies
                    .as_slice()
                    .iter()
                    .find(|policy| policy.admits(identity))
                    .map(|p| {
                        let mut bytes = Vec::new();
                        bytes.extend_from_slice(&p.repository_id.get().to_be_bytes());
                        bytes.extend_from_slice(&p.owner_id.get().to_be_bytes());
                        bytes
                    })
            }
            _ => return Err(PolicyRejection::ProfileMismatch),
        }
        .ok_or(PolicyRejection::NoPolicyAdmits)?;
        Ok(AdmittedWorkload {
            identity: identity.clone(),
            policy_digest: Digest::new(Sha256::digest(encoded).into()),
        })
    }

    pub(crate) fn configuration_components(&self) -> Vec<Vec<u8>> {
        match self {
            Self::Generic { policies } => policies
                .as_slice()
                .iter()
                .map(|p| p.subject.as_str().as_bytes().to_vec())
                .collect(),
            Self::GithubActions { policies } => policies
                .as_slice()
                .iter()
                .map(|p| {
                    github_policy_component(
                        p.repository_id.get(),
                        p.owner_id.get(),
                        p.workflow.as_ref(),
                        p.git_ref.as_ref(),
                        p.environment.as_ref(),
                    )
                })
                .collect(),
        }
    }
}

/// Appends one tagged, length-prefixed optional field, so that no two
/// distinct policies share an encoding.
fn push_policy_field(out: &mut Vec<u8>, tag: u8, value: Option<&[u8]>) {
    out.push(tag);
    match value {
        None => out.push(0),
        Some(bytes) => {
            out.push(1);
            out.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
            out.extend_from_slice(bytes);
        }
    }
}

/// Canonical configuration encoding of a GitHub workload policy: every field,
/// including the workflow pin, tagged and length-prefixed.
fn github_policy_component(
    repository_id: u64,
    owner_id: u64,
    workflow: Option<&WorkflowPin>,
    git_ref: Option<&GitRef>,
    environment: Option<&Environment>,
) -> Vec<u8> {
    let mut value = b"github-policy-v2".to_vec();
    push_policy_field(&mut value, 1, Some(&repository_id.to_be_bytes()));
    push_policy_field(&mut value, 2, Some(&owner_id.to_be_bytes()));
    match workflow {
        None => push_policy_field(&mut value, 3, None),
        Some(WorkflowPin::Exact {
            path,
            git_ref,
            commit,
        }) => {
            push_policy_field(&mut value, 3, Some(b"exact"));
            push_policy_field(&mut value, 4, Some(path.as_str().as_bytes()));
            push_policy_field(&mut value, 5, Some(git_ref.as_str().as_bytes()));
            push_policy_field(&mut value, 6, Some(commit.as_str().as_bytes()));
        }
        Some(WorkflowPin::AnyRef { path }) => {
            push_policy_field(&mut value, 3, Some(b"any-ref"));
            push_policy_field(&mut value, 4, Some(path.as_str().as_bytes()));
        }
    }
    push_policy_field(&mut value, 7, git_ref.map(|v| v.as_str().as_bytes()));
    push_policy_field(&mut value, 8, environment.map(|v| v.as_str().as_bytes()));
    value
}

/// Constructs one bounded generic workload policy set.
///
/// # Errors
///
/// Returns [`ConfigurationError`] when values are duplicated or exceed the
/// configured bound.
pub fn generic_policy_set(
    values: Vec<GenericPolicy>,
) -> Result<GenericPolicySet, ConfigurationError> {
    BoundedSet::new(values).map_err(ConfigurationError::Policies)
}
/// Constructs one bounded GitHub workload policy set.
///
/// # Errors
///
/// Returns [`ConfigurationError`] when values are duplicated or exceed the
/// configured bound.
pub fn github_policy_set(values: Vec<GithubPolicy>) -> Result<GithubPolicySet, ConfigurationError> {
    BoundedSet::new(values).map_err(ConfigurationError::Policies)
}

#[cfg(test)]
mod policy_commitment_tests {
    use super::*;

    fn policy(
        git_ref: Option<&str>,
        environment: Option<&str>,
        workflow: Option<WorkflowPin>,
    ) -> GithubPolicy {
        GithubPolicy {
            repository_id: RepositoryId::parse("123").expect("repository id"),
            owner_id: RepositoryOwnerId::parse("456").expect("owner id"),
            workflow,
            git_ref: git_ref.map(|value| GitRef::parse(value).expect("ref")),
            environment: environment.map(|value| Environment::parse(value).expect("environment")),
        }
    }

    fn components(policy: GithubPolicy) -> Vec<Vec<u8>> {
        IssuerProfile::GithubActions {
            policies: github_policy_set(vec![policy]).expect("policies"),
        }
        .configuration_components()
    }

    #[test]
    fn distinct_github_policies_never_share_a_configuration_encoding() {
        assert_ne!(
            components(policy(Some("refs/heads/ab"), Some("c"), None)),
            components(policy(Some("refs/heads/a"), Some("bc"), None))
        );
        assert_ne!(
            components(policy(Some("refs/heads/main"), None, None)),
            components(policy(None, Some("refs/heads/main"), None))
        );
        let pinned = WorkflowPin::AnyRef {
            path: WorkflowPath::parse(".github/workflows/release.yml").expect("path"),
        };
        assert_ne!(
            components(policy(None, None, Some(pinned))),
            components(policy(None, None, None))
        );
    }
}
