extern crate alloc;

use alloc::string::String;

use crate::{
    ClaimError, OidcError, github,
    identity::*,
    json::{JsonValue, flat_object},
    window::{TokenLifetime, TokenWindow},
};

pub const MAX_CLAIM_BYTES: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AudienceClaim(String);
impl AudienceClaim {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommonClaims {
    pub iss: IssuerUrl,
    pub sub: Subject,
    pub aud: AudienceClaim,
    pub window: TokenWindow,
    pub jti: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubClaims {
    pub common: CommonClaims,
    pub repository: Repository,
    pub repository_id: RepositoryId,
    pub repository_owner: RepositoryOwner,
    pub repository_owner_id: RepositoryOwnerId,
    pub workflow_ref: WorkflowRef,
    pub workflow_sha: CommitSha,
    pub job_workflow_ref: Option<WorkflowRef>,
    pub job_workflow_sha: Option<CommitSha>,
    pub git_ref: GitRef,
    pub sha: CommitSha,
    pub environment: Option<Environment>,
    pub runner_environment: Option<RunnerEnvironment>,
    pub actor: Option<Actor>,
    pub event_name: Option<EventName>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimSet {
    Generic(CommonClaims),
    GithubActions(GithubClaims),
}

impl ClaimSet {
    pub fn parse(
        payload: &[u8],
        profile: &IssuerProfile,
        lifetime: TokenLifetime,
    ) -> Result<Self, OidcError> {
        let mut members = flat_object(payload).map_err(OidcError::Claims)?;
        for (_, value) in &members {
            if matches!(value, JsonValue::String(value) | JsonValue::OneStringArray(value) if value.len() > MAX_CLAIM_BYTES)
            {
                return Err(OidcError::Claims(ClaimError::Limit));
            }
        }
        let iss = IssuerUrl::parse(&take_string(&mut members, "iss")?)?;
        let sub = Subject::parse(&take_string(&mut members, "sub")?)?;
        let aud = match take(&mut members, "aud")? {
            JsonValue::String(v) | JsonValue::OneStringArray(v) => AudienceClaim(v),
            _ => return Err(OidcError::Claims(ClaimError::WrongType)),
        };
        let iat = take_integer(&mut members, "iat")?;
        let exp = take_integer(&mut members, "exp")?;
        let nbf = take_optional_integer(&mut members, "nbf")?;
        let jti = take_optional_string(&mut members, "jti")?;
        let common = CommonClaims {
            iss,
            sub,
            aud,
            window: TokenWindow::new(iat, exp, nbf, lifetime).map_err(OidcError::Claims)?,
            jti,
        };
        match profile {
            IssuerProfile::Generic { .. } => {
                if !members.is_empty() {
                    return Err(OidcError::Claims(ClaimError::UnknownMember));
                }
                Ok(Self::Generic(common))
            }
            IssuerProfile::GithubActions { .. } => {
                let repository = Repository::parse(&take_string(&mut members, "repository")?)?;
                let repository_id =
                    RepositoryId::parse(&take_string(&mut members, "repository_id")?)?;
                let repository_owner =
                    RepositoryOwner::parse(&take_string(&mut members, "repository_owner")?)?;
                let repository_owner_id =
                    RepositoryOwnerId::parse(&take_string(&mut members, "repository_owner_id")?)?;
                let workflow_ref =
                    github::workflow_ref(&take_string(&mut members, "workflow_ref")?)
                        .map_err(OidcError::Claims)?;
                let workflow_sha = CommitSha::parse(&take_string(&mut members, "workflow_sha")?)?;
                let job_workflow_ref = take_optional_string(&mut members, "job_workflow_ref")?
                    .map(|value| github::workflow_ref(&value))
                    .transpose()
                    .map_err(OidcError::Claims)?;
                let job_workflow_sha = take_optional_string(&mut members, "job_workflow_sha")?
                    .map(|value| CommitSha::parse(&value))
                    .transpose()?;
                if job_workflow_ref.is_some() != job_workflow_sha.is_some() {
                    return Err(OidcError::Claims(ClaimError::InconsistentIdentity));
                }
                let git_ref = GitRef::parse(&take_string(&mut members, "ref")?)?;
                let sha = CommitSha::parse(&take_string(&mut members, "sha")?)?;
                let environment = take_optional_string(&mut members, "environment")?
                    .map(|v| Environment::parse(&v))
                    .transpose()?;
                let runner_environment = take_optional_string(&mut members, "runner_environment")?
                    .map(|v| RunnerEnvironment::parse(&v))
                    .transpose()?;
                let actor = take_optional_string(&mut members, "actor")?
                    .map(|v| Actor::parse(&v))
                    .transpose()?;
                let event_name = take_optional_string(&mut members, "event_name")?
                    .map(|v| EventName::parse(&v))
                    .transpose()?;
                const IGNORED: &[&str] = &[
                    "actor_id",
                    "base_ref",
                    "check_run_id",
                    "enterprise",
                    "enterprise_id",
                    "head_ref",
                    "ref_protected",
                    "ref_type",
                    "repository_visibility",
                    "run_attempt",
                    "run_id",
                    "run_number",
                    "workflow",
                ];
                members.retain(|(name, _)| !IGNORED.contains(&name.as_str()));
                if !members.is_empty() {
                    return Err(OidcError::Claims(ClaimError::UnknownMember));
                }
                Ok(Self::GithubActions(GithubClaims {
                    common,
                    repository,
                    repository_id,
                    repository_owner,
                    repository_owner_id,
                    workflow_ref,
                    workflow_sha,
                    job_workflow_ref,
                    job_workflow_sha,
                    git_ref,
                    sha,
                    environment,
                    runner_environment,
                    actor,
                    event_name,
                }))
            }
        }
    }

    #[must_use]
    pub const fn common(&self) -> &CommonClaims {
        match self {
            Self::Generic(v) => v,
            Self::GithubActions(v) => &v.common,
        }
    }
    pub fn into_identity(self) -> Result<WorkloadIdentity, OidcError> {
        match self {
            Self::Generic(value) => Ok(WorkloadIdentity::Generic(GenericIdentity {
                issuer: value.iss,
                subject: value.sub,
            })),
            Self::GithubActions(value) => Ok(WorkloadIdentity::GithubActions(GithubIdentity::new(
                GithubIdentity {
                    issuer: value.common.iss,
                    subject: value.common.sub,
                    repository: value.repository,
                    repository_id: value.repository_id,
                    owner: value.repository_owner,
                    owner_id: value.repository_owner_id,
                    workflow: WorkflowIdentity {
                        reference: value.workflow_ref,
                        commit: value.workflow_sha,
                    },
                    job_workflow: match (value.job_workflow_ref, value.job_workflow_sha) {
                        (Some(reference), Some(commit)) => {
                            ReusableWorkflow::Present(WorkflowIdentity { reference, commit })
                        }
                        _ => ReusableWorkflow::Absent,
                    },
                    git_ref: value.git_ref,
                    sha: value.sha,
                    environment: value.environment,
                    runner: value.runner_environment,
                    actor: value.actor,
                    event: value.event_name,
                },
            )?)),
        }
    }
}

fn position(members: &[(String, JsonValue)], name: &str) -> Option<usize> {
    members.iter().position(|(candidate, _)| candidate == name)
}
fn take(
    members: &mut alloc::vec::Vec<(String, JsonValue)>,
    name: &str,
) -> Result<JsonValue, OidcError> {
    position(members, name)
        .map(|i| members.remove(i).1)
        .ok_or(OidcError::Claims(ClaimError::MissingMember))
}
fn take_string(
    members: &mut alloc::vec::Vec<(String, JsonValue)>,
    name: &str,
) -> Result<String, OidcError> {
    match take(members, name)? {
        JsonValue::String(v) => Ok(v),
        _ => Err(OidcError::Claims(ClaimError::WrongType)),
    }
}
fn take_integer(
    members: &mut alloc::vec::Vec<(String, JsonValue)>,
    name: &str,
) -> Result<u64, OidcError> {
    match take(members, name)? {
        JsonValue::Integer(v) => Ok(v),
        _ => Err(OidcError::Claims(ClaimError::WrongType)),
    }
}
fn take_optional_string(
    members: &mut alloc::vec::Vec<(String, JsonValue)>,
    name: &str,
) -> Result<Option<String>, OidcError> {
    position(members, name)
        .map(|_| take_string(members, name))
        .transpose()
}
fn take_optional_integer(
    members: &mut alloc::vec::Vec<(String, JsonValue)>,
    name: &str,
) -> Result<Option<u64>, OidcError> {
    position(members, name)
        .map(|_| take_integer(members, name))
        .transpose()
}
