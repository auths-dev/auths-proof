extern crate alloc;

use alloc::{boxed::Box, string::String, vec::Vec};
use auths_model::{BoundedSet, Digest};
use auths_ports::VerifiedLeaf;
use sha2::{Digest as _, Sha256};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

use crate::{ExtensionError, SigstoreError};

pub const MAX_POLICIES: usize = 64;
pub const MAX_EXTENSION_BYTES: usize = 1024;

macro_rules! text {
    ($name:ident, $max:expr, $valid:expr) => {
        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);
        impl $name {
            /// Parses one bounded Fulcio identity field.
            ///
            /// # Errors
            ///
            /// Returns [`ExtensionError`] when the field is empty, exceeds its
            /// bound, or violates its field-specific syntax.
            pub fn parse(value: &str) -> Result<Self, ExtensionError> {
                if value.is_empty() || value.len() > $max || !($valid)(value) {
                    return Err(ExtensionError::InvalidValue);
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
    !value.bytes().any(|b| b.is_ascii_control())
}
fn https(value: &str) -> bool {
    value.starts_with("https://")
        && !value.contains(['@', '#'])
        && !value.bytes().any(|b| b.is_ascii_control() || b == b' ')
}
text!(IssuerUrl, 512, https);
text!(Subject, 1024, no_control);
text!(Environment, 256, no_control);
text!(GitRef, 256, |v: &str| v.starts_with("refs/")
    && !v.contains("..")
    && !v.contains("//")
    && !v.contains(' '));
text!(WorkflowPath, 256, |v: &str| v
    .starts_with(".github/workflows/")
    && v.rsplit_once('.')
        .is_some_and(|(_, extension)| matches!(extension, "yml" | "yaml"))
    && !v.contains(".."));
text!(RunInvocationUri, 1024, https);

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Repository(String);
impl Repository {
    /// Parses one canonical `owner/repository` name.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionError`] when the repository is malformed or exceeds
    /// its bound.
    pub fn parse(value: &str) -> Result<Self, ExtensionError> {
        let mut p = value.split('/');
        let a = p.next().unwrap_or("");
        let b = p.next().unwrap_or("");
        if a.is_empty()
            || b.is_empty()
            || p.next().is_some()
            || value.len() > 256
            || !value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'/' | b'.' | b'_' | b'-'))
        {
            return Err(ExtensionError::InvalidValue);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
    #[must_use]
    pub fn owner(&self) -> &str {
        self.0.split_once('/').map_or("", |v| v.0)
    }
}
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RepositoryOwner(String);
impl RepositoryOwner {
    /// Parses one canonical repository owner.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionError`] when the owner is malformed or exceeds its
    /// bound.
    pub fn parse(value: &str) -> Result<Self, ExtensionError> {
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(ExtensionError::InvalidValue);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
macro_rules! id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(u64);
        impl $name {
            /// Parses one positive canonical decimal identifier.
            ///
            /// # Errors
            ///
            /// Returns [`ExtensionError`] when the value is zero, has a
            /// leading zero, is non-decimal, or exceeds `u64`.
            pub fn parse(v: &str) -> Result<Self, ExtensionError> {
                if v.is_empty() || v.starts_with('0') || !v.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(ExtensionError::InvalidValue);
                }
                let n = v.parse().map_err(|_| ExtensionError::InvalidValue)?;
                if n == 0 {
                    return Err(ExtensionError::InvalidValue);
                }
                Ok(Self(n))
            }
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }
        }
    };
}
id!(RepositoryId);
id!(RepositoryOwnerId);
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CommitSha(String);
impl CommitSha {
    /// Parses one lowercase SHA-1 commit identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionError`] unless the value is exactly 40 lowercase
    /// hexadecimal digits, optionally prefixed by `sha1:`.
    pub fn parse(v: &str) -> Result<Self, ExtensionError> {
        let v = v.strip_prefix("sha1:").unwrap_or(v);
        if v.len() != 40
            || !v
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(ExtensionError::InvalidValue);
        }
        Ok(Self(v.into()))
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
    /// Returns [`ExtensionError`] for an unknown environment label.
    pub fn parse(v: &str) -> Result<Self, ExtensionError> {
        match v {
            "github-hosted" => Ok(Self::GithubHosted),
            "self-hosted" => Ok(Self::SelfHosted),
            _ => Err(ExtensionError::InvalidValue),
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
text!(EventName, 64, |v: &str| v
    .bytes()
    .all(|b| b.is_ascii_lowercase() || b == b'_'));

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
pub enum CertificateIdentity {
    Uri(String),
    Email(String),
    OtherName(String),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FulcioGenericIdentity {
    pub issuer: IssuerUrl,
    pub subject: Subject,
    pub certificate_san: CertificateIdentity,
}
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FulcioGithubIdentity {
    pub issuer: IssuerUrl,
    pub subject: Subject,
    pub certificate_san: CertificateIdentity,
    pub repository: Repository,
    pub repository_id: RepositoryId,
    pub owner: RepositoryOwner,
    pub owner_id: RepositoryOwnerId,
    pub workflow: WorkflowIdentity,
    pub job_workflow: ReusableWorkflow,
    pub git_ref: GitRef,
    pub sha: CommitSha,
    pub environment: Option<Environment>,
    pub runner: RunnerEnvironment,
    pub event: EventName,
    pub run_invocation: RunInvocationUri,
}
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FulcioWorkloadIdentity {
    Generic(FulcioGenericIdentity),
    GithubActions(Box<FulcioGithubIdentity>),
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
pub struct FulcioGenericPolicy {
    pub subject: Subject,
}
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FulcioGithubPolicy {
    pub repository_id: RepositoryId,
    pub owner_id: RepositoryOwnerId,
    pub workflow: Option<WorkflowPin>,
    pub git_ref: Option<GitRef>,
    pub environment: Option<Environment>,
}
pub type FulcioGenericPolicySet = BoundedSet<FulcioGenericPolicy, MAX_POLICIES>;
pub type FulcioGithubPolicySet = BoundedSet<FulcioGithubPolicy, MAX_POLICIES>;
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FulcioIssuerProfile {
    Generic { policies: FulcioGenericPolicySet },
    GithubActions { policies: FulcioGithubPolicySet },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyRejection {
    ProfileMismatch,
    NoPolicyAdmits,
}
#[derive(Clone, Debug)]
pub struct AdmittedWorkload {
    pub identity: FulcioWorkloadIdentity,
    pub policy_digest: Digest,
}

impl FulcioIssuerProfile {
    /// Applies the configured issuer profile to one extracted workload.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyRejection`] when the identity kind does not match the
    /// profile or no configured policy admits it.
    pub fn admit(
        &self,
        identity: &FulcioWorkloadIdentity,
    ) -> Result<AdmittedWorkload, PolicyRejection> {
        let bytes = match (self, identity) {
            (Self::Generic { policies }, FulcioWorkloadIdentity::Generic(i)) => policies
                .as_slice()
                .iter()
                .find(|p| p.subject == i.subject)
                .map(|p| p.subject.as_str().as_bytes().to_vec()),
            (Self::GithubActions { policies }, FulcioWorkloadIdentity::GithubActions(i)) => {
                policies
                    .as_slice()
                    .iter()
                    .find(|p| github_admits(p, i))
                    .map(|p| {
                        let mut v = Vec::new();
                        v.extend_from_slice(&p.repository_id.get().to_be_bytes());
                        v.extend_from_slice(&p.owner_id.get().to_be_bytes());
                        v
                    })
            }
            _ => return Err(PolicyRejection::ProfileMismatch),
        }
        .ok_or(PolicyRejection::NoPolicyAdmits)?;
        Ok(AdmittedWorkload {
            identity: identity.clone(),
            policy_digest: Digest::new(Sha256::digest(bytes).into()),
        })
    }
    pub(crate) fn components(&self) -> Vec<Vec<u8>> {
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
                    let mut v = Vec::new();
                    v.extend_from_slice(&p.repository_id.get().to_be_bytes());
                    v.extend_from_slice(&p.owner_id.get().to_be_bytes());
                    v
                })
                .collect(),
        }
    }
}
fn github_admits(p: &FulcioGithubPolicy, i: &FulcioGithubIdentity) -> bool {
    p.repository_id == i.repository_id
        && p.owner_id == i.owner_id
        && p.workflow.as_ref().is_none_or(|pin| match pin {
            WorkflowPin::Exact {
                path,
                git_ref,
                commit,
            } => {
                i.workflow.reference.path == *path
                    && i.workflow.reference.git_ref == *git_ref
                    && i.workflow.commit == *commit
            }
            WorkflowPin::AnyRef { path } => i.workflow.reference.path == *path,
        })
        && p.git_ref.as_ref().is_none_or(|v| i.git_ref == *v)
        && p.environment
            .as_ref()
            .is_none_or(|v| i.environment.as_ref() == Some(v))
}

pub(crate) struct FulcioFacts {
    pub issuer: IssuerUrl,
    pub subject: Subject,
    pub san: CertificateIdentity,
    pub values: Vec<(String, String)>,
}
impl FulcioFacts {
    pub fn extract(leaf: &VerifiedLeaf) -> Result<Self, SigstoreError> {
        let (rem, cert) = parse_x509_certificate(leaf.der().as_bytes())
            .map_err(|_| SigstoreError::Extension(ExtensionError::Certificate))?;
        if !rem.is_empty() {
            return Err(SigstoreError::Extension(ExtensionError::Certificate));
        }
        let mut values = Vec::new();
        for ext in cert.iter_extensions() {
            let oid = ext.oid.to_id_string();
            if oid.starts_with("1.3.6.1.4.1.57264.1.") {
                if values.iter().any(|(prior, _)| prior == &oid) {
                    return Err(SigstoreError::Extension(ExtensionError::Duplicate));
                }
                let value = der_string(ext.value)?;
                if value.len() > MAX_EXTENSION_BYTES {
                    return Err(SigstoreError::Extension(ExtensionError::Limit));
                }
                values.push((oid, value));
            }
        }
        if values.iter().any(|(oid, _)| oid == "1.3.6.1.4.1.57264.1.1") {
            return Err(SigstoreError::Extension(ExtensionError::Deprecated));
        }
        let issuer = IssuerUrl::parse(required(&values, "1.3.6.1.4.1.57264.1.8")?)
            .map_err(SigstoreError::Extension)?;
        let subject = Subject::parse(required(&values, "1.3.6.1.4.1.57264.1.24")?)
            .map_err(SigstoreError::Extension)?;
        let san_ext = cert
            .subject_alternative_name()
            .map_err(|_| SigstoreError::Extension(ExtensionError::Certificate))?
            .ok_or(SigstoreError::Extension(ExtensionError::Missing))?;
        if san_ext.value.general_names.len() != 1 {
            return Err(SigstoreError::Extension(ExtensionError::IdentitySan));
        }
        let san = match &san_ext.value.general_names[0] {
            GeneralName::URI(v) => CertificateIdentity::Uri((*v).into()),
            GeneralName::RFC822Name(v) => CertificateIdentity::Email((*v).into()),
            GeneralName::OtherName(oid, value) if oid.to_id_string() == "1.3.6.1.4.1.57264.1.7" => {
                CertificateIdentity::OtherName(der_string(value)?)
            }
            _ => return Err(SigstoreError::Extension(ExtensionError::IdentitySan)),
        };
        Ok(Self {
            issuer,
            subject,
            san,
            values,
        })
    }
    pub fn into_identity(
        self,
        profile: &FulcioIssuerProfile,
    ) -> Result<FulcioWorkloadIdentity, SigstoreError> {
        match profile {
            FulcioIssuerProfile::Generic { .. } => {
                Ok(FulcioWorkloadIdentity::Generic(FulcioGenericIdentity {
                    issuer: self.issuer,
                    subject: self.subject,
                    certificate_san: self.san,
                }))
            }
            FulcioIssuerProfile::GithubActions { .. } => {
                let repository =
                    github_repository(required(&self.values, "1.3.6.1.4.1.57264.1.12")?)?;
                let owner = github_owner(required(&self.values, "1.3.6.1.4.1.57264.1.16")?)?;
                let initiating_workflow = workflow(
                    required(&self.values, "1.3.6.1.4.1.57264.1.18")?,
                    required(&self.values, "1.3.6.1.4.1.57264.1.19")?,
                )?;
                let signer = workflow(
                    required(&self.values, "1.3.6.1.4.1.57264.1.9")?,
                    required(&self.values, "1.3.6.1.4.1.57264.1.10")?,
                )?;
                let job_workflow = if signer == initiating_workflow {
                    ReusableWorkflow::Absent
                } else {
                    ReusableWorkflow::Present(signer)
                };
                Ok(FulcioWorkloadIdentity::GithubActions(Box::new(
                    FulcioGithubIdentity {
                        issuer: self.issuer,
                        subject: self.subject,
                        certificate_san: self.san,
                        repository,
                        repository_id: RepositoryId::parse(required(
                            &self.values,
                            "1.3.6.1.4.1.57264.1.15",
                        )?)
                        .map_err(SigstoreError::Extension)?,
                        owner,
                        owner_id: RepositoryOwnerId::parse(required(
                            &self.values,
                            "1.3.6.1.4.1.57264.1.17",
                        )?)
                        .map_err(SigstoreError::Extension)?,
                        workflow: initiating_workflow,
                        job_workflow,
                        git_ref: GitRef::parse(required(&self.values, "1.3.6.1.4.1.57264.1.14")?)
                            .map_err(SigstoreError::Extension)?,
                        sha: CommitSha::parse(required(&self.values, "1.3.6.1.4.1.57264.1.13")?)
                            .map_err(SigstoreError::Extension)?,
                        environment: optional(&self.values, "1.3.6.1.4.1.57264.1.23")
                            .map(Environment::parse)
                            .transpose()
                            .map_err(SigstoreError::Extension)?,
                        runner: RunnerEnvironment::parse(required(
                            &self.values,
                            "1.3.6.1.4.1.57264.1.11",
                        )?)
                        .map_err(SigstoreError::Extension)?,
                        event: EventName::parse(required(&self.values, "1.3.6.1.4.1.57264.1.20")?)
                            .map_err(SigstoreError::Extension)?,
                        run_invocation: RunInvocationUri::parse(required(
                            &self.values,
                            "1.3.6.1.4.1.57264.1.21",
                        )?)
                        .map_err(SigstoreError::Extension)?,
                    },
                )))
            }
        }
    }
}
fn required<'a>(v: &'a [(String, String)], oid: &str) -> Result<&'a str, SigstoreError> {
    optional(v, oid).ok_or(SigstoreError::Extension(ExtensionError::Missing))
}
fn optional<'a>(v: &'a [(String, String)], oid: &str) -> Option<&'a str> {
    v.iter().find(|(id, _)| id == oid).map(|(_, v)| v.as_str())
}
fn github_repository(v: &str) -> Result<Repository, SigstoreError> {
    Repository::parse(
        v.strip_prefix("https://github.com/")
            .ok_or(SigstoreError::Extension(ExtensionError::InvalidValue))?,
    )
    .map_err(SigstoreError::Extension)
}
fn github_owner(v: &str) -> Result<RepositoryOwner, SigstoreError> {
    RepositoryOwner::parse(
        v.strip_prefix("https://github.com/")
            .ok_or(SigstoreError::Extension(ExtensionError::InvalidValue))?,
    )
    .map_err(SigstoreError::Extension)
}
fn workflow(uri: &str, commit: &str) -> Result<WorkflowIdentity, SigstoreError> {
    let value = uri
        .strip_prefix("https://github.com/")
        .ok_or(SigstoreError::Extension(ExtensionError::InvalidValue))?;
    let marker = "/.github/workflows/";
    let i = value
        .find(marker)
        .ok_or(SigstoreError::Extension(ExtensionError::InvalidValue))?;
    let repo = Repository::parse(&value[..i]).map_err(SigstoreError::Extension)?;
    let rest = &value[i + 1..];
    let at = rest
        .rfind('@')
        .ok_or(SigstoreError::Extension(ExtensionError::InvalidValue))?;
    Ok(WorkflowIdentity {
        reference: WorkflowRef {
            repository: repo,
            path: WorkflowPath::parse(&rest[..at]).map_err(SigstoreError::Extension)?,
            git_ref: GitRef::parse(&rest[at + 1..]).map_err(SigstoreError::Extension)?,
        },
        commit: CommitSha::parse(commit).map_err(SigstoreError::Extension)?,
    })
}
fn der_string(bytes: &[u8]) -> Result<String, SigstoreError> {
    let mut value = bytes;
    if value.first() == Some(&0xa0) {
        let (h, l) = tlv(value, 0xa0)?;
        value = value
            .get(h..h + l)
            .ok_or(SigstoreError::Extension(ExtensionError::InvalidValue))?;
    }
    let tag = *value
        .first()
        .ok_or(SigstoreError::Extension(ExtensionError::InvalidValue))?;
    if !matches!(tag, 0x0c | 0x16) {
        return Err(SigstoreError::Extension(ExtensionError::InvalidValue));
    }
    let (h, l) = tlv(value, tag)?;
    let text = core::str::from_utf8(
        value
            .get(h..h + l)
            .ok_or(SigstoreError::Extension(ExtensionError::InvalidValue))?,
    )
    .map_err(|_| SigstoreError::Extension(ExtensionError::InvalidValue))?;
    Ok(text.into())
}
fn tlv(v: &[u8], tag: u8) -> Result<(usize, usize), SigstoreError> {
    if v.first() != Some(&tag) {
        return Err(SigstoreError::Extension(ExtensionError::InvalidValue));
    }
    let b = *v
        .get(1)
        .ok_or(SigstoreError::Extension(ExtensionError::InvalidValue))?;
    if b & 0x80 == 0 {
        return Ok((2, usize::from(b)));
    }
    let n = usize::from(b & 0x7f);
    if n == 0 || n > 4 || v.len() < 2 + n {
        return Err(SigstoreError::Extension(ExtensionError::InvalidValue));
    }
    let mut l = 0;
    for b in &v[2..2 + n] {
        l = l * 256 + usize::from(*b);
    }
    Ok((2 + n, l))
}
