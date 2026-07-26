//! Exact target V1 profiles for HTTP, Git, deployment, software supply
//! chains, and edge control.

#![forbid(unsafe_code)]

use auths_model::{
    BudgetAlgebraId, BudgetCeiling, CanonicalAction, CapabilityId, MediaType, Permission,
    ProfileId, ProfileRef, ResourceId,
};
use auths_profile_api::{ActionProfile, ApprovalDisplay, ProfileContractError};
use auths_verifier::VerifiedAction;
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, marker::PhantomData};

const MAX_ACTION_BYTES: usize = 256 * 1024;

trait DomainMeaning: Clone + DeserializeOwned + Serialize {
    const PROFILE_ID: &'static str;
    const PROFILE_VERSION: u16 = 1;
    const MEDIA_TYPE: &'static str;

    fn validate(&self) -> Result<(), ProfileContractError>;
    fn permission(&self) -> Result<Permission, ProfileContractError>;
    fn display(&self) -> Vec<(String, String)>;
    fn budget(&self) -> Result<Option<BudgetCeiling>, ProfileContractError> {
        Ok(None)
    }
}

/// Zero-sized implementation of one exact domain profile.
#[derive(Clone, Copy, Debug)]
pub struct DomainProfile<T>(PhantomData<T>);

impl<T> Default for DomainProfile<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

/// Executor-safe command decoded from a sealed verified action.
#[derive(Clone, Debug, PartialEq)]
pub struct DomainCommand<T> {
    action: T,
}

impl<T> DomainCommand<T> {
    #[must_use]
    pub const fn action(&self) -> &T {
        &self.action
    }
}

impl<T> ActionProfile for DomainProfile<T>
where
    T: DomainMeaning,
{
    type Command = DomainCommand<T>;

    fn canonicalize(&self, untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
        if untrusted.is_empty() || untrusted.len() > MAX_ACTION_BYTES {
            return Err(ProfileContractError::LimitExceeded);
        }
        let action: T =
            serde_json::from_slice(untrusted).map_err(|_| ProfileContractError::Malformed)?;
        action.validate()?;
        let bytes = serde_json_canonicalizer::to_vec(&action)
            .map_err(|_| ProfileContractError::Malformed)?;
        if bytes.len() > MAX_ACTION_BYTES {
            return Err(ProfileContractError::LimitExceeded);
        }
        CanonicalAction::new(
            profile::<T>()?,
            MediaType::parse(T::MEDIA_TYPE)
                .map_err(|_| ProfileContractError::UnsupportedProfile)?,
            bytes,
            action.permission()?,
            action.budget()?,
        )
        .map_err(|_| ProfileContractError::MeaningMismatch)
    }

    fn approval_display(
        &self,
        action: &CanonicalAction,
    ) -> Result<ApprovalDisplay, ProfileContractError> {
        let command = decode_action::<T>(action)?;
        Ok(ApprovalDisplay::new(
            format!("Auths V1 · {} approval", T::PROFILE_ID),
            command.display(),
            hex::encode(Sha256::digest(action.body())),
        ))
    }

    fn decode_verified(
        &self,
        action: &VerifiedAction,
    ) -> Result<Self::Command, ProfileContractError> {
        Ok(DomainCommand {
            action: decode_action::<T>(action.canonical_action())?,
        })
    }
}

fn profile<T: DomainMeaning>() -> Result<ProfileRef, ProfileContractError> {
    ProfileRef::new(
        ProfileId::parse(T::PROFILE_ID).map_err(|_| ProfileContractError::UnsupportedProfile)?,
        T::PROFILE_VERSION,
    )
    .map_err(|_| ProfileContractError::UnsupportedProfile)
}

fn decode_action<T: DomainMeaning>(canonical: &CanonicalAction) -> Result<T, ProfileContractError> {
    if canonical.profile() != &profile::<T>()? || canonical.media_type().as_str() != T::MEDIA_TYPE {
        return Err(ProfileContractError::UnsupportedProfile);
    }
    let action: T =
        serde_json::from_slice(canonical.body()).map_err(|_| ProfileContractError::Malformed)?;
    action.validate()?;
    let encoded =
        serde_json_canonicalizer::to_vec(&action).map_err(|_| ProfileContractError::Malformed)?;
    if encoded != canonical.body() {
        return Err(ProfileContractError::NonCanonical);
    }
    if action.permission()? != *canonical.permission() {
        return Err(ProfileContractError::MeaningMismatch);
    }
    if action.budget()?.as_ref() != canonical.requested_budget() {
        return Err(ProfileContractError::MeaningMismatch);
    }
    Ok(action)
}

fn reference_canonicalize<T: DomainMeaning>(
    untrusted: &[u8],
) -> Result<CanonicalAction, ProfileContractError> {
    if untrusted.is_empty() || untrusted.len() > MAX_ACTION_BYTES {
        return Err(ProfileContractError::LimitExceeded);
    }
    let generic: serde_json::Value =
        serde_json::from_slice(untrusted).map_err(|_| ProfileContractError::Malformed)?;
    let action: T = serde_json::from_value(generic).map_err(|_| ProfileContractError::Malformed)?;
    action.validate()?;
    let normalized = serde_json::to_value(&action).map_err(|_| ProfileContractError::Malformed)?;
    let bytes = serde_json_canonicalizer::to_vec(&normalized)
        .map_err(|_| ProfileContractError::Malformed)?;
    CanonicalAction::new(
        profile::<T>()?,
        MediaType::parse(T::MEDIA_TYPE).map_err(|_| ProfileContractError::UnsupportedProfile)?,
        bytes,
        action.permission()?,
        action.budget()?,
    )
    .map_err(|_| ProfileContractError::MeaningMismatch)
}

fn exact_profile(
    actual_id: &str,
    actual_version: u16,
    expected_id: &str,
) -> Result<(), ProfileContractError> {
    if actual_id == expected_id && actual_version == 1 {
        Ok(())
    } else {
        Err(ProfileContractError::UnsupportedProfile)
    }
}

fn token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/' | b':')
        })
}

fn lower_token(value: &str, maximum: usize) -> bool {
    token(value, maximum) && value == value.to_ascii_lowercase()
}

fn canonical_uri_component(value: &str, maximum: usize, allow_slash: bool) -> bool {
    if value.len() > maximum || !value.is_ascii() {
        return false;
    }
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
                || bytes[index + 1].is_ascii_lowercase()
                || bytes[index + 2].is_ascii_lowercase()
            {
                return false;
            }
            index += 3;
            continue;
        }
        let allowed = byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
            )
            || (allow_slash && byte == b'/');
        if !allowed {
            return false;
        }
        index += 1;
    }
    true
}

fn canonical_authority(value: &str, scheme: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value == value.to_ascii_lowercase()
        && value.is_ascii()
        && !value.contains(['/', '@'])
        && !value.contains("..")
        && !value.starts_with('.')
        && !value.ends_with('.')
        && !value.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']'))
        })
        && !((scheme == "http" && value.ends_with(":80"))
            || (scheme == "https" && value.ends_with(":443")))
}

fn canonical_header_value(value: &str) -> bool {
    value.len() <= 8 * 1024
        && value.is_ascii()
        && !value.bytes().any(|byte| byte.is_ascii_control())
        && value.trim() == value
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn permission(capability: &str, resource: &str) -> Result<Permission, ProfileContractError> {
    Ok(Permission::new(
        CapabilityId::parse(capability).map_err(|_| ProfileContractError::MeaningMismatch)?,
        ResourceId::parse(resource).map_err(|_| ProfileContractError::MeaningMismatch)?,
    ))
}

/// Closed canonical HTTP action.
#[derive(Clone, Debug, PartialEq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpAction {
    profile: String,
    profile_version: u16,
    method: String,
    scheme: String,
    authority: String,
    path: String,
    query: BTreeMap<String, Vec<String>>,
    headers: BTreeMap<String, String>,
    content_type: Option<String>,
    body_digest: Option<String>,
}

impl HttpAction {
    /// Constructs one explicit HTTP action.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        method: String,
        scheme: String,
        authority: String,
        path: String,
        query: BTreeMap<String, Vec<String>>,
        headers: BTreeMap<String, String>,
        content_type: Option<String>,
        body_digest: Option<String>,
    ) -> Self {
        Self {
            profile: "auths.http".into(),
            profile_version: 1,
            method,
            scheme,
            authority,
            path,
            query,
            headers,
            content_type,
            body_digest,
        }
    }

    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub const fn query(&self) -> &BTreeMap<String, Vec<String>> {
        &self.query
    }

    #[must_use]
    pub const fn headers(&self) -> &BTreeMap<String, String> {
        &self.headers
    }

    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    #[must_use]
    pub fn body_digest(&self) -> Option<&str> {
        self.body_digest.as_deref()
    }
}

impl DomainMeaning for HttpAction {
    const PROFILE_ID: &'static str = "auths.http";
    const MEDIA_TYPE: &'static str = "application/vnd.auths.http-action.v1+json";

    fn validate(&self) -> Result<(), ProfileContractError> {
        exact_profile(&self.profile, self.profile_version, Self::PROFILE_ID)?;
        if !matches!(
            self.method.as_str(),
            "DELETE" | "GET" | "HEAD" | "PATCH" | "POST" | "PUT"
        ) || !matches!(self.scheme.as_str(), "http" | "https")
            || !canonical_authority(&self.authority, &self.scheme)
            || !self.path.starts_with('/')
            || !canonical_uri_component(&self.path, 8 * 1024, true)
            || self.path.contains("//")
            || self.path.split('/').any(|part| part == "." || part == "..")
            || self.query.len() > 64
            || self.query.values().map(Vec::len).sum::<usize>() > 256
            || self.query.iter().any(|(name, values)| {
                name.is_empty()
                    || !canonical_uri_component(name, 256, false)
                    || values.is_empty()
                    || values
                        .iter()
                        .any(|value| !canonical_uri_component(value, 2 * 1024, false))
            })
            || self.headers.len() > 64
            || self
                .headers
                .iter()
                .any(|(name, value)| !lower_token(name, 128) || !canonical_header_value(value))
            || self.content_type.as_deref().is_some_and(|value| {
                !lower_token(value, 128) || !value.contains('/') || value.contains("..")
            })
            || self
                .body_digest
                .as_deref()
                .is_some_and(|value| !digest(value))
        {
            return Err(ProfileContractError::MeaningMismatch);
        }
        Ok(())
    }

    fn permission(&self) -> Result<Permission, ProfileContractError> {
        permission(
            &format!("http/{}", self.method.to_ascii_lowercase()),
            &format!("{}://{}{}", self.scheme, self.authority, self.path),
        )
    }

    fn display(&self) -> Vec<(String, String)> {
        vec![
            ("Method".into(), self.method.clone()),
            (
                "Target".into(),
                format!("{}://{}{}", self.scheme, self.authority, self.path),
            ),
            (
                "Body digest".into(),
                self.body_digest.clone().unwrap_or_else(|| "none".into()),
            ),
        ]
    }
}

/// Closed canonical Git action.
#[derive(Clone, Debug, PartialEq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitAction {
    profile: String,
    profile_version: u16,
    repository: String,
    operation: String,
    reference: String,
    object_id: String,
}

impl GitAction {
    #[must_use]
    pub fn new(
        repository: String,
        operation: String,
        reference: String,
        object_id: String,
    ) -> Self {
        Self {
            profile: "auths.git".into(),
            profile_version: 1,
            repository,
            operation,
            reference,
            object_id,
        }
    }

    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }

    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }

    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }

    #[must_use]
    pub fn object_id(&self) -> &str {
        &self.object_id
    }
}

impl DomainMeaning for GitAction {
    const PROFILE_ID: &'static str = "auths.git";
    const MEDIA_TYPE: &'static str = "application/vnd.auths.git-action.v1+json";

    fn validate(&self) -> Result<(), ProfileContractError> {
        exact_profile(&self.profile, self.profile_version, Self::PROFILE_ID)?;
        if !lower_token(&self.repository, 256)
            || !matches!(
                self.operation.as_str(),
                "create-ref" | "delete-ref" | "merge" | "push" | "tag"
            )
            || !token(&self.reference, 256)
            || self.reference.starts_with('/')
            || self.reference.ends_with('/')
            || self.reference.contains("//")
            || self
                .reference
                .split('/')
                .any(|part| part == "." || part == "..")
            || !digest(&self.object_id)
        {
            return Err(ProfileContractError::MeaningMismatch);
        }
        Ok(())
    }

    fn permission(&self) -> Result<Permission, ProfileContractError> {
        permission(
            &format!("git/{}", self.operation),
            &format!("git://{}/refs/{}", self.repository, self.reference),
        )
    }

    fn display(&self) -> Vec<(String, String)> {
        vec![
            ("Repository".into(), self.repository.clone()),
            ("Operation".into(), self.operation.clone()),
            ("Reference".into(), self.reference.clone()),
            ("Object".into(), self.object_id.clone()),
        ]
    }
}

/// Closed canonical deployment action.
#[derive(Clone, Debug, PartialEq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentAction {
    profile: String,
    profile_version: u16,
    environment: String,
    region: String,
    operation: String,
    artifact_digest: String,
    provenance_digest: String,
    configuration_digest: String,
    strategy: String,
    rollout_not_before: u64,
    rollout_expires_at: u64,
    blast_radius: u64,
}

impl DeploymentAction {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        environment: String,
        region: String,
        operation: String,
        artifact_digest: String,
        provenance_digest: String,
        configuration_digest: String,
        strategy: String,
        rollout_not_before: u64,
        rollout_expires_at: u64,
        blast_radius: u64,
    ) -> Self {
        Self {
            profile: "auths.deploy".into(),
            profile_version: 1,
            environment,
            region,
            operation,
            artifact_digest,
            provenance_digest,
            configuration_digest,
            strategy,
            rollout_not_before,
            rollout_expires_at,
            blast_radius,
        }
    }

    #[must_use]
    pub fn environment(&self) -> &str {
        &self.environment
    }

    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }

    #[must_use]
    pub fn artifact_digest(&self) -> &str {
        &self.artifact_digest
    }

    #[must_use]
    pub fn provenance_digest(&self) -> &str {
        &self.provenance_digest
    }

    #[must_use]
    pub fn configuration_digest(&self) -> &str {
        &self.configuration_digest
    }

    #[must_use]
    pub fn strategy(&self) -> &str {
        &self.strategy
    }

    #[must_use]
    pub const fn rollout_not_before(&self) -> u64 {
        self.rollout_not_before
    }

    #[must_use]
    pub const fn rollout_expires_at(&self) -> u64 {
        self.rollout_expires_at
    }

    #[must_use]
    pub const fn blast_radius(&self) -> u64 {
        self.blast_radius
    }
}

impl DomainMeaning for DeploymentAction {
    const PROFILE_ID: &'static str = "auths.deploy";
    const MEDIA_TYPE: &'static str = "application/vnd.auths.deploy-action.v1+json";

    fn validate(&self) -> Result<(), ProfileContractError> {
        exact_profile(&self.profile, self.profile_version, Self::PROFILE_ID)?;
        if !lower_token(&self.environment, 128)
            || !lower_token(&self.region, 128)
            || !matches!(self.operation.as_str(), "activate" | "deploy" | "rollback")
            || !digest(&self.artifact_digest)
            || !digest(&self.provenance_digest)
            || !digest(&self.configuration_digest)
            || !matches!(
                self.strategy.as_str(),
                "blue-green" | "canary" | "immediate" | "rolling"
            )
            || self.rollout_not_before == 0
            || self.rollout_expires_at < self.rollout_not_before
            || self.blast_radius == 0
        {
            return Err(ProfileContractError::MeaningMismatch);
        }
        Ok(())
    }

    fn permission(&self) -> Result<Permission, ProfileContractError> {
        permission(
            &format!("deploy/{}", self.operation),
            &format!(
                "deploy://{}/{}/artifacts/{}",
                self.environment, self.region, self.artifact_digest
            ),
        )
    }

    fn display(&self) -> Vec<(String, String)> {
        vec![
            ("Environment".into(), self.environment.clone()),
            ("Region".into(), self.region.clone()),
            ("Operation".into(), self.operation.clone()),
            ("Artifact".into(), self.artifact_digest.clone()),
            ("Provenance".into(), self.provenance_digest.clone()),
            ("Configuration".into(), self.configuration_digest.clone()),
            ("Strategy".into(), self.strategy.clone()),
            (
                "Rollout window".into(),
                format!("{}..={}", self.rollout_not_before, self.rollout_expires_at),
            ),
            ("Blast radius".into(), self.blast_radius.to_string()),
        ]
    }

    fn budget(&self) -> Result<Option<BudgetCeiling>, ProfileContractError> {
        Ok(Some(BudgetCeiling::new(
            BudgetAlgebraId::parse("deploy-blast-radius-v1")
                .map_err(|_| ProfileContractError::MeaningMismatch)?,
            self.blast_radius,
        )))
    }
}

/// Closed canonical software-supply-chain action.
#[derive(Clone, Debug, PartialEq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainAction {
    profile: String,
    profile_version: u16,
    operation: String,
    subject_digest: String,
    predicate_type: String,
    builder: String,
}

impl SupplyChainAction {
    #[must_use]
    pub fn new(
        operation: String,
        subject_digest: String,
        predicate_type: String,
        builder: String,
    ) -> Self {
        Self {
            profile: "auths.supply-chain".into(),
            profile_version: 1,
            operation,
            subject_digest,
            predicate_type,
            builder,
        }
    }

    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }

    #[must_use]
    pub fn subject_digest(&self) -> &str {
        &self.subject_digest
    }

    #[must_use]
    pub fn predicate_type(&self) -> &str {
        &self.predicate_type
    }

    #[must_use]
    pub fn builder(&self) -> &str {
        &self.builder
    }
}

impl DomainMeaning for SupplyChainAction {
    const PROFILE_ID: &'static str = "auths.supply-chain";
    const MEDIA_TYPE: &'static str = "application/vnd.auths.supply-chain-action.v1+json";

    fn validate(&self) -> Result<(), ProfileContractError> {
        exact_profile(&self.profile, self.profile_version, Self::PROFILE_ID)?;
        if !matches!(
            self.operation.as_str(),
            "approve" | "attest" | "publish" | "release"
        ) || !digest(&self.subject_digest)
            || !token(&self.predicate_type, 256)
            || !token(&self.builder, 256)
        {
            return Err(ProfileContractError::MeaningMismatch);
        }
        Ok(())
    }

    fn permission(&self) -> Result<Permission, ProfileContractError> {
        permission(
            &format!("supply-chain/{}", self.operation),
            &format!("supply-chain://subjects/{}", self.subject_digest),
        )
    }

    fn display(&self) -> Vec<(String, String)> {
        vec![
            ("Operation".into(), self.operation.clone()),
            ("Subject".into(), self.subject_digest.clone()),
            ("Predicate".into(), self.predicate_type.clone()),
            ("Builder".into(), self.builder.clone()),
        ]
    }
}

/// Closed canonical edge-control action.
#[derive(Clone, Debug, PartialEq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeAction {
    profile: String,
    profile_version: u16,
    fleet: String,
    device: String,
    command: String,
    sequence: u64,
    state_digest: Option<String>,
}

impl EdgeAction {
    #[must_use]
    pub fn new(
        fleet: String,
        device: String,
        command: String,
        sequence: u64,
        state_digest: Option<String>,
    ) -> Self {
        Self {
            profile: "auths.edge".into(),
            profile_version: 1,
            fleet,
            device,
            command,
            sequence,
            state_digest,
        }
    }

    #[must_use]
    pub fn fleet(&self) -> &str {
        &self.fleet
    }

    #[must_use]
    pub fn device(&self) -> &str {
        &self.device
    }

    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub fn state_digest(&self) -> Option<&str> {
        self.state_digest.as_deref()
    }
}

impl DomainMeaning for EdgeAction {
    const PROFILE_ID: &'static str = "auths.edge";
    const MEDIA_TYPE: &'static str = "application/vnd.auths.edge-action.v1+json";

    fn validate(&self) -> Result<(), ProfileContractError> {
        exact_profile(&self.profile, self.profile_version, Self::PROFILE_ID)?;
        if !lower_token(&self.fleet, 128)
            || !lower_token(&self.device, 128)
            || !matches!(
                self.command.as_str(),
                "activate-firmware" | "apply-config" | "execute" | "restart"
            )
            || self.sequence == 0
            || self
                .state_digest
                .as_deref()
                .is_some_and(|value| !digest(value))
        {
            return Err(ProfileContractError::MeaningMismatch);
        }
        Ok(())
    }

    fn permission(&self) -> Result<Permission, ProfileContractError> {
        permission(
            &format!("edge/{}", self.command),
            &format!("edge://{}/devices/{}", self.fleet, self.device),
        )
    }

    fn display(&self) -> Vec<(String, String)> {
        vec![
            ("Fleet".into(), self.fleet.clone()),
            ("Device".into(), self.device.clone()),
            ("Command".into(), self.command.clone()),
            ("Sequence".into(), self.sequence.to_string()),
        ]
    }
}

pub type HttpProfile = DomainProfile<HttpAction>;
pub type HttpCommand = DomainCommand<HttpAction>;
pub type GitProfile = DomainProfile<GitAction>;
pub type GitCommand = DomainCommand<GitAction>;
pub type DeploymentProfile = DomainProfile<DeploymentAction>;
pub type DeploymentCommand = DomainCommand<DeploymentAction>;
pub type SupplyChainProfile = DomainProfile<SupplyChainAction>;
pub type SupplyChainCommand = DomainCommand<SupplyChainAction>;
pub type EdgeProfile = DomainProfile<EdgeAction>;
pub type EdgeCommand = DomainCommand<EdgeAction>;

/// Reference canonicalizer for the closed HTTP profile.
///
/// # Errors
///
/// Returns a closed profile failure for malformed, ambiguous, or unsupported
/// input.
pub fn reference_canonicalize_http(
    untrusted: &[u8],
) -> Result<CanonicalAction, ProfileContractError> {
    reference_canonicalize::<HttpAction>(untrusted)
}

/// Reference canonicalizer for the closed Git profile.
///
/// # Errors
///
/// Returns a closed profile failure for malformed, ambiguous, or unsupported
/// input.
pub fn reference_canonicalize_git(
    untrusted: &[u8],
) -> Result<CanonicalAction, ProfileContractError> {
    reference_canonicalize::<GitAction>(untrusted)
}

/// Reference canonicalizer for the closed deployment profile.
///
/// # Errors
///
/// Returns a closed profile failure for malformed, ambiguous, or unsupported
/// input.
pub fn reference_canonicalize_deployment(
    untrusted: &[u8],
) -> Result<CanonicalAction, ProfileContractError> {
    reference_canonicalize::<DeploymentAction>(untrusted)
}

/// Reference canonicalizer for the closed software-supply-chain profile.
///
/// # Errors
///
/// Returns a closed profile failure for malformed, ambiguous, or unsupported
/// input.
pub fn reference_canonicalize_supply_chain(
    untrusted: &[u8],
) -> Result<CanonicalAction, ProfileContractError> {
    reference_canonicalize::<SupplyChainAction>(untrusted)
}

/// Reference canonicalizer for the closed edge-control profile.
///
/// # Errors
///
/// Returns a closed profile failure for malformed, ambiguous, or unsupported
/// input.
pub fn reference_canonicalize_edge(
    untrusted: &[u8],
) -> Result<CanonicalAction, ProfileContractError> {
    reference_canonicalize::<EdgeAction>(untrusted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_reference_parity<T: DomainMeaning>(action: &T) {
        let bytes = serde_json::to_vec(action).unwrap();
        assert_eq!(
            DomainProfile::<T>::default().canonicalize(&bytes).unwrap(),
            reference_canonicalize::<T>(&bytes).unwrap()
        );
    }

    #[test]
    fn every_target_profile_derives_exact_meaning() {
        let digest = "11".repeat(32);
        let cases: Vec<Box<dyn Fn() -> Result<CanonicalAction, ProfileContractError>>> = vec![
            Box::new(|| {
                HttpProfile::default().canonicalize(
                    &serde_json::to_vec(&HttpAction::new(
                        "POST".into(),
                        "https".into(),
                        "api.example.com".into(),
                        "/v1/releases".into(),
                        BTreeMap::new(),
                        BTreeMap::new(),
                        Some("application/json".into()),
                        Some(digest.clone()),
                    ))
                    .unwrap(),
                )
            }),
            Box::new(|| {
                GitProfile::default().canonicalize(
                    &serde_json::to_vec(&GitAction::new(
                        "example/repository".into(),
                        "push".into(),
                        "heads/main".into(),
                        digest.clone(),
                    ))
                    .unwrap(),
                )
            }),
            Box::new(|| {
                DeploymentProfile::default().canonicalize(
                    &serde_json::to_vec(&DeploymentAction::new(
                        "production".into(),
                        "eu-west-1".into(),
                        "deploy".into(),
                        digest.clone(),
                        digest.clone(),
                        digest.clone(),
                        "canary".into(),
                        1_800_000_000,
                        1_800_003_600,
                        10,
                    ))
                    .unwrap(),
                )
            }),
            Box::new(|| {
                SupplyChainProfile::default().canonicalize(
                    &serde_json::to_vec(&SupplyChainAction::new(
                        "attest".into(),
                        digest.clone(),
                        "slsa-provenance".into(),
                        "builder/main".into(),
                    ))
                    .unwrap(),
                )
            }),
            Box::new(|| {
                EdgeProfile::default().canonicalize(
                    &serde_json::to_vec(&EdgeAction::new(
                        "fleet-a".into(),
                        "device-7".into(),
                        "restart".into(),
                        1,
                        Some(digest.clone()),
                    ))
                    .unwrap(),
                )
            }),
        ];
        for canonicalize in cases {
            let action = canonicalize().expect("valid target profile");
            assert_eq!(
                action.body(),
                serde_json_canonicalizer::to_vec(
                    &serde_json::from_slice::<serde_json::Value>(action.body()).unwrap()
                )
                .unwrap()
            );
        }
    }

    #[test]
    fn unknown_fields_and_noncanonical_bytes_fail_closed() {
        let input = br#"{"profile":"auths.git","profile_version":1,"repository":"example/repository","operation":"push","reference":"heads/main","object_id":"1111111111111111111111111111111111111111111111111111111111111111","extra":true}"#;
        assert_eq!(
            GitProfile::default().canonicalize(input),
            Err(ProfileContractError::Malformed)
        );
    }

    #[test]
    fn every_profile_matches_the_reference_canonicalizer() {
        let digest = "22".repeat(32);
        assert_reference_parity(&HttpAction::new(
            "POST".into(),
            "https".into(),
            "api.example.com".into(),
            "/v1/releases".into(),
            BTreeMap::new(),
            BTreeMap::new(),
            Some("application/json".into()),
            Some(digest.clone()),
        ));
        assert_reference_parity(&GitAction::new(
            "example/repository".into(),
            "push".into(),
            "heads/main".into(),
            digest.clone(),
        ));
        assert_reference_parity(&DeploymentAction::new(
            "production".into(),
            "eu-west-1".into(),
            "deploy".into(),
            digest.clone(),
            digest.clone(),
            digest.clone(),
            "canary".into(),
            1_800_000_000,
            1_800_003_600,
            10,
        ));
        assert_reference_parity(&SupplyChainAction::new(
            "attest".into(),
            digest.clone(),
            "slsa-provenance".into(),
            "builder/main".into(),
        ));
        assert_reference_parity(&EdgeAction::new(
            "fleet-a".into(),
            "device-7".into(),
            "restart".into(),
            1,
            Some(digest),
        ));
    }

    #[test]
    fn http_defaults_unicode_and_noncanonical_uri_forms_fail_closed() {
        let missing_scheme = br#"{"profile":"auths.http","profile_version":1,"method":"GET","authority":"api.example.com","path":"/v1","query":{},"headers":{},"content_type":null,"body_digest":null}"#;
        assert_eq!(
            HttpProfile::default().canonicalize(missing_scheme),
            Err(ProfileContractError::Malformed)
        );

        for action in [
            HttpAction::new(
                "GET".into(),
                "https".into(),
                "api.example.com:443".into(),
                "/v1".into(),
                BTreeMap::new(),
                BTreeMap::new(),
                None,
                None,
            ),
            HttpAction::new(
                "GET".into(),
                "https".into(),
                "API.example.com".into(),
                "/v1".into(),
                BTreeMap::new(),
                BTreeMap::new(),
                None,
                None,
            ),
            HttpAction::new(
                "GET".into(),
                "https".into(),
                "api.example.com".into(),
                "/résumé".into(),
                BTreeMap::new(),
                BTreeMap::new(),
                None,
                None,
            ),
            HttpAction::new(
                "GET".into(),
                "https".into(),
                "api.example.com".into(),
                "/v1/%2fadmin".into(),
                BTreeMap::new(),
                BTreeMap::new(),
                None,
                None,
            ),
        ] {
            assert_eq!(
                HttpProfile::default().canonicalize(&serde_json::to_vec(&action).unwrap()),
                Err(ProfileContractError::MeaningMismatch)
            );
        }
    }

    #[test]
    fn byte_distinct_http_queries_are_explicit_even_with_same_permission() {
        let mut first_query = BTreeMap::new();
        first_query.insert("page".into(), vec!["1".into()]);
        let mut second_query = BTreeMap::new();
        second_query.insert("page".into(), vec!["2".into()]);
        let first = HttpProfile::default()
            .canonicalize(
                &serde_json::to_vec(&HttpAction::new(
                    "GET".into(),
                    "https".into(),
                    "api.example.com".into(),
                    "/v1/items".into(),
                    first_query,
                    BTreeMap::new(),
                    None,
                    None,
                ))
                .unwrap(),
            )
            .unwrap();
        let second = HttpProfile::default()
            .canonicalize(
                &serde_json::to_vec(&HttpAction::new(
                    "GET".into(),
                    "https".into(),
                    "api.example.com".into(),
                    "/v1/items".into(),
                    second_query,
                    BTreeMap::new(),
                    None,
                    None,
                ))
                .unwrap(),
            )
            .unwrap();
        assert_eq!(first.permission(), second.permission());
        assert_ne!(first.body(), second.body());
    }

    #[test]
    fn git_ref_normalization_and_unicode_identifiers_fail_closed() {
        let digest = "33".repeat(32);
        for action in [
            GitAction::new(
                "Example/repository".into(),
                "push".into(),
                "heads/main".into(),
                digest.clone(),
            ),
            GitAction::new(
                "example/répository".into(),
                "push".into(),
                "heads/main".into(),
                digest.clone(),
            ),
            GitAction::new(
                "example/repository".into(),
                "push".into(),
                "heads/../admin".into(),
                digest.clone(),
            ),
        ] {
            assert_eq!(
                GitProfile::default().canonicalize(&serde_json::to_vec(&action).unwrap()),
                Err(ProfileContractError::MeaningMismatch)
            );
        }
    }
}
