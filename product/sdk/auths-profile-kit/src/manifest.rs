use crate::{ProfileApi, ProfileApiError, ProfileType};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const MAX_MANIFEST_BYTES: usize = 262_144;
const ABSOLUTE_LOCAL_REQUEST_BYTES: usize = 33_554_432;
const PREPARE_ENVELOPE_OVERHEAD_BYTES: usize = 512;
const ERROR_ENVELOPE_BYTES: usize = 65_536;
const OUTCOME_ENVELOPE_OVERHEAD_BYTES: usize = 4_096;

/// Complete profile-package manifest for one domain.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilePackage {
    schema: String,
    domain: DomainManifest,
    api: String,
    qualification: QualificationManifest,
    profiles: Vec<ProfileManifest>,
}

/// Shared live-qualification declaration for one atomic domain family.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationManifest {
    family: Vec<String>,
    adapter: String,
    targets: Vec<crate::QualificationTarget>,
    protected_environment: String,
    common_scenarios: String,
    domain_scenarios: String,
    requirements: String,
    provider_matrix: String,
    operation_plans: String,
    failpoint_coverage: String,
    provider_truth_schema: String,
    profile_state_snapshot: String,
}

/// Generated distribution names and optional provider-connection contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DomainManifest {
    id: String,
    client_class: String,
    rust_package: String,
    typescript_package: String,
    python_distribution: String,
    python_module: String,
    connection: Option<ConnectionContract>,
}

/// One provider connection contract shared by a domain package.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionContract {
    provider_kind: String,
    contract: String,
    descriptor_schema: String,
    sources: ConnectionSources,
    evidence: ConnectionEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConnectionSources {
    specification: String,
    descriptor: String,
    onboarding: String,
    credentials: String,
    admin_routes: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConnectionEvidence {
    fixtures: String,
    conformance: String,
}

/// One exact profile operation and its evidence inventory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileManifest {
    id: String,
    version: u16,
    semantic_subject: String,
    effect_id: String,
    client: ProfileClient,
    contracts: ProfileContracts,
    limits: ProfileLimits,
    sources: ProfileSources,
    evidence: ProfileEvidence,
}

/// Generated client navigation and role types.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileClient {
    group: String,
    method: String,
    input_type: String,
    success_type: String,
    partial_type: Option<String>,
    progress_type: Option<String>,
}

/// Exact immutable semantic contracts used by the profile.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileContracts {
    canonical_action: String,
    evaluator: String,
    lifecycle: String,
    provider: String,
    receipt: String,
    credential_scope: Option<String>,
    configuration_format: Option<String>,
    preparation_evidence: Option<String>,
    error_owner: String,
    error_owner_version: u16,
}

/// Per-profile hard bounds included in runtime negotiation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileLimits {
    request_bytes: usize,
    response_bytes: usize,
    receipt_count: usize,
    receipt_bytes: usize,
    execution_milliseconds: u64,
    admissions_per_minute: u32,
    active_per_principal: u16,
    unresolved_per_principal: u16,
    durable_bytes_per_principal: u64,
    tombstones_per_principal: u32,
    terminal_retention_seconds: u64,
    idempotency_retention_seconds: u64,
}

/// Concrete vertical implementation sources.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileSources {
    specification: String,
    action: String,
    evaluator: String,
    command: String,
    lifecycle: String,
    gateway: String,
    reconciliation: String,
    receipt: String,
    errors: String,
    error_mapping: String,
}

/// Exact profile qualification evidence paths.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileEvidence {
    fixtures: String,
    mutation_corpus: String,
    provider_requests: String,
    demo: String,
    live_contract: String,
}

impl ProfilePackage {
    /// Parses and validates a manifest together with its restricted API.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed JSON, invalid naming, unsafe paths,
    /// missing API role types, inconsistent connection scope, or invalid bounds.
    pub fn from_json(bytes: &[u8], api: &ProfileApi) -> Result<Self, ProfilePackageError> {
        if bytes.is_empty() || bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ProfilePackageError::Limit);
        }
        let manifest: Self =
            serde_json::from_slice(bytes).map_err(|_| ProfilePackageError::Malformed)?;
        manifest.validate(api)?;
        Ok(manifest)
    }

    /// Validates every cross-field invariant in the package contract.
    ///
    /// # Errors
    ///
    /// Returns [`ProfilePackageError`] for invalid package identity, paths,
    /// connection declarations, profile roles, bounds, or ordering.
    pub fn validate(&self, api: &ProfileApi) -> Result<(), ProfilePackageError> {
        if self.schema != "auths.profile-package/1"
            || !lower_token(&self.domain.id)
            || !public_class_name(&self.domain.client_class)
            || self.domain.rust_package != format!("auths-{}", self.domain.id)
            || self.domain.typescript_package != format!("@auths-dev/profile-{}", self.domain.id)
            || self.domain.python_distribution != format!("auths-profile-{}", self.domain.id)
            || self.domain.python_module
                != format!("auths_profiles.{}", self.domain.id.replace('-', "_"))
            || !safe_path(&self.api)
            || self.profiles.is_empty()
            || self.profiles.len() > 32
        {
            return Err(ProfilePackageError::InvalidDomain);
        }
        if let Some(connection) = &self.domain.connection {
            connection.validate()?;
        }
        let mut identities = BTreeSet::new();
        let mut effects = BTreeSet::new();
        let mut methods = BTreeSet::new();
        let mut previous: Option<(&str, u16)> = None;
        for profile in &self.profiles {
            profile.validate(&self.domain, api)?;
            let identity = (profile.id.as_str(), profile.version);
            if previous.is_some_and(|value| value >= identity)
                || !identities.insert(identity)
                || !effects.insert(profile.effect_id.as_str())
                || !methods.insert((
                    profile.client.group.as_str(),
                    profile.client.method.as_str(),
                ))
            {
                return Err(ProfilePackageError::DuplicateOrUnsorted);
            }
            previous = Some(identity);
        }
        self.qualification.validate(&self.domain, &self.profiles)?;
        Ok(())
    }

    /// Computes SHA-256 over canonical compact JSON for the complete manifest.
    ///
    /// # Errors
    ///
    /// Returns [`ProfilePackageError::Malformed`] when the validated manifest
    /// cannot be projected to canonical JSON.
    pub fn package_manifest_digest(&self) -> Result<[u8; 32], ProfilePackageError> {
        digest_json(serde_json::to_value(self).map_err(|_| ProfilePackageError::Malformed)?)
    }

    /// Computes the immutable negotiated runtime projection for one profile.
    ///
    /// # Errors
    ///
    /// Returns [`ProfilePackageError`] for an unknown profile, an invalid API
    /// role closure, or a projection that cannot be canonically encoded.
    pub fn runtime_contract_digest(
        &self,
        profile_id: &str,
        version: u16,
        api: &ProfileApi,
        error_projection_digest: [u8; 32],
    ) -> Result<[u8; 32], ProfilePackageError> {
        let profile = self
            .profiles
            .iter()
            .find(|candidate| candidate.id == profile_id && candidate.version == version)
            .ok_or(ProfilePackageError::UnknownProfile)?;
        let roles = [
            Some(profile.client.input_type.as_str()),
            Some(profile.client.success_type.as_str()),
            profile.client.partial_type.as_deref(),
            profile.client.progress_type.as_deref(),
        ];
        let reachable: BTreeMap<String, ProfileType> =
            api.reachable_types(roles.into_iter().flatten())?;
        let connection = self.domain.connection.as_ref().map(|value| {
            json!({
                "providerKind": value.provider_kind,
                "contract": value.contract,
                "descriptorSchema": value.descriptor_schema,
            })
        });
        let projection = json!({
            "schema": "auths.profile-runtime-contract/1",
            "profile": {
                "id": profile.id,
                "version": profile.version,
                "semanticSubject": profile.semantic_subject,
                "effectId": profile.effect_id,
            },
            "connection": connection,
            "operationProtocol": "auths.profile-operation/1",
            "api": {
                "schema": "auths.profile-api/1",
                "inputType": profile.client.input_type,
                "successType": profile.client.success_type,
                "partialType": profile.client.partial_type,
                "progressType": profile.client.progress_type,
                "reachableTypes": reachable,
            },
            "contracts": {
                "canonicalAction": profile.contracts.canonical_action,
                "evaluator": profile.contracts.evaluator,
                "lifecycle": profile.contracts.lifecycle,
                "provider": profile.contracts.provider,
                "receipt": profile.contracts.receipt,
                "credentialScope": profile.contracts.credential_scope,
                "configurationFormat": profile.contracts.configuration_format,
                "preparationEvidence": profile.contracts.preparation_evidence,
                "errorOwner": profile.contracts.error_owner,
                "errorOwnerVersion": profile.contracts.error_owner_version,
                "errorProjectionDigest": hex::encode(error_projection_digest),
            },
            "limits": profile.limits,
        });
        digest_json(projection)
    }

    #[must_use]
    pub const fn domain(&self) -> &DomainManifest {
        &self.domain
    }

    #[must_use]
    pub fn profiles(&self) -> &[ProfileManifest] {
        &self.profiles
    }

    /// Returns the atomic live-qualification declaration.
    #[must_use]
    pub const fn qualification(&self) -> &QualificationManifest {
        &self.qualification
    }
}

impl QualificationManifest {
    fn validate(
        &self,
        domain: &DomainManifest,
        profiles: &[ProfileManifest],
    ) -> Result<(), ProfilePackageError> {
        let expected = profiles
            .iter()
            .map(|profile| profile.semantic_subject.as_str())
            .collect::<Vec<_>>();
        let mut previous = None;
        if self.family.iter().map(String::as_str).collect::<Vec<_>>() != expected
            || self.adapter != domain.id
            || self.targets.is_empty()
            || self.targets.len() > 4
            || self.protected_environment != format!("qualification-{}", domain.id)
            || self.common_scenarios != "auths.profile-qualification-common/1"
            || !safe_path(&self.domain_scenarios)
            || !safe_path(&self.requirements)
            || !safe_path(&self.provider_matrix)
            || !safe_path(&self.operation_plans)
            || !safe_path(&self.failpoint_coverage)
            || !safe_path(&self.provider_truth_schema)
            || !safe_path(&self.profile_state_snapshot)
        {
            return Err(ProfilePackageError::InvalidQualification);
        }
        for target in &self.targets {
            if previous.is_some_and(|value| value >= *target) {
                return Err(ProfilePackageError::InvalidQualification);
            }
            previous = Some(*target);
        }
        Ok(())
    }

    /// Returns the exact byte-sorted profile family.
    #[must_use]
    pub fn family(&self) -> &[String] {
        &self.family
    }

    /// Returns the statically registered qualification adapter ID.
    #[must_use]
    pub fn adapter(&self) -> &str {
        &self.adapter
    }

    /// Returns the exact intended qualification targets.
    #[must_use]
    pub fn targets(&self) -> &[crate::QualificationTarget] {
        &self.targets
    }

    /// Returns the protected GitHub environment name.
    #[must_use]
    pub fn protected_environment(&self) -> &str {
        &self.protected_environment
    }

    /// Returns the domain-owned canonical scenario manifest path.
    #[must_use]
    pub fn domain_scenarios(&self) -> &str {
        &self.domain_scenarios
    }

    /// Returns the exact requirement-to-evidence inventory path.
    #[must_use]
    pub fn requirements(&self) -> &str {
        &self.requirements
    }

    /// Returns the exact protected provider-version matrix path.
    #[must_use]
    pub fn provider_matrix(&self) -> &str {
        &self.provider_matrix
    }

    /// Returns the exact reviewed scenario-to-operation workflow plan.
    #[must_use]
    pub fn operation_plans(&self) -> &str {
        &self.operation_plans
    }

    /// Returns the exact qualification-only failpoint coverage path.
    #[must_use]
    pub fn failpoint_coverage(&self) -> &str {
        &self.failpoint_coverage
    }

    /// Returns the domain-owned closed provider-truth schema path.
    #[must_use]
    pub fn provider_truth_schema(&self) -> &str {
        &self.provider_truth_schema
    }

    /// Returns the fixed, domain-owned protected profile-state snapshot path.
    #[must_use]
    pub fn profile_state_snapshot(&self) -> &str {
        &self.profile_state_snapshot
    }
}

impl DomainManifest {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the manifest-owned public class name used in generated SDKs.
    #[must_use]
    pub fn client_class(&self) -> &str {
        &self.client_class
    }

    /// Returns the manifest-owned generated Python import path.
    #[must_use]
    pub fn python_module(&self) -> &str {
        &self.python_module
    }

    #[must_use]
    pub const fn connection(&self) -> Option<&ConnectionContract> {
        self.connection.as_ref()
    }
}

impl ConnectionContract {
    fn validate(&self) -> Result<(), ProfilePackageError> {
        if !lower_token(&self.provider_kind)
            || !semantic_id(&self.contract)
            || !semantic_id(&self.descriptor_schema)
            || !self.sources.paths().into_iter().all(safe_path)
            || !self.evidence.paths().into_iter().all(safe_path)
        {
            return Err(ProfilePackageError::InvalidConnection);
        }
        Ok(())
    }

    #[must_use]
    pub fn provider_kind(&self) -> &str {
        &self.provider_kind
    }

    #[must_use]
    pub fn contract(&self) -> &str {
        &self.contract
    }

    #[must_use]
    pub fn descriptor_schema(&self) -> &str {
        &self.descriptor_schema
    }
}

impl ConnectionSources {
    fn paths(&self) -> [&str; 5] {
        [
            &self.specification,
            &self.descriptor,
            &self.onboarding,
            &self.credentials,
            &self.admin_routes,
        ]
    }
}

impl ConnectionEvidence {
    fn paths(&self) -> [&str; 2] {
        [&self.fixtures, &self.conformance]
    }
}

impl ProfileManifest {
    fn validate(
        &self,
        domain: &DomainManifest,
        api: &ProfileApi,
    ) -> Result<(), ProfilePackageError> {
        let prefix = format!("auths.{}.", domain.id);
        if !self.id.starts_with(&prefix)
            || self.id.len() > 128
            || self.version == 0
            || self.semantic_subject != format!("{}/{}", self.id, self.version)
            || !semantic_id(&self.effect_id)
            || !lower_token(&self.client.group)
            || !lower_token(&self.client.method)
            || !self
                .client
                .role_types()
                .into_iter()
                .flatten()
                .all(type_name)
            || !self
                .client
                .role_types()
                .into_iter()
                .flatten()
                .all(|name| api.get(name).is_some())
        {
            return Err(ProfilePackageError::InvalidProfile);
        }
        self.contracts.validate(domain.connection.is_some())?;
        self.limits.validate()?;
        self.validate_encoded_sizes(api)?;
        if !self.sources.paths().into_iter().all(safe_path)
            || !self.evidence.paths().into_iter().all(safe_path)
        {
            return Err(ProfilePackageError::UnsafePath);
        }
        api.reachable_types(self.client.role_types().into_iter().flatten())?;
        Ok(())
    }

    fn validate_encoded_sizes(&self, api: &ProfileApi) -> Result<(), ProfilePackageError> {
        let input = api.maximum_encoded_size(&self.client.input_type)?;
        if input > self.limits.request_bytes
            || input
                .checked_add(PREPARE_ENVELOPE_OVERHEAD_BYTES)
                .is_none_or(|value| value > ABSOLUTE_LOCAL_REQUEST_BYTES)
        {
            return Err(ProfilePackageError::InvalidLimits);
        }
        let mut maximum_body = api.maximum_encoded_size(&self.client.success_type)?;
        for optional in [&self.client.partial_type, &self.client.progress_type]
            .into_iter()
            .flatten()
        {
            maximum_body = maximum_body.max(api.maximum_encoded_size(optional)?);
        }
        let maximum_response = maximum_body
            .checked_add(self.limits.receipt_bytes)
            .and_then(|value| value.checked_add(ERROR_ENVELOPE_BYTES))
            .and_then(|value| value.checked_add(OUTCOME_ENVELOPE_OVERHEAD_BYTES))
            .ok_or(ProfilePackageError::InvalidLimits)?;
        if maximum_response > self.limits.response_bytes {
            return Err(ProfilePackageError::InvalidLimits);
        }
        Ok(())
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    #[must_use]
    pub const fn client(&self) -> &ProfileClient {
        &self.client
    }

    /// Returns the manifest-owned credential scope for this connected
    /// profile, if the domain has a provider connection.
    #[must_use]
    pub fn credential_scope(&self) -> Option<&str> {
        self.contracts.credential_scope.as_deref()
    }
}

impl ProfileClient {
    fn role_types(&self) -> [Option<&str>; 4] {
        [
            Some(&self.input_type),
            Some(&self.success_type),
            self.partial_type.as_deref(),
            self.progress_type.as_deref(),
        ]
    }

    #[must_use]
    pub fn group(&self) -> &str {
        &self.group
    }

    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    #[must_use]
    pub fn input_type(&self) -> &str {
        &self.input_type
    }

    #[must_use]
    pub fn success_type(&self) -> &str {
        &self.success_type
    }
}

impl ProfileContracts {
    fn validate(&self, connected: bool) -> Result<(), ProfilePackageError> {
        if ![
            self.canonical_action.as_str(),
            self.evaluator.as_str(),
            self.lifecycle.as_str(),
            self.provider.as_str(),
            self.receipt.as_str(),
        ]
        .into_iter()
        .all(semantic_id)
            || self
                .credential_scope
                .as_deref()
                .is_some_and(|value| !semantic_id(value))
            || self
                .configuration_format
                .as_deref()
                .is_some_and(|value| !semantic_id(value))
            || self
                .preparation_evidence
                .as_deref()
                .is_some_and(|value| value != "protected-lease")
            || (self.preparation_evidence.is_some()
                && (!connected || self.configuration_format.is_none()))
            || connected != self.credential_scope.is_some()
            || !lower_token(&self.error_owner)
            || self.error_owner_version == 0
        {
            return Err(ProfilePackageError::InvalidContract);
        }
        Ok(())
    }
}

impl ProfileLimits {
    fn validate(&self) -> Result<(), ProfilePackageError> {
        if !(1..=25_165_824).contains(&self.request_bytes)
            || !(1..=16_777_216).contains(&self.response_bytes)
            || !(1..=16).contains(&self.receipt_count)
            || !(1..=8_388_608).contains(&self.receipt_bytes)
            || self.receipt_bytes > self.response_bytes
            || !(1..=300_000).contains(&self.execution_milliseconds)
            || !(1..=10_000).contains(&self.admissions_per_minute)
            || !(1..=1_024).contains(&self.active_per_principal)
            || self.unresolved_per_principal == 0
            || self.unresolved_per_principal > 256
            || self.unresolved_per_principal > self.active_per_principal
            || !(1_048_576..=1_073_741_824).contains(&self.durable_bytes_per_principal)
            || !(1_024..=1_000_000).contains(&self.tombstones_per_principal)
            || !(604_800..=31_536_000).contains(&self.terminal_retention_seconds)
            || !(604_800..=315_360_000).contains(&self.idempotency_retention_seconds)
            || self.idempotency_retention_seconds < self.terminal_retention_seconds
        {
            return Err(ProfilePackageError::InvalidLimits);
        }
        Ok(())
    }
}

impl ProfileSources {
    fn paths(&self) -> [&str; 10] {
        [
            &self.specification,
            &self.action,
            &self.evaluator,
            &self.command,
            &self.lifecycle,
            &self.gateway,
            &self.reconciliation,
            &self.receipt,
            &self.errors,
            &self.error_mapping,
        ]
    }
}

impl ProfileEvidence {
    fn paths(&self) -> [&str; 5] {
        [
            &self.fixtures,
            &self.mutation_corpus,
            &self.provider_requests,
            &self.demo,
            &self.live_contract,
        ]
    }
}

fn digest_json(value: Value) -> Result<[u8; 32], ProfilePackageError> {
    let canonical = canonical_json(value);
    let bytes = serde_json::to_vec(&canonical).map_err(|_| ProfilePackageError::Malformed)?;
    Ok(Sha256::digest(bytes).into())
}

fn canonical_json(value: Value) -> Value {
    match value {
        Value::Object(values) => {
            let sorted: BTreeMap<_, _> = values
                .into_iter()
                .map(|(key, value)| (key, canonical_json(value)))
                .collect();
            let map: Map<_, _> = sorted.into_iter().collect();
            Value::Object(map)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonical_json).collect()),
        other => other,
    }
}

pub(crate) fn lower_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn type_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_uppercase()
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

pub(crate) fn semantic_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

pub(crate) fn safe_path(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 256
        || value.starts_with('/')
        || value.starts_with('\\')
        || value.contains('\\')
        || value.contains('\0')
    {
        return false;
    }
    value
        .split('/')
        .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn public_class_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_uppercase)
        && bytes.iter().all(u8::is_ascii_alphanumeric)
}

/// Closed profile-package validation error.
#[derive(Debug, Error)]
pub enum ProfilePackageError {
    #[error("profile package exceeds a hard limit")]
    Limit,
    #[error("profile package JSON is malformed")]
    Malformed,
    #[error("profile package domain is invalid")]
    InvalidDomain,
    #[error("profile package connection contract is invalid")]
    InvalidConnection,
    #[error("profile package profile is invalid")]
    InvalidProfile,
    #[error("profile package contracts are invalid")]
    InvalidContract,
    #[error("profile package limits are invalid")]
    InvalidLimits,
    #[error("profile package contains an unsafe path")]
    UnsafePath,
    #[error("profile package profiles are duplicate or unsorted")]
    DuplicateOrUnsorted,
    #[error("profile package qualification declaration is invalid")]
    InvalidQualification,
    #[error("profile is not in the package")]
    UnknownProfile,
    #[error("profile API is invalid: {0}")]
    Api(#[from] ProfileApiError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api() -> ProfileApi {
        ProfileApi::from_json(
            br#"{"schema":"auths.profile-api/1","types":{"Refund":{"kind":"record","fields":[{"name":"id","value":{"kind":"string","minimumBytes":1,"maximumBytes":64,"alphabet":"registered-token"},"sensitive":false}]},"RefundInput":{"kind":"record","fields":[{"name":"amount","value":{"kind":"uint","bits":64,"minimum":"1","maximum":"1000000"},"sensitive":false}]}}}"#,
        )
        .unwrap()
    }

    fn manifest() -> Vec<u8> {
        br#"{"schema":"auths.profile-package/1","domain":{"id":"stripe","clientClass":"Stripe","rustPackage":"auths-stripe","typescriptPackage":"@auths-dev/profile-stripe","pythonDistribution":"auths-profile-stripe","pythonModule":"auths_profiles.stripe","connection":{"providerKind":"stripe","contract":"auths.stripe.connection/1","descriptorSchema":"auths.stripe.connection-descriptor/1","sources":{"specification":"docs/specs/stripe.md","descriptor":"src/connection/descriptor.rs","onboarding":"src/connection/onboarding.rs","credentials":"src/connection/credentials.rs","adminRoutes":"src/connection/admin_routes.rs"},"evidence":{"fixtures":"fixtures/connection/v1","conformance":"tests/connection.rs"}}},"api":"api/profile-api.json","qualification":{"family":["auths.stripe.refund/1"],"adapter":"stripe","targets":["linux-x86_64"],"protectedEnvironment":"qualification-stripe","commonScenarios":"auths.profile-qualification-common/1","domainScenarios":"qualification/scenarios-v1.json","requirements":"qualification/requirements-v1.json","providerMatrix":"qualification/provider-matrix-v1.json","operationPlans":"qualification/operation-plans-v1.json","failpointCoverage":"qualification/failpoint-coverage-v1.json","providerTruthSchema":"qualification/provider-truth-v1.schema.json","profileStateSnapshot":"profiles/stripe-refund-reservations-v1/state.json"},"profiles":[{"id":"auths.stripe.refund","version":1,"semanticSubject":"auths.stripe.refund/1","effectId":"stripe.refund.create","client":{"group":"refunds","method":"create","inputType":"RefundInput","successType":"Refund","partialType":null,"progressType":null},"contracts":{"canonicalAction":"auths.stripe.refund-action/1","evaluator":"auths.stripe.refund-evaluator/1","lifecycle":"auths.stripe.refund-lifecycle/1","provider":"auths.stripe.refund-provider/1","receipt":"auths.stripe.refund-receipt/1","credentialScope":"stripe.refunds.write/1","errorOwner":"stripe-refund","errorOwnerVersion":1},"limits":{"requestBytes":262144,"responseBytes":262144,"receiptCount":4,"receiptBytes":65536,"executionMilliseconds":30000,"admissionsPerMinute":600,"activePerPrincipal":64,"unresolvedPerPrincipal":16,"durableBytesPerPrincipal":67108864,"tombstonesPerPrincipal":100000,"terminalRetentionSeconds":2592000,"idempotencyRetentionSeconds":2592000},"sources":{"specification":"docs/specs/refund.md","action":"src/refund/action.rs","evaluator":"src/refund/evaluator.rs","command":"src/refund/command.rs","lifecycle":"src/refund/lifecycle.rs","gateway":"src/refund/gateway.rs","reconciliation":"src/refund/reconciliation.rs","receipt":"src/refund/receipt.rs","errors":"errors/refund-v1.json","errorMapping":"src/refund/errors.rs"},"evidence":{"fixtures":"fixtures/refund/v1","mutationCorpus":"tests/mutations.rs","providerRequests":"fixtures/refund/provider","demo":"demos/stripe-refund","liveContract":"demos/stripe-refund/tests/live.mjs"}}]}"#.to_vec()
    }

    #[test]
    fn manifest_and_runtime_digest_are_deterministic() {
        let api = api();
        let package = ProfilePackage::from_json(&manifest(), &api).unwrap();
        assert_eq!(package.domain().client_class(), "Stripe");
        assert_eq!(
            package.package_manifest_digest().unwrap(),
            package.package_manifest_digest().unwrap()
        );
        assert_eq!(
            package
                .runtime_contract_digest("auths.stripe.refund", 1, &api, [7; 32])
                .unwrap(),
            package
                .runtime_contract_digest("auths.stripe.refund", 1, &api, [7; 32])
                .unwrap(),
        );
    }

    #[test]
    fn connected_profile_requires_a_scope() {
        let api = api();
        let source = String::from_utf8(manifest()).unwrap().replace(
            "\"credentialScope\":\"stripe.refunds.write/1\"",
            "\"credentialScope\":null",
        );
        assert!(ProfilePackage::from_json(source.as_bytes(), &api).is_err());
    }

    #[test]
    fn public_client_class_is_manifest_owned_and_closed() {
        let api = api();
        for invalid in ["stripe", "Postgre_SQL", "Open-Tofu", "9Stripe", ""] {
            let source = String::from_utf8(manifest()).unwrap().replace(
                "\"clientClass\":\"Stripe\"",
                &format!("\"clientClass\":\"{invalid}\""),
            );
            assert!(ProfilePackage::from_json(source.as_bytes(), &api).is_err());
        }
    }
}
