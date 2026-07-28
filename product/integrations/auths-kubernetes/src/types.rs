//! Closed Kubernetes rollout action, evidence, configuration, and result types.

use std::{collections::BTreeMap, fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize};

use crate::canonical::{CanonicalError, canonical_digest, canonical_json, sha256};

/// Exact profile identifier.
pub const PROFILE_ID: &str = "auths.kubernetes.workload-rollout";
/// Exact profile version.
pub const PROFILE_VERSION: u16 = 1;
/// Exact rollout capability.
pub const ROLLOUT_CAPABILITY: &str = "kubernetes.deployment/apply";
/// Canonical media type.
pub const MEDIA_TYPE: &str = "application/vnd.auths.kubernetes.workload-rollout.v1+json";
/// Server-side apply media type.
pub const APPLY_MEDIA_TYPE: &str = "application/apply-patch+yaml";
/// Maximum accepted canonical action size.
pub const MAX_ACTION_BYTES: usize = 64 * 1024;
/// Hard evidence age ceiling.
pub const HARD_MAX_EVIDENCE_AGE_SECONDS: u64 = 15 * 60;
/// Hard authorization lifetime ceiling.
pub const HARD_MAX_AUTHORIZATION_LIFETIME_SECONDS: u64 = 60 * 60;

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn valid_uid(value: &str) -> bool {
    (8..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

macro_rules! validated_string {
    ($name:ident, $error:ident, $validator:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Parses one closed identifier.
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

validated_string!(DigestHex, Digest, valid_digest);
validated_string!(KubernetesName, Name, valid_dns_name);
validated_string!(KubernetesUid, Uid, valid_uid);

impl DigestHex {
    /// Constructs a lowercase digest from SHA-256 bytes.
    #[must_use]
    pub fn from_digest_bytes(bytes: [u8; 32]) -> Self {
        Self(hex::encode(bytes))
    }
}

/// Closed identifier parsing error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TypeError {
    /// Invalid lowercase SHA-256 digest.
    #[error("invalid lowercase SHA-256 digest")]
    Digest,
    /// Invalid Kubernetes DNS name.
    #[error("invalid Kubernetes DNS name")]
    Name,
    /// Invalid Kubernetes UID.
    #[error("invalid Kubernetes UID")]
    Uid,
}

/// Immutable container image reference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ImageDigestRef(String);

impl ImageDigestRef {
    /// Parses `registry/repository@sha256:<digest>`.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        let Some((repository, digest)) = value.rsplit_once("@sha256:") else {
            return Err(ValidationError::MutableImageReference);
        };
        if repository.is_empty()
            || repository.len() > 512
            || repository.bytes().any(|byte| byte.is_ascii_whitespace())
            || !valid_digest(digest)
        {
            return Err(ValidationError::MutableImageReference);
        }
        Ok(Self(value))
    }

    /// Returns the complete immutable reference.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Admission assumptions bound into verifier policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdmissionMode {
    /// Pinned demonstration namespace without applicable mutating webhooks.
    DeterministicDemo,
    /// Inventoried production admission behavior.
    ObservedProduction,
}

/// Verifier configuration demanded by the proof and loaded by the executor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesVerifierConfiguration {
    profile: String,
    canonicalization_version: String,
    cluster_audience: String,
    allowed_namespaces: Vec<KubernetesName>,
    allowed_deployments: Vec<KubernetesName>,
    allowed_container_names: Vec<KubernetesName>,
    minimum_replicas: u32,
    maximum_replicas: u32,
    allowed_annotation_keys: Vec<String>,
    maximum_evidence_age_seconds: u64,
    maximum_authorization_lifetime_seconds: u64,
    field_manager: String,
    permitted_api_versions: Vec<String>,
    permitted_resource_kinds: Vec<String>,
    admission_mode: AdmissionMode,
    receipt_schema_version: String,
    executor_audience: String,
}

/// Input for a validated verifier configuration.
pub struct KubernetesVerifierConfigurationInput {
    pub cluster_audience: String,
    pub allowed_namespaces: Vec<KubernetesName>,
    pub allowed_deployments: Vec<KubernetesName>,
    pub allowed_container_names: Vec<KubernetesName>,
    pub minimum_replicas: u32,
    pub maximum_replicas: u32,
    pub allowed_annotation_keys: Vec<String>,
    pub maximum_evidence_age_seconds: u64,
    pub maximum_authorization_lifetime_seconds: u64,
    pub field_manager: String,
    pub permitted_api_versions: Vec<String>,
    pub permitted_resource_kinds: Vec<String>,
    pub admission_mode: AdmissionMode,
    pub receipt_schema_version: String,
    pub executor_audience: String,
}

impl KubernetesVerifierConfiguration {
    /// Builds a validated, canonically ordered configuration.
    pub fn new(mut input: KubernetesVerifierConfigurationInput) -> Result<Self, ValidationError> {
        input.allowed_namespaces.sort();
        input.allowed_namespaces.dedup();
        input.allowed_deployments.sort();
        input.allowed_deployments.dedup();
        input.allowed_container_names.sort();
        input.allowed_container_names.dedup();
        input.allowed_annotation_keys.sort();
        input.allowed_annotation_keys.dedup();
        input.permitted_api_versions.sort();
        input.permitted_api_versions.dedup();
        input.permitted_resource_kinds.sort();
        input.permitted_resource_kinds.dedup();
        let configuration = Self {
            profile: format!("{PROFILE_ID}/{PROFILE_VERSION}"),
            canonicalization_version: "rfc8785-sha256-v1".into(),
            cluster_audience: input.cluster_audience,
            allowed_namespaces: input.allowed_namespaces,
            allowed_deployments: input.allowed_deployments,
            allowed_container_names: input.allowed_container_names,
            minimum_replicas: input.minimum_replicas,
            maximum_replicas: input.maximum_replicas,
            allowed_annotation_keys: input.allowed_annotation_keys,
            maximum_evidence_age_seconds: input.maximum_evidence_age_seconds,
            maximum_authorization_lifetime_seconds: input.maximum_authorization_lifetime_seconds,
            field_manager: input.field_manager,
            permitted_api_versions: input.permitted_api_versions,
            permitted_resource_kinds: input.permitted_resource_kinds,
            admission_mode: input.admission_mode,
            receipt_schema_version: input.receipt_schema_version,
            executor_audience: input.executor_audience,
        };
        configuration.validate()?;
        Ok(configuration)
    }

    /// Validates hard ceilings and closed allowlists.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.profile != format!("{PROFILE_ID}/{PROFILE_VERSION}")
            || self.canonicalization_version != "rfc8785-sha256-v1"
            || self.cluster_audience.is_empty()
            || self.allowed_namespaces.is_empty()
            || self.allowed_deployments.is_empty()
            || self.allowed_container_names.is_empty()
            || self.minimum_replicas == 0
            || self.minimum_replicas > self.maximum_replicas
            || self.maximum_replicas > 20
            || !(1..=HARD_MAX_EVIDENCE_AGE_SECONDS).contains(&self.maximum_evidence_age_seconds)
            || !(1..=HARD_MAX_AUTHORIZATION_LIFETIME_SECONDS)
                .contains(&self.maximum_authorization_lifetime_seconds)
            || self.field_manager != "auths-workload-rollout"
            || self.permitted_api_versions != ["apps/v1"]
            || self.permitted_resource_kinds != ["Deployment"]
            || self.receipt_schema_version != "auths.kubernetes.receipt/1"
            || self.executor_audience.is_empty()
            || self
                .allowed_annotation_keys
                .iter()
                .any(|key| !valid_annotation_key(key))
        {
            return Err(ValidationError::InvalidConfiguration);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
    #[must_use]
    pub fn cluster_audience(&self) -> &str {
        &self.cluster_audience
    }
    #[must_use]
    pub fn executor_audience(&self) -> &str {
        &self.executor_audience
    }
    #[must_use]
    pub fn field_manager(&self) -> &str {
        &self.field_manager
    }
    #[must_use]
    pub const fn minimum_replicas(&self) -> u32 {
        self.minimum_replicas
    }
    #[must_use]
    pub const fn maximum_replicas(&self) -> u32 {
        self.maximum_replicas
    }
    #[must_use]
    pub const fn maximum_evidence_age_seconds(&self) -> u64 {
        self.maximum_evidence_age_seconds
    }
    #[must_use]
    pub const fn maximum_authorization_lifetime_seconds(&self) -> u64 {
        self.maximum_authorization_lifetime_seconds
    }
    #[must_use]
    pub fn receipt_schema_version(&self) -> &str {
        &self.receipt_schema_version
    }
    #[must_use]
    pub const fn admission_mode(&self) -> AdmissionMode {
        self.admission_mode
    }
    #[must_use]
    pub fn allows_namespace(&self, value: &KubernetesName) -> bool {
        self.allowed_namespaces.binary_search(value).is_ok()
    }
    #[must_use]
    pub fn allows_deployment(&self, value: &KubernetesName) -> bool {
        self.allowed_deployments.binary_search(value).is_ok()
    }
    #[must_use]
    pub fn allows_container(&self, value: &KubernetesName) -> bool {
        self.allowed_container_names.binary_search(value).is_ok()
    }
    #[must_use]
    pub fn allows_annotation(&self, key: &str) -> bool {
        self.allowed_annotation_keys
            .binary_search_by(|candidate| candidate.as_str().cmp(key))
            .is_ok()
    }
}

fn valid_annotation_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b'-' | b'_'))
}

/// Semantic change allowed by the profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedChangeProjectionV1 {
    pub container_name: KubernetesName,
    pub previous_image_digest: ImageDigestRef,
    pub requested_image_digest: ImageDigestRef,
    pub previous_replicas: u32,
    pub requested_replicas: u32,
    pub annotation_changes: BTreeMap<String, String>,
    pub unchanged_fields_digest: DigestHex,
}

impl AllowedChangeProjectionV1 {
    pub fn validate(
        &self,
        configuration: &KubernetesVerifierConfiguration,
    ) -> Result<(), ValidationError> {
        if self.previous_image_digest == self.requested_image_digest
            || !configuration.allows_container(&self.container_name)
            || !(configuration.minimum_replicas()..=configuration.maximum_replicas())
                .contains(&self.requested_replicas)
            || self
                .annotation_changes
                .keys()
                .any(|key| !configuration.allows_annotation(key))
        {
            return Err(ValidationError::ChangeOutsideProfile);
        }
        Ok(())
    }
}

/// Fresh authenticated cluster evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesEvidenceV1 {
    pub cluster_audience: String,
    pub api_server_identity: String,
    pub namespace_name: KubernetesName,
    pub namespace_uid: KubernetesUid,
    pub resource_name: KubernetesName,
    pub resource_uid: KubernetesUid,
    pub resource_version: String,
    pub generation: u64,
    pub deletion_timestamp: Option<String>,
    pub current_spec_digest: DigestHex,
    pub current_image: ImageDigestRef,
    pub current_replicas: u32,
    pub dry_run_response_digest: DigestHex,
    pub dry_run_warnings: Vec<String>,
    pub managed_field_conflict: bool,
    pub observed_at: u64,
}

impl KubernetesEvidenceV1 {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.cluster_audience.is_empty()
            || self.api_server_identity.is_empty()
            || self.resource_version.is_empty()
            || self.generation == 0
            || self.deletion_timestamp.is_some()
            || self.current_replicas == 0
            || self.dry_run_warnings.len() > 16
            || self
                .dry_run_warnings
                .iter()
                .any(|warning| warning.len() > 512)
        {
            return Err(ValidationError::InvalidEvidence);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Exact canonical rollout action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesWorkloadRolloutV1 {
    profile: String,
    workflow_id: String,
    executor_audience: String,
    cluster_audience: String,
    api_server_identity: String,
    namespace_name: KubernetesName,
    namespace_uid: KubernetesUid,
    resource_api_version: String,
    resource_kind: String,
    resource_name: KubernetesName,
    resource_uid: KubernetesUid,
    expected_resource_version: String,
    current_spec_digest: DigestHex,
    patch_content_type: String,
    patch_bytes: String,
    patch_digest: DigestHex,
    field_manager: String,
    force_conflicts: bool,
    field_validation: String,
    dry_run_response_digest: DigestHex,
    dry_run_observed_at: u64,
    allowed_change_projection: AllowedChangeProjectionV1,
    required_configuration_digest: DigestHex,
    evidence_digest: DigestHex,
    expires_at: u64,
    nonce: DigestHex,
}

/// Input for one exact rollout action.
pub struct KubernetesWorkloadRolloutInput {
    pub workflow_id: String,
    pub executor_audience: String,
    pub cluster_audience: String,
    pub api_server_identity: String,
    pub namespace_name: KubernetesName,
    pub namespace_uid: KubernetesUid,
    pub resource_name: KubernetesName,
    pub resource_uid: KubernetesUid,
    pub expected_resource_version: String,
    pub current_spec_digest: DigestHex,
    pub patch_bytes: String,
    pub dry_run_response_digest: DigestHex,
    pub dry_run_observed_at: u64,
    pub allowed_change_projection: AllowedChangeProjectionV1,
    pub required_configuration_digest: DigestHex,
    pub evidence_digest: DigestHex,
    pub expires_at: u64,
    pub nonce: DigestHex,
}

impl KubernetesWorkloadRolloutV1 {
    /// Constructs an exact rollout and commits to the canonical patch bytes.
    pub fn new(input: KubernetesWorkloadRolloutInput) -> Result<Self, ValidationError> {
        let patch_value: serde_json::Value =
            serde_json::from_str(&input.patch_bytes).map_err(|_| ValidationError::Malformed)?;
        let canonical_patch = String::from_utf8(
            canonical_json(&patch_value).map_err(|_| ValidationError::Canonicalization)?,
        )
        .map_err(|_| ValidationError::Canonicalization)?;
        if canonical_patch != input.patch_bytes {
            return Err(ValidationError::NonCanonical);
        }
        let action = Self {
            profile: format!("{PROFILE_ID}/{PROFILE_VERSION}"),
            workflow_id: input.workflow_id,
            executor_audience: input.executor_audience,
            cluster_audience: input.cluster_audience,
            api_server_identity: input.api_server_identity,
            namespace_name: input.namespace_name,
            namespace_uid: input.namespace_uid,
            resource_api_version: "apps/v1".into(),
            resource_kind: "Deployment".into(),
            resource_name: input.resource_name,
            resource_uid: input.resource_uid,
            expected_resource_version: input.expected_resource_version,
            current_spec_digest: input.current_spec_digest,
            patch_content_type: APPLY_MEDIA_TYPE.into(),
            patch_digest: sha256(canonical_patch.as_bytes()),
            patch_bytes: canonical_patch,
            field_manager: "auths-workload-rollout".into(),
            force_conflicts: false,
            field_validation: "Strict".into(),
            dry_run_response_digest: input.dry_run_response_digest,
            dry_run_observed_at: input.dry_run_observed_at,
            allowed_change_projection: input.allowed_change_projection,
            required_configuration_digest: input.required_configuration_digest,
            evidence_digest: input.evidence_digest,
            expires_at: input.expires_at,
            nonce: input.nonce,
        };
        action.validate()?;
        Ok(action)
    }

    /// Validates closed profile invariants and canonical byte commitments.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.profile != format!("{PROFILE_ID}/{PROFILE_VERSION}")
            || self.workflow_id.is_empty()
            || self.workflow_id.len() > 128
            || self.executor_audience.is_empty()
            || self.cluster_audience.is_empty()
            || self.api_server_identity.is_empty()
            || self.resource_api_version != "apps/v1"
            || self.resource_kind != "Deployment"
            || self.expected_resource_version.is_empty()
            || self.patch_content_type != APPLY_MEDIA_TYPE
            || self.field_manager != "auths-workload-rollout"
            || self.force_conflicts
            || self.field_validation != "Strict"
            || self.patch_bytes.is_empty()
            || self.patch_bytes.len() > MAX_ACTION_BYTES
            || sha256(self.patch_bytes.as_bytes()) != self.patch_digest
            || self.expires_at <= self.dry_run_observed_at
        {
            return Err(ValidationError::InvalidAction);
        }
        let value: serde_json::Value =
            serde_json::from_str(&self.patch_bytes).map_err(|_| ValidationError::Malformed)?;
        let canonical = canonical_json(&value).map_err(|_| ValidationError::Canonicalization)?;
        if canonical != self.patch_bytes.as_bytes() {
            return Err(ValidationError::NonCanonical);
        }
        self.validate_patch_shape(&value)?;
        Ok(())
    }

    fn validate_patch_shape(&self, value: &serde_json::Value) -> Result<(), ValidationError> {
        let object = exact_object(value, &["apiVersion", "kind", "metadata", "spec"])?;
        if object.get("apiVersion").and_then(serde_json::Value::as_str) != Some("apps/v1")
            || object.get("kind").and_then(serde_json::Value::as_str) != Some("Deployment")
        {
            return Err(ValidationError::ChangeOutsideProfile);
        }
        let metadata = exact_object(
            object.get("metadata").ok_or(ValidationError::Malformed)?,
            &["annotations", "name", "namespace"],
        )?;
        if metadata.get("name").and_then(serde_json::Value::as_str)
            != Some(self.resource_name.as_str())
            || metadata
                .get("namespace")
                .and_then(serde_json::Value::as_str)
                != Some(self.namespace_name.as_str())
        {
            return Err(ValidationError::ChangeOutsideProfile);
        }
        let annotations: BTreeMap<String, String> = serde_json::from_value(
            metadata
                .get("annotations")
                .cloned()
                .ok_or(ValidationError::Malformed)?,
        )
        .map_err(|_| ValidationError::Malformed)?;
        if annotations != self.allowed_change_projection.annotation_changes {
            return Err(ValidationError::ChangeOutsideProfile);
        }
        let spec = exact_object(
            object.get("spec").ok_or(ValidationError::Malformed)?,
            &["replicas", "template"],
        )?;
        let replicas = spec
            .get("replicas")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(ValidationError::Malformed)?;
        if replicas != self.allowed_change_projection.requested_replicas {
            return Err(ValidationError::ChangeOutsideProfile);
        }
        let template = exact_object(
            spec.get("template").ok_or(ValidationError::Malformed)?,
            &["spec"],
        )?;
        let pod_spec = exact_object(
            template.get("spec").ok_or(ValidationError::Malformed)?,
            &["containers"],
        )?;
        let containers = pod_spec
            .get("containers")
            .and_then(serde_json::Value::as_array)
            .ok_or(ValidationError::Malformed)?;
        if containers.len() != 1 {
            return Err(ValidationError::ChangeOutsideProfile);
        }
        let container = exact_object(&containers[0], &["image", "name"])?;
        let image = container
            .get("image")
            .and_then(serde_json::Value::as_str)
            .ok_or(ValidationError::Malformed)?;
        ImageDigestRef::parse(image)?;
        ImageDigestRef::parse(
            self.allowed_change_projection
                .previous_image_digest
                .as_str(),
        )?;
        ImageDigestRef::parse(
            self.allowed_change_projection
                .requested_image_digest
                .as_str(),
        )?;
        if container.get("name").and_then(serde_json::Value::as_str)
            != Some(self.allowed_change_projection.container_name.as_str())
            || image
                != self
                    .allowed_change_projection
                    .requested_image_digest
                    .as_str()
        {
            return Err(ValidationError::ChangeOutsideProfile);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_json(self)
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        if bytes.is_empty() || bytes.len() > MAX_ACTION_BYTES {
            return Err(ValidationError::LimitExceeded);
        }
        let action: Self = serde_json::from_slice(bytes).map_err(|_| ValidationError::Malformed)?;
        action.validate()?;
        if canonical_json(&action).map_err(|_| ValidationError::Canonicalization)? != bytes {
            return Err(ValidationError::NonCanonical);
        }
        Ok(action)
    }
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
    #[must_use]
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }
    #[must_use]
    pub fn executor_audience(&self) -> &str {
        &self.executor_audience
    }
    #[must_use]
    pub fn namespace_name(&self) -> &KubernetesName {
        &self.namespace_name
    }
    #[must_use]
    pub fn resource_name(&self) -> &KubernetesName {
        &self.resource_name
    }
    #[must_use]
    pub fn resource_uid(&self) -> &KubernetesUid {
        &self.resource_uid
    }
    #[must_use]
    pub fn expected_resource_version(&self) -> &str {
        &self.expected_resource_version
    }
    #[must_use]
    pub fn patch_bytes(&self) -> &[u8] {
        self.patch_bytes.as_bytes()
    }
    #[must_use]
    pub fn patch_digest(&self) -> &DigestHex {
        &self.patch_digest
    }
    #[must_use]
    pub fn projection(&self) -> &AllowedChangeProjectionV1 {
        &self.allowed_change_projection
    }
    #[must_use]
    pub fn required_configuration_digest(&self) -> &DigestHex {
        &self.required_configuration_digest
    }
    #[must_use]
    pub fn evidence_digest(&self) -> &DigestHex {
        &self.evidence_digest
    }
    #[must_use]
    pub const fn observed_at(&self) -> u64 {
        self.dry_run_observed_at
    }
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
    #[must_use]
    pub fn cluster_audience(&self) -> &str {
        &self.cluster_audience
    }
    #[must_use]
    pub fn api_server_identity(&self) -> &str {
        &self.api_server_identity
    }
    #[must_use]
    pub fn namespace_uid(&self) -> &KubernetesUid {
        &self.namespace_uid
    }
    #[must_use]
    pub fn current_spec_digest(&self) -> &DigestHex {
        &self.current_spec_digest
    }
    #[must_use]
    pub fn dry_run_response_digest(&self) -> &DigestHex {
        &self.dry_run_response_digest
    }
    #[must_use]
    pub fn field_manager(&self) -> &str {
        &self.field_manager
    }
}

fn exact_object<'a>(
    value: &'a serde_json::Value,
    keys: &[&str],
) -> Result<&'a serde_json::Map<String, serde_json::Value>, ValidationError> {
    let object = value.as_object().ok_or(ValidationError::Malformed)?;
    if object.len() != keys.len() || object.keys().any(|key| !keys.contains(&key.as_str())) {
        return Err(ValidationError::ChangeOutsideProfile);
    }
    Ok(object)
}

/// Persisted and converged Kubernetes result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesRolloutResult {
    pub resource_uid: KubernetesUid,
    pub resource_version: String,
    pub generation: u64,
    pub observed_generation: u64,
    pub requested_replicas: u32,
    pub updated_replicas: u32,
    pub available_replicas: u32,
    pub image: ImageDigestRef,
    pub api_accepted: bool,
    pub persisted_verified: bool,
    pub rollout_converged: bool,
    pub audit_id: Option<String>,
    pub observed_at: u64,
}

/// Closed profile validation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ValidationError {
    #[error("Kubernetes profile input exceeded a hard limit")]
    LimitExceeded,
    #[error("Kubernetes profile input is malformed")]
    Malformed,
    #[error("Kubernetes profile input is not canonical")]
    NonCanonical,
    #[error("Kubernetes profile canonicalization failed")]
    Canonicalization,
    #[error("invalid Kubernetes rollout action")]
    InvalidAction,
    #[error("invalid Kubernetes verifier configuration")]
    InvalidConfiguration,
    #[error("invalid Kubernetes evidence")]
    InvalidEvidence,
    #[error("mutable image reference is forbidden")]
    MutableImageReference,
    #[error("change falls outside the Kubernetes rollout profile")]
    ChangeOutsideProfile,
}
