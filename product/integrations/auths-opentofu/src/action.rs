//! Canonical saved-plan action.

use serde::{Deserialize, Serialize};

use crate::{
    canonical::{canonical_digest, canonical_json},
    errors::{CanonicalError, ValidationError},
    types::{
        DigestHex, MAX_ACTION_BYTES, OpenTofuVerifierConfigurationV1, PROFILE_ID, PROFILE_VERSION,
        PlanHandle,
    },
};

/// Public change counts committed into the action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermittedChangeSummaryV1 {
    pub creates: u32,
    pub updates: u32,
    pub reads: u32,
    pub no_ops: u32,
}

impl PermittedChangeSummaryV1 {
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.creates
            .saturating_add(self.updates)
            .saturating_add(self.reads)
            .saturating_add(self.no_ops)
    }
}

/// Exact input to the protected apply service.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenTofuSavedPlanApplyV1 {
    profile: String,
    executor_audience: String,
    opentofu_version: String,
    platform: String,
    backend_identity: String,
    workspace: String,
    state_lineage: String,
    state_serial: u64,
    state_digest: DigestHex,
    configuration_bundle_digest: DigestHex,
    variable_commitment: DigestHex,
    dependency_lock_digest: DigestHex,
    module_manifest_digest: DigestHex,
    opaque_plan_digest: DigestHex,
    plan_projection_digest: DigestHex,
    plan_handle: PlanHandle,
    permitted_change_summary: PermittedChangeSummaryV1,
    required_configuration_digest: DigestHex,
    planned_at: u64,
    expires_at: u64,
    nonce: DigestHex,
}

/// Construction input keeps every security-relevant field explicit.
pub struct OpenTofuSavedPlanApplyInput {
    pub executor_audience: String,
    pub opentofu_version: String,
    pub platform: String,
    pub backend_identity: String,
    pub workspace: String,
    pub state_lineage: String,
    pub state_serial: u64,
    pub state_digest: DigestHex,
    pub configuration_bundle_digest: DigestHex,
    pub variable_commitment: DigestHex,
    pub dependency_lock_digest: DigestHex,
    pub module_manifest_digest: DigestHex,
    pub opaque_plan_digest: DigestHex,
    pub plan_projection_digest: DigestHex,
    pub plan_handle: PlanHandle,
    pub permitted_change_summary: PermittedChangeSummaryV1,
    pub required_configuration: OpenTofuVerifierConfigurationV1,
    pub planned_at: u64,
    pub expires_at: u64,
    pub nonce: DigestHex,
}

impl OpenTofuSavedPlanApplyV1 {
    pub fn new(input: OpenTofuSavedPlanApplyInput) -> Result<Self, ValidationError> {
        input.required_configuration.validate()?;
        let action = Self {
            profile: format!("{PROFILE_ID}/{PROFILE_VERSION}"),
            executor_audience: input.executor_audience,
            opentofu_version: input.opentofu_version,
            platform: input.platform,
            backend_identity: input.backend_identity,
            workspace: input.workspace,
            state_lineage: input.state_lineage,
            state_serial: input.state_serial,
            state_digest: input.state_digest,
            configuration_bundle_digest: input.configuration_bundle_digest,
            variable_commitment: input.variable_commitment,
            dependency_lock_digest: input.dependency_lock_digest,
            module_manifest_digest: input.module_manifest_digest,
            opaque_plan_digest: input.opaque_plan_digest,
            plan_projection_digest: input.plan_projection_digest,
            plan_handle: input.plan_handle,
            permitted_change_summary: input.permitted_change_summary,
            required_configuration_digest: input
                .required_configuration
                .digest()
                .map_err(|_| ValidationError::Malformed)?,
            planned_at: input.planned_at,
            expires_at: input.expires_at,
            nonce: input.nonce,
        };
        action.validate()?;
        Ok(action)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.profile != format!("{PROFILE_ID}/{PROFILE_VERSION}")
            || self.executor_audience.is_empty()
            || self.executor_audience.len() > 512
            || self.opentofu_version.is_empty()
            || self.opentofu_version.len() > 64
            || self.platform.is_empty()
            || self.platform.len() > 128
            || self.backend_identity.is_empty()
            || self.backend_identity.len() > 512
            || self.workspace.is_empty()
            || self.workspace.len() > 128
            || self.state_lineage.is_empty()
            || self.state_lineage.len() > 256
            || self.permitted_change_summary.total() == 0
            || self.expires_at <= self.planned_at
        {
            return Err(ValidationError::Malformed);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ValidationError> {
        self.validate()?;
        let bytes = canonical_json(self).map_err(|_| ValidationError::Malformed)?;
        if bytes.len() > MAX_ACTION_BYTES {
            return Err(ValidationError::LimitExceeded);
        }
        Ok(bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        if bytes.is_empty() || bytes.len() > MAX_ACTION_BYTES {
            return Err(ValidationError::LimitExceeded);
        }
        let action: Self = serde_json::from_slice(bytes).map_err(|_| ValidationError::Malformed)?;
        action.validate()?;
        if action.canonical_bytes()? != bytes {
            return Err(ValidationError::NonCanonical);
        }
        Ok(action)
    }

    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }

    #[must_use]
    pub fn executor_audience(&self) -> &str {
        &self.executor_audience
    }
    #[must_use]
    pub fn opentofu_version(&self) -> &str {
        &self.opentofu_version
    }
    #[must_use]
    pub fn platform(&self) -> &str {
        &self.platform
    }
    #[must_use]
    pub fn backend_identity(&self) -> &str {
        &self.backend_identity
    }
    #[must_use]
    pub fn workspace(&self) -> &str {
        &self.workspace
    }
    #[must_use]
    pub fn state_lineage(&self) -> &str {
        &self.state_lineage
    }
    #[must_use]
    pub const fn state_serial(&self) -> u64 {
        self.state_serial
    }
    #[must_use]
    pub const fn state_digest(&self) -> &DigestHex {
        &self.state_digest
    }
    #[must_use]
    pub const fn configuration_bundle_digest(&self) -> &DigestHex {
        &self.configuration_bundle_digest
    }
    #[must_use]
    pub const fn variable_commitment(&self) -> &DigestHex {
        &self.variable_commitment
    }
    #[must_use]
    pub const fn dependency_lock_digest(&self) -> &DigestHex {
        &self.dependency_lock_digest
    }
    #[must_use]
    pub const fn module_manifest_digest(&self) -> &DigestHex {
        &self.module_manifest_digest
    }
    #[must_use]
    pub const fn opaque_plan_digest(&self) -> &DigestHex {
        &self.opaque_plan_digest
    }
    #[must_use]
    pub const fn plan_projection_digest(&self) -> &DigestHex {
        &self.plan_projection_digest
    }
    #[must_use]
    pub const fn plan_handle(&self) -> &PlanHandle {
        &self.plan_handle
    }
    #[must_use]
    pub const fn required_configuration_digest(&self) -> &DigestHex {
        &self.required_configuration_digest
    }
    #[must_use]
    pub const fn planned_at(&self) -> u64 {
        self.planned_at
    }
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
    #[must_use]
    pub const fn permitted_change_summary(&self) -> &PermittedChangeSummaryV1 {
        &self.permitted_change_summary
    }
}
