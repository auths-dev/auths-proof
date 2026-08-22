//! Protected source-to-saved-plan orchestration.

use crate::{
    action::{OpenTofuSavedPlanApplyInput, OpenTofuSavedPlanApplyV1, PermittedChangeSummaryV1},
    bundle::OpenTofuSourceBundleV1,
    canonical::sha256,
    errors::{PortError, ValidationError},
    plan_projection::SavedPlanProjectionV1,
    ports::{PlanArtifactStore, SavedPlanArtifact},
    types::{DigestHex, OpenTofuStateEvidenceV1, OpenTofuVerifierConfigurationV1, ResourceAction},
};

/// Exact outputs produced inside an isolated OpenTofu planner.
pub struct RawSavedPlan {
    pub saved_plan_bytes: Vec<u8>,
    pub show_json: Vec<u8>,
    pub opentofu_version: String,
    pub platform: String,
}

/// Protected OpenTofu runtime. Implementations own planning credentials.
pub trait OpenTofuPlannerRuntime: Send + Sync {
    fn create_saved_plan(
        &self,
        bundle: &OpenTofuSourceBundleV1,
        evidence: &OpenTofuStateEvidenceV1,
    ) -> Result<RawSavedPlan, PortError>;
}

/// Complete result passed to proof issuance.
pub struct PlannedSavedPlan {
    pub action: OpenTofuSavedPlanApplyV1,
    pub projection: SavedPlanProjectionV1,
    pub evidence: OpenTofuStateEvidenceV1,
}

/// Protected planner with explicit runtime and encrypted artifact store.
pub struct ProtectedPlanner<R, S> {
    runtime: R,
    artifacts: S,
}

impl<R, S> ProtectedPlanner<R, S>
where
    R: OpenTofuPlannerRuntime,
    S: PlanArtifactStore,
{
    #[must_use]
    pub const fn new(runtime: R, artifacts: S) -> Self {
        Self { runtime, artifacts }
    }

    /// Creates, projects, commits, and stores one saved plan.
    #[allow(
        clippy::too_many_arguments,
        reason = "all proof-bound planner facts remain explicit"
    )]
    pub fn plan(
        &self,
        bundle: &OpenTofuSourceBundleV1,
        evidence: OpenTofuStateEvidenceV1,
        configuration: OpenTofuVerifierConfigurationV1,
        variable_commitment: DigestHex,
        nonce: DigestHex,
        planned_at: u64,
        expires_at: u64,
    ) -> Result<PlannedSavedPlan, PlannerError> {
        bundle.validate()?;
        evidence.validate()?;
        configuration.validate()?;
        if bundle.requested_workspace != evidence.workspace
            || sha256(bundle.dependency_lock_file.as_bytes()) != evidence.dependency_lock_digest
            || crate::bundle::empty_module_manifest_digest()? != evidence.module_manifest_digest
            || planned_at != evidence.observed_at
        {
            return Err(PlannerError::EvidenceMismatch);
        }
        let raw = self.runtime.create_saved_plan(bundle, &evidence)?;
        let projection = SavedPlanProjectionV1::from_show_json(&raw.show_json, &configuration)?;
        let plan_digest = sha256(&raw.saved_plan_bytes);
        let projection_digest = projection.digest()?;
        let handle = self
            .artifacts
            .put(SavedPlanArtifact::new(raw.saved_plan_bytes)?)?;
        let action = OpenTofuSavedPlanApplyV1::new(OpenTofuSavedPlanApplyInput {
            executor_audience: configuration.executor_audience().into(),
            opentofu_version: raw.opentofu_version,
            platform: raw.platform,
            backend_identity: evidence.backend_identity.clone(),
            workspace: evidence.workspace.clone(),
            state_lineage: evidence.state_lineage.clone(),
            state_serial: evidence.state_serial,
            state_digest: evidence.state_digest.clone(),
            configuration_bundle_digest: bundle.digest()?,
            variable_commitment,
            dependency_lock_digest: evidence.dependency_lock_digest.clone(),
            module_manifest_digest: evidence.module_manifest_digest.clone(),
            opaque_plan_digest: plan_digest,
            plan_projection_digest: projection_digest,
            plan_handle: handle,
            permitted_change_summary: summary(&projection),
            required_configuration: configuration,
            planned_at,
            expires_at,
            nonce,
        })?;
        Ok(PlannedSavedPlan {
            action,
            projection,
            evidence,
        })
    }
}

fn summary(projection: &SavedPlanProjectionV1) -> PermittedChangeSummaryV1 {
    let mut result = PermittedChangeSummaryV1 {
        creates: 0,
        updates: 0,
        reads: 0,
        no_ops: 0,
    };
    for action in projection
        .resource_changes
        .iter()
        .flat_map(|change| &change.actions)
    {
        match action {
            ResourceAction::Create => result.creates = result.creates.saturating_add(1),
            ResourceAction::Update => result.updates = result.updates.saturating_add(1),
            ResourceAction::Read => result.reads = result.reads.saturating_add(1),
            ResourceAction::NoOp => result.no_ops = result.no_ops.saturating_add(1),
            ResourceAction::Delete => {}
        }
    }
    result
}

/// Closed protected-planning failure.
#[derive(Debug, thiserror::Error)]
pub enum PlannerError {
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    Canonical(#[from] crate::errors::CanonicalError),
    #[error(transparent)]
    Port(#[from] PortError),
    #[error("protected planner evidence does not match the source bundle")]
    EvidenceMismatch,
}
