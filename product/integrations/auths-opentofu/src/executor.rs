//! Verified and claimed saved-plan command.

use auths_sdk::Authorized;

use crate::{
    action::OpenTofuSavedPlanApplyV1, claim::ClaimLease, plan_projection::SavedPlanProjectionV1,
    profile::OpenTofuApplyCommand, types::OpenTofuStateEvidenceV1,
};

/// Exact command accessible only after Auths verification and an atomic claim.
pub struct VerifiedSavedPlanCommand {
    authorized: Authorized<OpenTofuApplyCommand>,
    projection: SavedPlanProjectionV1,
    planning_evidence: OpenTofuStateEvidenceV1,
    lease: ClaimLease,
}

impl VerifiedSavedPlanCommand {
    pub(crate) const fn new(
        authorized: Authorized<OpenTofuApplyCommand>,
        projection: SavedPlanProjectionV1,
        planning_evidence: OpenTofuStateEvidenceV1,
        lease: ClaimLease,
    ) -> Self {
        Self {
            authorized,
            projection,
            planning_evidence,
            lease,
        }
    }

    #[must_use]
    pub fn action(&self) -> &OpenTofuSavedPlanApplyV1 {
        self.authorized.command().action()
    }
    #[must_use]
    pub const fn projection(&self) -> &SavedPlanProjectionV1 {
        &self.projection
    }
    #[must_use]
    pub const fn planning_evidence(&self) -> &OpenTofuStateEvidenceV1 {
        &self.planning_evidence
    }
    #[must_use]
    pub(crate) const fn lease(&self) -> &ClaimLease {
        &self.lease
    }
}
