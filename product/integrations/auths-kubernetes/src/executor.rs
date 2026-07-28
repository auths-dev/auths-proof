//! Verified command wrapper for the Kubernetes mutation boundary.

use auths_sdk::Authorized;

use crate::{
    claim::ClaimLease,
    profile::KubernetesRolloutCommand,
    types::{KubernetesEvidenceV1, KubernetesWorkloadRolloutV1},
};

/// Exact rollout command available only after verification and claim.
pub struct VerifiedRolloutCommand {
    authorized: Authorized<KubernetesRolloutCommand>,
    evidence: KubernetesEvidenceV1,
    lease: ClaimLease,
}

impl VerifiedRolloutCommand {
    pub(crate) const fn new(
        authorized: Authorized<KubernetesRolloutCommand>,
        evidence: KubernetesEvidenceV1,
        lease: ClaimLease,
    ) -> Self {
        Self {
            authorized,
            evidence,
            lease,
        }
    }

    #[must_use]
    pub fn action(&self) -> &KubernetesWorkloadRolloutV1 {
        self.authorized.command().action()
    }
    #[must_use]
    pub const fn evidence(&self) -> &KubernetesEvidenceV1 {
        &self.evidence
    }
    #[must_use]
    pub(crate) const fn lease(&self) -> &ClaimLease {
        &self.lease
    }
}
