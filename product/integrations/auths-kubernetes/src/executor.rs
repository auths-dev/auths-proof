//! Verified command wrapper for the Kubernetes mutation boundary.

use auths_lifecycle::ProviderCallAuthorizationV1;
use auths_sdk::Authorized;

use crate::{
    profile::KubernetesRolloutCommand,
    types::{KubernetesEvidenceV1, KubernetesWorkloadRolloutV1},
};

/// Exact rollout command available only after verification and claim.
pub struct VerifiedRolloutCommand {
    authorized: Authorized<KubernetesRolloutCommand>,
    evidence: KubernetesEvidenceV1,
    provider_authorization: ProviderCallAuthorizationV1,
}

impl VerifiedRolloutCommand {
    pub(crate) const fn new(
        authorized: Authorized<KubernetesRolloutCommand>,
        evidence: KubernetesEvidenceV1,
        provider_authorization: ProviderCallAuthorizationV1,
    ) -> Self {
        Self {
            authorized,
            evidence,
            provider_authorization,
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
    pub const fn provider_authorization(&self) -> &ProviderCallAuthorizationV1 {
        &self.provider_authorization
    }
}
