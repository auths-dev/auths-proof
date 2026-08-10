//! Auths action profile for one exact Kubernetes Deployment rollout.

use auths_model::{
    BudgetAlgebraId, BudgetCeiling, CanonicalAction, CapabilityId, MediaType, Permission,
    ProfileId, ProfileRef, ResourceId,
};
use auths_profile_api::{ActionProfile, ProfileContractError, ReviewDisplay};
use auths_sdk::VerifiedAction;
use sha2::{Digest as _, Sha256};

use crate::types::{
    KubernetesWorkloadRolloutV1, MAX_ACTION_BYTES, MEDIA_TYPE, PROFILE_ID, PROFILE_VERSION,
    ROLLOUT_CAPABILITY, ValidationError,
};

const ROLLOUT_BUDGET_ALGEBRA: &str = "numeric-ceiling-v1";

/// Profile-decoded command obtainable only after Auths verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KubernetesRolloutCommand {
    action: KubernetesWorkloadRolloutV1,
}

impl KubernetesRolloutCommand {
    /// Returns the exact verified action.
    #[must_use]
    pub const fn action(&self) -> &KubernetesWorkloadRolloutV1 {
        &self.action
    }
}

/// `auths.kubernetes.workload-rollout/1` implementation.
#[derive(Clone, Copy, Debug, Default)]
pub struct KubernetesRolloutProfile;

impl ActionProfile for KubernetesRolloutProfile {
    type Command = KubernetesRolloutCommand;

    fn canonicalize(&self, untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
        if untrusted.is_empty() || untrusted.len() > MAX_ACTION_BYTES {
            return Err(ProfileContractError::LimitExceeded);
        }
        let action = KubernetesWorkloadRolloutV1::from_canonical_bytes(untrusted)
            .map_err(ProfileContractError::from)?;
        canonical_action(
            &action,
            action
                .canonical_bytes()
                .map_err(|_| ProfileContractError::Malformed)?,
        )
    }

    fn review_display(
        &self,
        canonical: &CanonicalAction,
    ) -> Result<ReviewDisplay, ProfileContractError> {
        let action = validate_canonical_action(canonical)?;
        Ok(ReviewDisplay::new(
            "Auths V1 · Roll out one Kubernetes Deployment",
            vec![
                ("Cluster".into(), action.cluster_audience().into()),
                ("Namespace".into(), action.namespace_name().to_string()),
                ("Deployment".into(), action.resource_name().to_string()),
                (
                    "Container".into(),
                    action.projection().container_name.to_string(),
                ),
                (
                    "Image".into(),
                    action.projection().requested_image_digest.as_str().into(),
                ),
                (
                    "Replicas".into(),
                    action.projection().requested_replicas.to_string(),
                ),
                ("Executor".into(), action.executor_audience().into()),
            ],
            hex::encode(Sha256::digest(canonical.body())),
        ))
    }

    fn decode_verified(
        &self,
        verified: &VerifiedAction,
    ) -> Result<Self::Command, ProfileContractError> {
        Ok(KubernetesRolloutCommand {
            action: validate_canonical_action(verified.canonical_action())?,
        })
    }
}

fn canonical_action(
    action: &KubernetesWorkloadRolloutV1,
    body: Vec<u8>,
) -> Result<CanonicalAction, ProfileContractError> {
    CanonicalAction::new(
        expected_profile()?,
        MediaType::parse(MEDIA_TYPE).map_err(|_| ProfileContractError::UnsupportedProfile)?,
        body,
        permission(action)?,
        Some(BudgetCeiling::new(
            BudgetAlgebraId::parse(ROLLOUT_BUDGET_ALGEBRA)
                .map_err(|_| ProfileContractError::MeaningMismatch)?,
            1,
        )),
    )
    .map_err(|_| ProfileContractError::LimitExceeded)
}

fn validate_canonical_action(
    canonical: &CanonicalAction,
) -> Result<KubernetesWorkloadRolloutV1, ProfileContractError> {
    if canonical.profile() != &expected_profile()? || canonical.media_type().as_str() != MEDIA_TYPE
    {
        return Err(ProfileContractError::UnsupportedProfile);
    }
    let action = KubernetesWorkloadRolloutV1::from_canonical_bytes(canonical.body())
        .map_err(ProfileContractError::from)?;
    let expected = canonical_action(&action, canonical.body().to_vec())?;
    if canonical.permission() != expected.permission()
        || canonical.requested_budget() != expected.requested_budget()
        || !canonical.detached_attachments().is_empty()
    {
        return Err(ProfileContractError::MeaningMismatch);
    }
    Ok(action)
}

fn expected_profile() -> Result<ProfileRef, ProfileContractError> {
    ProfileRef::new(
        ProfileId::parse(PROFILE_ID).map_err(|_| ProfileContractError::UnsupportedProfile)?,
        PROFILE_VERSION,
    )
    .map_err(|_| ProfileContractError::UnsupportedProfile)
}

fn permission(action: &KubernetesWorkloadRolloutV1) -> Result<Permission, ProfileContractError> {
    let resource = format!(
        "kubernetes://{}/apis/apps/v1/namespaces/{}/deployments/{}/{}",
        action.cluster_audience(),
        action.namespace_name(),
        action.resource_name(),
        action.resource_uid()
    );
    Ok(Permission::new(
        CapabilityId::parse(ROLLOUT_CAPABILITY)
            .map_err(|_| ProfileContractError::MeaningMismatch)?,
        ResourceId::parse(&resource).map_err(|_| ProfileContractError::MeaningMismatch)?,
    ))
}

impl From<ValidationError> for ProfileContractError {
    fn from(error: ValidationError) -> Self {
        match error {
            ValidationError::LimitExceeded => Self::LimitExceeded,
            ValidationError::Malformed | ValidationError::Canonicalization => Self::Malformed,
            ValidationError::NonCanonical => Self::NonCanonical,
            ValidationError::InvalidAction => Self::UnsupportedProfile,
            ValidationError::InvalidConfiguration
            | ValidationError::InvalidEvidence
            | ValidationError::MutableImageReference
            | ValidationError::ChangeOutsideProfile => Self::MeaningMismatch,
        }
    }
}

#[cfg(test)]
mod tests {
    use auths_profile_api::ActionProfile as _;

    use super::*;
    use crate::{test_support::fixture, types::ROLLOUT_CAPABILITY};

    #[test]
    fn profile_binds_exact_deployment_uid_and_one_effect_budget() {
        let fixture = fixture();
        let canonical = KubernetesRolloutProfile
            .canonicalize(&fixture.action.canonical_bytes().unwrap())
            .unwrap();
        assert_eq!(
            canonical.permission().capability().as_str(),
            ROLLOUT_CAPABILITY
        );
        assert!(
            canonical
                .permission()
                .resource()
                .as_str()
                .contains(fixture.action.resource_uid().as_str())
        );
        assert_eq!(canonical.requested_budget().unwrap().value(), 1);
    }
}
