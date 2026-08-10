//! Auths profile for exact GitHub branch and draft-PR actions.

use auths_model::{
    BudgetAlgebraId, BudgetCeiling, CanonicalAction, CapabilityId, MediaType, Permission,
    ProfileId, ProfileRef, ResourceId,
};
use auths_profile_api::{ActionProfile, ProfileContractError, ReviewDisplay};
use auths_sdk::VerifiedAction;

use crate::types::{
    BRANCH_CAPABILITY, ExactGitHubAction, GitHubOperation, MAX_ACTION_BYTES, MEDIA_TYPE,
    PROFILE_ID, PROFILE_VERSION, PULL_REQUEST_CAPABILITY, ValidationError,
};

const PUBLICATION_BUDGET_ALGEBRA: &str = "numeric-ceiling-v1";

/// Profile-decoded command obtainable only from an Auths-verified action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubCommand {
    action: ExactGitHubAction,
}

impl GitHubCommand {
    /// Returns the exact Auths-authorized action.
    #[must_use]
    pub const fn action(&self) -> &ExactGitHubAction {
        &self.action
    }
}

/// `auths.github.issue-address/1` profile.
#[derive(Clone, Copy, Debug, Default)]
pub struct GitHubIssueProfile;

impl ActionProfile for GitHubIssueProfile {
    type Command = GitHubCommand;

    fn canonicalize(&self, untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
        if untrusted.is_empty() || untrusted.len() > MAX_ACTION_BYTES {
            return Err(ProfileContractError::LimitExceeded);
        }
        let action: ExactGitHubAction =
            serde_json::from_slice(untrusted).map_err(|_| ProfileContractError::Malformed)?;
        action.validate().map_err(ProfileContractError::from)?;
        let bytes = action
            .canonical_bytes()
            .map_err(|_| ProfileContractError::Malformed)?;
        canonical_action(&action, bytes)
    }

    fn review_display(
        &self,
        canonical: &CanonicalAction,
    ) -> Result<ReviewDisplay, ProfileContractError> {
        let action = validate_canonical_action(canonical)?;
        let operation = match action.operation() {
            GitHubOperation::PublishBranch => "Publish one exact GitHub branch",
            GitHubOperation::OpenDraftPullRequest => "Open one exact draft pull request",
        };
        Ok(ReviewDisplay::new(
            format!("Auths V1 · {operation}"),
            vec![
                ("Repository".into(), action.repository().slug()),
                (
                    "Issue".into(),
                    format!("#{}", action.issue().issue_number()),
                ),
                ("Workflow".into(), action.workflow_id().to_string()),
                ("Executor".into(), action.executor_audience().to_string()),
                ("Merge".into(), "not permitted".into()),
            ],
            action
                .digest()
                .map_err(|_| ProfileContractError::Malformed)?
                .to_string(),
        ))
    }

    fn decode_verified(
        &self,
        verified: &VerifiedAction,
    ) -> Result<Self::Command, ProfileContractError> {
        Ok(GitHubCommand {
            action: validate_canonical_action(verified.canonical_action())?,
        })
    }
}

fn canonical_action(
    action: &ExactGitHubAction,
    body: Vec<u8>,
) -> Result<CanonicalAction, ProfileContractError> {
    CanonicalAction::new(
        expected_profile()?,
        MediaType::parse(MEDIA_TYPE).map_err(|_| ProfileContractError::UnsupportedProfile)?,
        body,
        permission(action)?,
        Some(BudgetCeiling::new(
            BudgetAlgebraId::parse(PUBLICATION_BUDGET_ALGEBRA)
                .map_err(|_| ProfileContractError::MeaningMismatch)?,
            1,
        )),
    )
    .map_err(|_| ProfileContractError::LimitExceeded)
}

fn validate_canonical_action(
    canonical: &CanonicalAction,
) -> Result<ExactGitHubAction, ProfileContractError> {
    if canonical.profile() != &expected_profile()? || canonical.media_type().as_str() != MEDIA_TYPE
    {
        return Err(ProfileContractError::UnsupportedProfile);
    }
    let action: ExactGitHubAction =
        serde_json::from_slice(canonical.body()).map_err(|_| ProfileContractError::Malformed)?;
    action.validate().map_err(ProfileContractError::from)?;
    let expected = canonical_action(
        &action,
        action
            .canonical_bytes()
            .map_err(|_| ProfileContractError::Malformed)?,
    )?;
    if canonical.body() != expected.body()
        || canonical.permission() != expected.permission()
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

fn permission(action: &ExactGitHubAction) -> Result<Permission, ProfileContractError> {
    let capability = match action.operation() {
        GitHubOperation::PublishBranch => BRANCH_CAPABILITY,
        GitHubOperation::OpenDraftPullRequest => PULL_REQUEST_CAPABILITY,
    };
    let resource = format!(
        "github://repositories/{}/issues/{}/workflows/{}",
        action.repository().repository_id(),
        action.issue().issue_number(),
        action.workflow_id()
    );
    Ok(Permission::new(
        CapabilityId::parse(capability).map_err(|_| ProfileContractError::MeaningMismatch)?,
        ResourceId::parse(&resource).map_err(|_| ProfileContractError::MeaningMismatch)?,
    ))
}

impl From<ValidationError> for ProfileContractError {
    fn from(error: ValidationError) -> Self {
        match error {
            ValidationError::InvalidAction => Self::UnsupportedProfile,
            ValidationError::InvalidGrant
            | ValidationError::InvalidConfiguration
            | ValidationError::InvalidPath => Self::MeaningMismatch,
        }
    }
}

#[cfg(test)]
mod tests {
    use auths_profile_api::ActionProfile as _;

    use super::*;
    use crate::types::{
        DigestHex, ExactGitHubAction, ExecutorAudience, GitOid, IssueResource, NodeId,
        PublishBranchAction, RefName, RepositoryName, RepositoryOwner, RepositoryResource,
        WorkflowId,
    };

    #[test]
    fn profile_derives_exact_resource_and_one_effect_budget() {
        let action = branch_action();
        let canonical = GitHubIssueProfile
            .canonicalize(&action.canonical_bytes().unwrap())
            .unwrap();
        assert_eq!(
            canonical.permission().capability().as_str(),
            BRANCH_CAPABILITY
        );
        assert_eq!(
            canonical.permission().resource().as_str(),
            "github://repositories/42/issues/7/workflows/workflow-1234567890"
        );
        assert_eq!(canonical.requested_budget().unwrap().value(), 1);
    }

    #[test]
    fn every_security_relevant_branch_field_changes_the_action_digest() {
        let baseline = branch_action();
        let baseline_digest = baseline.digest().unwrap();
        let ExactGitHubAction::PublishBranch(action) = baseline else {
            unreachable!()
        };
        let mut variants = Vec::new();

        let mut changed = action.clone();
        changed.workflow_grant_digest = digest('b');
        variants.push(changed);
        let mut changed = action.clone();
        changed.repository = RepositoryResource::new(
            43,
            NodeId::parse("R_node_124").unwrap(),
            RepositoryOwner::parse("auths-dev").unwrap(),
            RepositoryName::parse("auths-github-demo").unwrap(),
        )
        .unwrap();
        changed.issue = IssueResource::new(43, NodeId::parse("I_node_124").unwrap(), 7).unwrap();
        variants.push(changed);
        let mut changed = action.clone();
        changed.issue = IssueResource::new(42, NodeId::parse("I_node_125").unwrap(), 8).unwrap();
        variants.push(changed);
        let mut changed = action.clone();
        changed.base_ref = RefName::parse("release").unwrap();
        variants.push(changed);
        let mut changed = action.clone();
        changed.base_revision = oid('b');
        variants.push(changed);
        let mut changed = action.clone();
        changed.target_ref = RefName::parse("auths/issue-7-other123456").unwrap();
        variants.push(changed);
        let mut changed = action.clone();
        changed.candidate_revision = oid('c');
        variants.push(changed);
        let mut changed = action.clone();
        changed.candidate_tree = oid('d');
        variants.push(changed);
        let mut changed = action.clone();
        changed.candidate_bundle_digest = digest('c');
        variants.push(changed);
        let mut changed = action.clone();
        changed.change_set_digest = digest('d');
        variants.push(changed);
        let mut changed = action.clone();
        changed.evidence_digest = digest('e');
        variants.push(changed);
        let mut changed = action.clone();
        changed.verifier_configuration_digest = digest('f');
        variants.push(changed);
        let mut changed = action.clone();
        changed.executor_audience =
            ExecutorAudience::parse("auths-github://other-executor").unwrap();
        variants.push(changed);
        let mut changed = action;
        changed.expires_at += 1;
        variants.push(changed);

        for variant in variants {
            assert_ne!(
                ExactGitHubAction::PublishBranch(variant).digest().unwrap(),
                baseline_digest
            );
        }
    }

    fn branch_action() -> ExactGitHubAction {
        let repository = RepositoryResource::new(
            42,
            NodeId::parse("R_node_123").unwrap(),
            RepositoryOwner::parse("auths-dev").unwrap(),
            RepositoryName::parse("auths-github-demo").unwrap(),
        )
        .unwrap();
        let issue = IssueResource::new(42, NodeId::parse("I_node_123").unwrap(), 7).unwrap();
        ExactGitHubAction::PublishBranch(PublishBranchAction {
            capability: BRANCH_CAPABILITY.into(),
            profile_id: PROFILE_ID.into(),
            profile_version: PROFILE_VERSION,
            workflow_id: WorkflowId::parse("workflow-1234567890").unwrap(),
            workflow_grant_digest: digest('a'),
            repository,
            issue,
            base_ref: RefName::parse("main").unwrap(),
            base_revision: oid('1'),
            target_ref: RefName::parse("auths/issue-7-workflow-123").unwrap(),
            expected_target_state: "absent".into(),
            candidate_revision: oid('2'),
            candidate_tree: oid('3'),
            candidate_bundle_digest: digest('4'),
            change_set_digest: digest('5'),
            evidence_digest: digest('6'),
            verifier_configuration_digest: digest('7'),
            executor_audience: ExecutorAudience::parse("auths-github://test-executor").unwrap(),
            expires_at: 1_900_000_900,
        })
    }

    fn oid(character: char) -> GitOid {
        GitOid::parse(character.to_string().repeat(40)).unwrap()
    }

    fn digest(character: char) -> DigestHex {
        DigestHex::parse(character.to_string().repeat(64)).unwrap()
    }
}
