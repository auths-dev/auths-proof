use serde::{Deserialize, Serialize};

use crate::{
    canonical::{canonical_json, sha256},
    lifecycle::{BRANCH_PROVIDER_CONTRACT_ID, PULL_REQUEST_PROVIDER_CONTRACT_ID},
    types::{ExactGitHubAction, OpenDraftPullRequestAction, PublishBranchAction, ValidationError},
};

const MAX_REQUEST_BYTES: usize = 32 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BranchPublishRequestV1 {
    contract: String,
    repository_path: String,
    argv: [String; 3],
    refspec: String,
}

impl BranchPublishRequestV1 {
    /// Derives the only provider request allowed for this branch action.
    ///
    /// # Errors
    ///
    /// Returns invalid-action when the input or derived request is outside the
    /// closed provider contract.
    pub fn derive(action: &PublishBranchAction) -> Result<Self, ValidationError> {
        ExactGitHubAction::PublishBranch(action.clone()).validate()?;
        let request = Self {
            contract: BRANCH_PROVIDER_CONTRACT_ID.into(),
            repository_path: format!(
                "/{}/{}.git",
                action.repository.owner(),
                action.repository.name()
            ),
            argv: ["push".into(), "--porcelain".into(), "--no-verify".into()],
            refspec: format!(
                "{}:refs/heads/{}",
                action.candidate_revision, action.target_ref
            ),
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates the exact branch-publish provider contract.
    ///
    /// # Errors
    ///
    /// Returns invalid-action when any request field differs from the closed
    /// contract or exceeds its bounds.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.contract != BRANCH_PROVIDER_CONTRACT_ID
            || self.argv != ["push", "--porcelain", "--no-verify"]
            || !self.repository_path.starts_with('/')
            || !self.repository_path.as_bytes().ends_with(b".git")
            || self.repository_path.len() > 256
            || self.refspec.is_empty()
            || self.refspec.len() > 512
        {
            return Err(ValidationError::InvalidAction);
        }
        Ok(())
    }

    #[must_use]
    pub fn repository_path(&self) -> &str {
        &self.repository_path
    }

    #[must_use]
    pub fn argv(&self) -> [&str; 3] {
        self.argv.each_ref().map(String::as_str)
    }

    #[must_use]
    pub fn refspec(&self) -> &str {
        &self.refspec
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftPullRequestV1 {
    contract: String,
    path: String,
    title: String,
    body: String,
    head: String,
    base: String,
    draft: bool,
}

impl DraftPullRequestV1 {
    /// Derives the only provider request allowed for this pull-request action.
    ///
    /// # Errors
    ///
    /// Returns invalid-action when input bytes or the derived request are
    /// outside the closed provider contract.
    pub fn derive(
        action: &OpenDraftPullRequestAction,
        exact_body: &str,
    ) -> Result<Self, ValidationError> {
        ExactGitHubAction::OpenDraftPullRequest(action.clone()).validate()?;
        if action.exact_body_digest != sha256(exact_body.as_bytes()) {
            return Err(ValidationError::InvalidAction);
        }
        let request = Self {
            contract: PULL_REQUEST_PROVIDER_CONTRACT_ID.into(),
            path: format!(
                "/repos/{}/{}/pulls",
                action.repository.owner(),
                action.repository.name()
            ),
            title: action.exact_title.clone(),
            body: exact_body.into(),
            head: action.head_ref.to_string(),
            base: action.base_ref.to_string(),
            draft: true,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates the exact draft pull-request provider contract.
    ///
    /// # Errors
    ///
    /// Returns invalid-action when any request field differs from the closed
    /// contract or exceeds its bounds.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.contract != PULL_REQUEST_PROVIDER_CONTRACT_ID
            || !self.path.starts_with("/repos/")
            || !self.path.ends_with("/pulls")
            || self.path.len() > 512
            || self.title.is_empty()
            || self.title.len() > 512
            || self.body.is_empty()
            || self.body.len() > 16 * 1024
            || self.head.is_empty()
            || self.head.len() > 256
            || self.base.is_empty()
            || self.base.len() > 256
            || !self.draft
        {
            return Err(ValidationError::InvalidAction);
        }
        let bytes = canonical_json(self).map_err(|_| ValidationError::InvalidAction)?;
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(ValidationError::InvalidAction);
        }
        Ok(())
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    #[must_use]
    pub fn body(&self) -> &str {
        &self.body
    }

    #[must_use]
    pub fn head(&self) -> &str {
        &self.head
    }

    #[must_use]
    pub fn base(&self) -> &str {
        &self.base
    }

    #[must_use]
    pub const fn draft(&self) -> bool {
        self.draft
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        service::{
            derive_open_pull_request_action, derive_publish_branch_action,
            deterministic_pull_request_body,
        },
        test_support::fixture,
    };

    use super::*;

    #[test]
    fn provider_requests_are_exact_and_operation_specific() {
        let fixture = fixture();
        let branch =
            derive_publish_branch_action(&fixture.grant, &fixture.configuration, &fixture.evidence)
                .unwrap();
        let branch_request = BranchPublishRequestV1::derive(&branch).unwrap();
        assert_eq!(
            branch_request.argv(),
            ["push", "--porcelain", "--no-verify"]
        );

        let receipt = crate::types::DigestHex::parse("44".repeat(32)).unwrap();
        let body = deterministic_pull_request_body(
            &fixture.grant,
            &branch.candidate_revision,
            &receipt,
            "https://receipts.example.test",
        );
        let pull = derive_open_pull_request_action(
            &fixture.grant,
            &fixture.configuration,
            &fixture.evidence,
            &receipt,
            &body,
        )
        .unwrap();
        let pull_request = DraftPullRequestV1::derive(&pull, &body).unwrap();
        assert!(pull_request.draft());
        assert_ne!(
            serde_json::to_value(branch_request).unwrap(),
            serde_json::to_value(pull_request).unwrap()
        );
    }
}
