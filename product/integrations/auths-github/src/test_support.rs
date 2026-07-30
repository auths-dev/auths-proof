//! Deterministic GitHub profile inputs for repository-owned fixtures.

#![allow(
    clippy::missing_panics_doc,
    reason = "fixed fixture constants are validated during construction"
)]

use crate::{
    CandidateEvidence, CandidatePolicy, ExecutorAudience, GitHubEvidence, GitOid, IssueEvidence,
    IssueResource, NodeId, ObjectFormat, PathChange, PublicationPolicy, RefEvidence,
    RepositoryEvidence, RepositoryName, RepositoryOwner, RepositoryResource, VerifierConfiguration,
    VerifierConfigurationInput, WorkflowGrant, WorkflowGrantInput, WorkflowId, canonical::sha256,
};

/// Trusted evaluation time used by the frozen corpus.
pub const NOW: u64 = 1_800_000_000;

/// Complete deterministic GitHub fixture.
pub struct Fixture {
    pub configuration: VerifierConfiguration,
    pub grant: WorkflowGrant,
    pub candidate: CandidateEvidence,
    pub evidence: GitHubEvidence,
}

/// Returns the canonical deterministic fixture.
#[must_use]
pub fn fixture() -> Fixture {
    let repository = RepositoryResource::new(
        42,
        NodeId::parse("R_node_auths_fixture").unwrap(),
        RepositoryOwner::parse("auths-dev").unwrap(),
        RepositoryName::parse("auths-github-demo").unwrap(),
    )
    .unwrap();
    let issue = IssueResource::new(42, NodeId::parse("I_node_auths_fixture").unwrap(), 42).unwrap();
    let executor_audience = ExecutorAudience::parse("auths-github://fixture-executor").unwrap();
    let repository_policy_digest = sha256(b"repository-policy");
    let configuration = VerifierConfiguration::new(VerifierConfigurationInput {
        candidate_inspector: "git-cli-bounded-v1".into(),
        github_adapter: "github-rest-2022-11-28".into(),
        canonical_reference: "jcs-rfc8785-v1".into(),
        repository_automation_policy_digest: repository_policy_digest.clone(),
        maximum_evidence_age_seconds: 30,
        executor_audience: executor_audience.clone(),
        receipt_schema: "auths-github-receipt-v1".into(),
    })
    .unwrap();
    let base_revision = GitOid::parse("1".repeat(40)).unwrap();
    let candidate_revision = GitOid::parse("2".repeat(40)).unwrap();
    let candidate_tree = GitOid::parse("3".repeat(40)).unwrap();
    let workflow_id = WorkflowId::parse("workflow-auths-fixture").unwrap();
    let grant = WorkflowGrant::new(WorkflowGrantInput {
        workflow_id: workflow_id.clone(),
        repository: repository.clone(),
        issue: issue.clone(),
        base_ref: crate::RefName::parse("main").unwrap(),
        base_revision: base_revision.clone(),
        object_format: ObjectFormat::Sha1,
        candidate_policy: candidate_policy(),
        publication_policy: PublicationPolicy::one_draft_pull_request(),
        executor_audience,
        issued_at: NOW - 60,
        expires_at: NOW + 840,
        required_configuration: configuration.clone(),
    })
    .unwrap();
    let changed_paths = vec![PathChange {
        path: "src/lib.rs".into(),
        old_mode: 0o100_644,
        new_mode: 0o100_644,
        added_bytes: 128,
        deleted_bytes: 16,
    }];
    let candidate = CandidateEvidence::fixture(
        base_revision.clone(),
        candidate_revision,
        candidate_tree,
        1,
        4,
        2_048,
        changed_paths,
        128,
        16,
        sha256(b"candidate-bundle"),
        sha256(b"change-set"),
    );
    let target_ref = grant.target_ref().unwrap();
    let evidence = GitHubEvidence {
        schema: "auths-github-evidence-v1".into(),
        workflow_id,
        repository: RepositoryEvidence {
            repository_id: repository.repository_id(),
            repository_node_id: repository.repository_node_id().clone(),
            owner: repository.owner().to_string(),
            name: repository.name().to_string(),
        },
        issue: IssueEvidence {
            repository_id: issue.repository_id(),
            issue_node_id: issue.issue_node_id().clone(),
            issue_number: issue.issue_number(),
            open: true,
        },
        base: RefEvidence {
            ref_name: grant.base_ref().clone(),
            revision: Some(base_revision),
        },
        target: RefEvidence {
            ref_name: target_ref,
            revision: None,
        },
        matching_pull_requests: Vec::new(),
        candidate: candidate.clone(),
        repository_policy_digest,
        acquired_at: NOW - 5,
        source_configuration: "github-rest-2022-11-28".into(),
    };
    Fixture {
        configuration,
        grant,
        candidate,
        evidence,
    }
}

fn candidate_policy() -> CandidatePolicy {
    CandidatePolicy {
        allowed_paths: vec!["src/**".into()],
        denied_paths: vec![".github/**".into()],
        maximum_changed_files: 2,
        maximum_added_bytes: 8 * 1024,
        maximum_deleted_bytes: 8 * 1024,
        maximum_candidate_bytes: 2 * 1024 * 1024,
        maximum_git_objects: 1_000,
        maximum_commits: 1,
        allow_executable_bit_changes: false,
        allow_symlinks: false,
        allow_submodules: false,
        allow_merge_commits: false,
        allow_non_utf8_paths: false,
        allow_git_attributes_changes: false,
        allow_gitmodules_changes: false,
        allow_repository_automation_changes: false,
    }
}
