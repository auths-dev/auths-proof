#![allow(
    clippy::must_use_candidate,
    reason = "repository fixture builders are consumed only by deterministic oracle tooling"
)]

use crate::{
    canonical::sha256,
    types::{
        CandidateFacts, CandidateSubmission, CobId, ExecutorAudience, GitOid,
        IssueAddressGrantInput, IssueAddressGrantV1, NodeId, OpenPatchActionInput,
        OpenPatchActionV1, PathChange, RadicleDid, RadicleEvidenceInput, RadicleEvidenceV1, Rid,
        VerifierConfiguration, VerifierConfigurationInput, WorkflowId,
    },
};

pub const NOW: u64 = 1_000;

pub fn oid(character: char) -> GitOid {
    GitOid::parse(character.to_string().repeat(40)).unwrap()
}

pub fn digest(character: char) -> crate::types::DigestHex {
    crate::types::DigestHex::parse(character.to_string().repeat(64)).unwrap()
}

pub fn node(character: char) -> NodeId {
    NodeId::parse(format!("z{}", character.to_string().repeat(31))).unwrap()
}

pub fn configuration(maximum_evidence_age_seconds: u64) -> VerifierConfiguration {
    VerifierConfiguration::new(VerifierConfigurationInput {
        candidate_inspector: "git-cli-2.51.0".into(),
        radicle_adapter: "radicle-cli-1.6.0".into(),
        canonical_reference: "radicle-canonical-v1".into(),
        observation_peers: vec![node('a'), node('b')],
        minimum_successful_peers: 2,
        maximum_evidence_age_seconds,
        synchronization_timeout_seconds: 9,
        maximum_bundle_bytes: 1024 * 1024,
        maximum_expanded_bytes: 4 * 1024 * 1024,
        maximum_objects: 1_000,
        maximum_tree_depth: 16,
        maximum_path_bytes: 256,
        expected_signer_did: RadicleDid::parse("did:key:zexecutor").unwrap(),
        executor_audience: ExecutorAudience::parse("auths-radicle://executor-a").unwrap(),
        receipt_schema: "auths-radicle-receipt-v1".into(),
    })
    .unwrap()
}

pub fn grant(configuration: VerifierConfiguration) -> IssueAddressGrantV1 {
    IssueAddressGrantV1::new(IssueAddressGrantInput {
        workflow_id: WorkflowId::parse("workflow-0001").unwrap(),
        rid: Rid::parse("rad:z123456789").unwrap(),
        issue_id: CobId::parse("1".repeat(40)).unwrap(),
        repository_identity_revision: oid('2'),
        canonical_base_oid: oid('3'),
        allowed_path_prefixes: vec!["src/".into()],
        denied_path_prefixes: vec!["src/secrets/".into()],
        maximum_changed_files: 4,
        maximum_changed_bytes: 32_768,
        maximum_commits: 2,
        expected_signer_did: configuration.expected_signer_did().clone(),
        executor_audience: configuration.executor_audience().clone(),
        expires_at: NOW + 300,
        required_configuration: configuration,
    })
    .unwrap()
}

pub fn submission() -> CandidateSubmission {
    CandidateSubmission {
        bundle: b"bounded-demo-bundle".to_vec(),
        base_oid: oid('3'),
        candidate_oid: oid('4'),
        patch_title: "Address the issue".into(),
        patch_body: "This exact candidate addresses the issue.".into(),
    }
}

pub fn candidate(submission: &CandidateSubmission) -> CandidateFacts {
    CandidateFacts::new(
        submission.base_oid.clone(),
        submission.candidate_oid.clone(),
        vec![submission.candidate_oid.clone()],
        vec![
            PathChange::new(
                "src/lib.rs",
                Some(oid('5')),
                Some(oid('6')),
                Some(0o100_644),
                Some(0o100_644),
                512,
            )
            .unwrap(),
        ],
        sha256(&submission.bundle),
        2_048,
        4,
    )
    .unwrap()
}

pub fn evidence(grant: &IssueAddressGrantV1, synchronized_at: u64) -> RadicleEvidenceV1 {
    RadicleEvidenceV1::new(RadicleEvidenceInput {
        rid: grant.rid().clone(),
        repository_identity_revision: grant.repository_identity_revision().clone(),
        delegates: vec![RadicleDid::parse("did:key:zdelegate").unwrap()],
        delegate_threshold: 1,
        default_branch: "main".into(),
        canonical_head_oid: grant.canonical_base_oid().clone(),
        canonical_derivation_digest: digest('7'),
        issue_id: grant.issue_id().clone(),
        issue_tip_ids: vec![oid('8')],
        issue_materialized_digest: digest('9'),
        issue_open: true,
        issue_history_complete: true,
        executor_signer_did: grant.expected_signer_did().clone(),
        executor_node_id: node('c'),
        synchronized_peers: grant.required_configuration().observation_peers().to_vec(),
        synchronized_at,
        adapter_version: grant.required_configuration().radicle_adapter().into(),
    })
    .unwrap()
}

pub fn action(
    grant: &IssueAddressGrantV1,
    configuration: &VerifierConfiguration,
    submission: &CandidateSubmission,
    candidate: &CandidateFacts,
    evidence: &RadicleEvidenceV1,
) -> OpenPatchActionV1 {
    let issue_reference = format!(
        "Radicle-Issue: {}\nAuths-Workflow: {}",
        grant.issue_id(),
        grant.workflow_id()
    );
    OpenPatchActionV1::new(OpenPatchActionInput {
        workflow_id: grant.workflow_id().clone(),
        workflow_grant_digest: grant.digest().unwrap(),
        rid: grant.rid().clone(),
        issue_id: grant.issue_id().clone(),
        repository_identity_revision: grant.repository_identity_revision().clone(),
        canonical_base_oid: grant.canonical_base_oid().clone(),
        candidate_oid: candidate.candidate_oid().clone(),
        candidate_bundle_digest: candidate.bundle_digest().clone(),
        candidate_commit_set_digest: candidate.commit_set_digest().clone(),
        candidate_tree_delta_digest: candidate.tree_delta_digest().clone(),
        patch_title_digest: sha256(submission.patch_title.as_bytes()),
        patch_body_digest: sha256(submission.patch_body.as_bytes()),
        issue_reference_digest: sha256(issue_reference.as_bytes()),
        signer_did: grant.expected_signer_did().clone(),
        executor_audience: grant.executor_audience().clone(),
        required_configuration_digest: configuration.digest().unwrap(),
        evidence_snapshot_digest: evidence.digest().unwrap(),
    })
}
