use auths_model::BoundedSet;
use auths_oidc_workload::identity as oidc;
use auths_sigstore_keyless::identity as fulcio;

#[test]
fn independent_github_policy_joins_agree_on_immutable_ids() {
    let repository = "auths-dev/auths-proof";
    let owner = "auths-dev";
    let path = ".github/workflows/release.yml";
    let reference = "refs/heads/main";
    let commit = "0123456789abcdef0123456789abcdef01234567";
    let oidc_identity = oidc::GithubIdentity::new(oidc::GithubIdentity {
        issuer: oidc::IssuerUrl::parse("https://token.actions.githubusercontent.com").unwrap(),
        subject: oidc::Subject::parse("repo:auths-dev/auths-proof").unwrap(),
        repository: oidc::Repository::parse(repository).unwrap(),
        repository_id: oidc::RepositoryId::parse("42").unwrap(),
        owner: oidc::RepositoryOwner::parse(owner).unwrap(),
        owner_id: oidc::RepositoryOwnerId::parse("7").unwrap(),
        workflow: oidc::WorkflowIdentity {
            reference: oidc::WorkflowRef {
                repository: oidc::Repository::parse(repository).unwrap(),
                path: oidc::WorkflowPath::parse(path).unwrap(),
                git_ref: oidc::GitRef::parse(reference).unwrap(),
            },
            commit: oidc::CommitSha::parse(commit).unwrap(),
        },
        job_workflow: oidc::ReusableWorkflow::Absent,
        git_ref: oidc::GitRef::parse(reference).unwrap(),
        sha: oidc::CommitSha::parse(commit).unwrap(),
        environment: None,
        runner: None,
        actor: None,
        event: None,
    })
    .unwrap();
    let oidc_policy = oidc::GithubPolicy {
        repository_id: oidc::RepositoryId::parse("42").unwrap(),
        owner_id: oidc::RepositoryOwnerId::parse("7").unwrap(),
        workflow: None,
        git_ref: None,
        environment: None,
    };
    let fulcio_identity = fulcio::FulcioGithubIdentity {
        issuer: fulcio::IssuerUrl::parse("https://token.actions.githubusercontent.com").unwrap(),
        subject: fulcio::Subject::parse("repo:auths-dev/auths-proof").unwrap(),
        certificate_san: fulcio::CertificateIdentity::Uri(
            "https://github.com/auths-dev/auths-proof".into(),
        ),
        repository: fulcio::Repository::parse(repository).unwrap(),
        repository_id: fulcio::RepositoryId::parse("42").unwrap(),
        owner: fulcio::RepositoryOwner::parse(owner).unwrap(),
        owner_id: fulcio::RepositoryOwnerId::parse("7").unwrap(),
        workflow: fulcio::WorkflowIdentity {
            reference: fulcio::WorkflowRef {
                repository: fulcio::Repository::parse(repository).unwrap(),
                path: fulcio::WorkflowPath::parse(path).unwrap(),
                git_ref: fulcio::GitRef::parse(reference).unwrap(),
            },
            commit: fulcio::CommitSha::parse(commit).unwrap(),
        },
        job_workflow: fulcio::ReusableWorkflow::Absent,
        git_ref: fulcio::GitRef::parse(reference).unwrap(),
        sha: fulcio::CommitSha::parse(commit).unwrap(),
        environment: None,
        runner: fulcio::RunnerEnvironment::GithubHosted,
        event: fulcio::EventName::parse("push").unwrap(),
        run_invocation: fulcio::RunInvocationUri::parse(
            "https://github.com/auths-dev/auths-proof/actions/runs/1",
        )
        .unwrap(),
    };
    let fulcio_policy = fulcio::FulcioGithubPolicy {
        repository_id: fulcio::RepositoryId::parse("42").unwrap(),
        owner_id: fulcio::RepositoryOwnerId::parse("7").unwrap(),
        workflow: None,
        git_ref: None,
        environment: None,
    };
    let profile = fulcio::FulcioIssuerProfile::GithubActions {
        policies: BoundedSet::new(vec![fulcio_policy]).unwrap(),
    };
    assert!(oidc_policy.admits(&oidc_identity));
    assert!(
        profile
            .admit(&fulcio::FulcioWorkloadIdentity::GithubActions(Box::new(
                fulcio_identity.clone()
            )))
            .is_ok()
    );
    let rejected = fulcio::FulcioGithubPolicy {
        repository_id: fulcio::RepositoryId::parse("43").unwrap(),
        owner_id: fulcio::RepositoryOwnerId::parse("7").unwrap(),
        workflow: None,
        git_ref: None,
        environment: None,
    };
    let rejected = fulcio::FulcioIssuerProfile::GithubActions {
        policies: BoundedSet::new(vec![rejected]).unwrap(),
    };
    assert!(
        rejected
            .admit(&fulcio::FulcioWorkloadIdentity::GithubActions(Box::new(
                fulcio_identity
            )))
            .is_err()
    );
}
