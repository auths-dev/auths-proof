extern crate alloc;

use alloc::{string::ToString, vec, vec::Vec};
use auths_model::{AssuranceClaim, AssuranceClaimId, ClaimParameterId, EvidenceSourceId};
use base64ct::{Base64UrlUnpadded, Encoding as _};

use crate::identity::{AdmittedWorkload, ReusableWorkflow, WorkloadIdentity};

pub(crate) fn assurance_claims(
    admitted: &AdmittedWorkload,
    source: &EvidenceSourceId,
) -> Result<Vec<AssuranceClaim>, auths_model::ModelError> {
    let identity = admitted.identity();
    let (issuer, subject) = match identity {
        WorkloadIdentity::Generic(value) => (value.issuer.as_str(), value.subject.as_str()),
        WorkloadIdentity::GithubActions(value) => (value.issuer.as_str(), value.subject.as_str()),
    };
    let mut claims = vec![
        claim("oidc.issuer", vec![("issuer", issuer)], source)?,
        claim("oidc.subject", vec![("subject", subject)], source)?,
    ];
    let digest = Base64UrlUnpadded::encode_string(admitted.policy_digest().as_bytes());
    claims.push(claim(
        "oidc.policy",
        vec![("policy_digest", digest.as_str())],
        source,
    )?);
    if let WorkloadIdentity::GithubActions(value) = identity {
        let repository_id = value.repository_id.get().to_string();
        let owner_id = value.owner_id.get().to_string();
        claims.push(claim(
            "oidc.repository",
            vec![
                ("repository", value.repository.as_str()),
                ("repository_id", repository_id.as_str()),
                ("owner", value.owner.as_str()),
                ("owner_id", owner_id.as_str()),
            ],
            source,
        )?);
        let mut parameters = vec![
            ("repository", value.workflow.reference.repository.as_str()),
            ("path", value.workflow.reference.path.as_str()),
            ("ref", value.workflow.reference.git_ref.as_str()),
            ("commit", value.workflow.commit.as_str()),
        ];
        if let ReusableWorkflow::Present(job) = &value.job_workflow {
            parameters.extend([
                ("job_repository", job.reference.repository.as_str()),
                ("job_path", job.reference.path.as_str()),
                ("job_ref", job.reference.git_ref.as_str()),
                ("job_commit", job.commit.as_str()),
            ]);
        }
        claims.push(claim("oidc.workflow", parameters, source)?);
        claims.push(claim(
            "oidc.ref",
            vec![("ref", value.git_ref.as_str()), ("sha", value.sha.as_str())],
            source,
        )?);
        if let Some(environment) = &value.environment {
            claims.push(claim(
                "oidc.environment",
                vec![("environment", environment.as_str())],
                source,
            )?);
        }
        if let Some(runner) = value.runner {
            claims.push(claim(
                "oidc.runner",
                vec![("runner_environment", runner.as_str())],
                source,
            )?);
        }
        if let (Some(actor), Some(event)) = (&value.actor, &value.event) {
            claims.push(claim(
                "oidc.actor",
                vec![("actor", actor.as_str()), ("event", event.as_str())],
                source,
            )?);
        }
    }
    Ok(claims)
}

pub(crate) fn token_window_claim(
    issued: u64,
    expires: u64,
    source: &EvidenceSourceId,
) -> Result<AssuranceClaim, auths_model::ModelError> {
    let lifetime = expires.saturating_sub(issued).to_string();
    let issued = issued.to_string();
    let expires = expires.to_string();
    claim(
        "oidc.token-window",
        vec![
            ("issued", issued.as_str()),
            ("expires", expires.as_str()),
            ("lifetime_seconds", lifetime.as_str()),
        ],
        source,
    )
}

fn claim(
    kind: &str,
    parameters: Vec<(&str, &str)>,
    source: &EvidenceSourceId,
) -> Result<AssuranceClaim, auths_model::ModelError> {
    AssuranceClaim::new(
        AssuranceClaimId::parse(kind)?,
        parameters
            .into_iter()
            .map(|(key, value)| {
                Ok((
                    ClaimParameterId::parse(key)?,
                    ClaimParameterId::parse(value)?,
                ))
            })
            .collect::<Result<Vec<_>, auths_model::ModelError>>()?,
        None,
        source.clone(),
    )
}
