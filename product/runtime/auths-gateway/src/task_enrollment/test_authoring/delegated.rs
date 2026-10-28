//! Test-only company → machine → A → B authoring through production enrollment.
//! Every bootstrap and enrollment is natively verified and durably published.

use super::*;
use crate::participant_enrollment::tests::{chained_at, invocation};
use crate::participant_enrollment::{
    ACCEPT_PARTICIPANT_TOOL, ENROLL_PARTICIPANT_TOOL, PARTICIPANT_ENROLLMENT_SCHEMA,
    ParticipantEnrollment, ParticipantEnrollmentProofs, ParticipantScopeGrant,
};
use auths_codec::grant_id;

pub(crate) struct DelegatedEnrollment<'a> {
    pub(crate) ledger: &'a FileReleaseTaskLedger,
    pub(crate) task: &'a ApprovedAgentTask,
    pub(crate) recipes: &'a TaskEnrollmentRecipes<'a>,
    pub(crate) context: &'a TrustedContext,
    pub(crate) pins: &'a TaskActivationPins,
    pub(crate) time: &'a crate::QualificationGate,
    /// Explicit company root, machine, initial agent and child identities.
    pub(crate) signers: [&'a Signer; 4],
    pub(crate) now: u64,
}

fn grant_path(
    input: &DelegatedEnrollment<'_>,
    service: &str,
    tools: &[&str],
    audience: Audience,
) -> Vec<SignedGrant> {
    let mut grants = Vec::new();
    let mut parent = None;
    for (index, pair) in input.signers.windows(2).enumerate() {
        let grant = grant_for_audiences_at(
            pair[0],
            pair[1],
            service,
            tools,
            parent,
            u16::try_from(2 - index).unwrap(),
            vec![audience.clone()],
            input.now,
        );
        parent = Some(grant_id(grant.statement()).unwrap());
        grants.push(grant);
    }
    grants
}

fn proof(
    input: &DelegatedEnrollment<'_>,
    grants: &[SignedGrant],
    child: bool,
    service: &str,
    tool: &str,
    arguments: &Map<String, serde_json::Value>,
) -> crate::observed_tests::Submission {
    let count = if child { 3 } else { 2 };
    chained_at(
        &input.signers[..=count],
        &grants[..count].iter().collect::<Vec<_>>(),
        service,
        tool,
        arguments,
        input.now,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "native fixture signs separate root, parent, child and resource evidence before production journal publication"
)]
pub(crate) fn bootstrap_delegated(
    input: &DelegatedEnrollment<'_>,
) -> BTreeMap<String, Vec<SignedGrant>> {
    let task = input.task;
    let card = task.descriptor();
    assert_eq!(card.agent_principal, input.signers[2].principal.as_str());
    let projections = scopes(card, input.recipes).unwrap();
    let control = grant_path(
        input,
        PARTICIPANT_SERVICE,
        &[
            ACTIVATE_ROOT_TOOL,
            ENROLL_PARTICIPANT_TOOL,
            ACCEPT_PARTICIPANT_TOOL,
        ],
        Audience::parse(&format!("mcp://{PARTICIPANT_SERVICE}")).unwrap(),
    );
    let resources: BTreeMap<_, _> = projections
        .iter()
        .map(|scope| {
            (
                scope.recipe_digest.clone(),
                grant_path(
                    input,
                    &scope.service,
                    &[&scope.tool],
                    resource_audience(
                        task.commitment(),
                        card.delegation.partition_generation,
                        &scope.recipe_digest,
                    )
                    .unwrap(),
                ),
            )
        })
        .collect();
    let authority = TaskRootAuthority {
        control_grant: *grant_id(control[1].statement()).unwrap().as_bytes(),
        resource_grants: projections
            .iter()
            .map(|scope| {
                (
                    scope.scope_id.clone(),
                    *grant_id(resources[&scope.recipe_digest][1].statement())
                        .unwrap()
                        .as_bytes(),
                )
            })
            .collect(),
    };
    let root = root_pins(task, input.recipes, &authority).unwrap();
    let activation = proof(
        input,
        &control,
        false,
        PARTICIPANT_SERVICE,
        ACTIVATE_ROOT_TOOL,
        json!({"root_enrollment_commitment": root.enrollment_commitment})
            .as_object()
            .unwrap(),
    );
    let transaction = EnrollmentTransaction {
        context: input.context,
        pins: input.pins,
        time: input.time,
    };
    let resource_proofs = |child| {
        projections
            .iter()
            .map(|scope| {
                let value = match &scope.resource {
                    EnrollmentResourceBinding::Exact { handle } => handle.as_str(),
                    EnrollmentResourceBinding::CreatedChild { .. } => "unresolved-witness-only",
                };
                proof(
                    input,
                    &resources[&scope.recipe_digest],
                    child,
                    &scope.service,
                    &scope.tool,
                    json!({&scope.resource_argument: value})
                        .as_object()
                        .unwrap(),
                )
            })
            .collect::<Vec<_>>()
    };
    let root_resources = resource_proofs(false);
    let root_witnesses = projections
        .iter()
        .zip(&root_resources)
        .map(|(scope, signed)| EnrollmentResourceWitness {
            scope_id: &scope.scope_id,
            invocation: invocation(signed),
        })
        .collect::<Vec<_>>();
    input
        .ledger
        .bootstrap_participants(
            &card.task_id,
            &transaction,
            input.recipes,
            &authority,
            &RootEnrollmentProofs {
                activation: invocation(&activation),
                resources: &root_witnesses,
            },
        )
        .unwrap();
    let (channel, instance) = card
        .delegation
        .permitted_channels
        .iter()
        .find(|(_, pin)| pin.principal == input.signers[3].principal)
        .unwrap();
    let enrollment = ParticipantEnrollment {
        schema: PARTICIPANT_ENROLLMENT_SCHEMA.into(),
        engagement_commitment: *task.commitment(),
        partition_generation: card.delegation.partition_generation,
        parent_enrollment: root.enrollment_commitment,
        parent_instance_generation: root.instance_generation,
        enrollment_id: "installed-agent-b".into(),
        child_principal: input.signers[3].principal.as_str().into(),
        child_instance_generation: instance.instance_generation,
        delivery_channel: channel.clone(),
        control_grant: *grant_id(control[2].statement()).unwrap().as_bytes(),
        scopes: projections
            .iter()
            .map(|scope| ParticipantScopeGrant {
                scope_id: scope.scope_id.clone(),
                grant_id: *grant_id(resources[&scope.recipe_digest][2].statement())
                    .unwrap()
                    .as_bytes(),
            })
            .collect(),
        not_before: input.now,
        expires_at: card.expires_at,
        remaining_depth: 0,
        ceilings: root.ceilings,
    };
    let parent = proof(
        input,
        &control,
        false,
        PARTICIPANT_SERVICE,
        ENROLL_PARTICIPANT_TOOL,
        json!({"enrollment": enrollment}).as_object().unwrap(),
    );
    let child = proof(
        input,
        &control,
        true,
        PARTICIPANT_SERVICE,
        ACCEPT_PARTICIPANT_TOOL,
        json!({"enrollment_commitment": enrollment.commitment().unwrap()})
            .as_object()
            .unwrap(),
    );
    let child_resources = resource_proofs(true);
    let child_witnesses = projections
        .iter()
        .zip(&child_resources)
        .map(|(scope, signed)| EnrollmentResourceWitness {
            scope_id: &scope.scope_id,
            invocation: invocation(signed),
        })
        .collect::<Vec<_>>();
    input
        .ledger
        .enroll_participant(
            &card.task_id,
            &transaction,
            root.enrollment_commitment,
            &ParticipantEnrollmentProofs {
                parent: invocation(&parent),
                child: invocation(&child),
                resources: &child_witnesses,
            },
        )
        .unwrap();
    resources
}
