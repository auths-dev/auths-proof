//! Test-only operator preparation and native root authoring for installed flows.
//! Production must receive explicit operator trust, never expand anchors this way.

use super::*;
use crate::harness::Signer;
use crate::observed_tests::submission_for_audience;
use crate::participant_enrollment::tests::grant_for_audiences_at;
use crate::participant_enrollment::{
    ACTIVATE_ROOT_TOOL, EnrollmentInvocation, EnrollmentResourceBinding, EnrollmentResourceWitness,
    PARTICIPANT_SERVICE, RootEnrollmentProofs, resource_audience,
};
use crate::release_state::{EnrollmentTransaction, FileReleaseTaskLedger};
use crate::task_activation::TaskActivationPins;
use auths_model::{
    Audience, AudienceSet, PermissionSet, ResourceId, SignedGrant, TrustAnchor, TrustedContext,
};
use auths_profile_mcp::McpToolCall;
use serde_json::{Map, json};

/// Explicit test operator decision, performed before installing the engine.
/// Preserves status snapshots, assurance, limits and existing profile permissions.
pub(crate) fn operator_context(
    context: &TrustedContext,
    card: &AgentTaskDescriptor,
) -> TrustedContext {
    let commitment = card.canonical_commitment().unwrap();
    let control = McpToolCall::new(PARTICIPANT_SERVICE, ACTIVATE_ROOT_TOOL, Map::new()).unwrap();
    let mut extra: Vec<_> = card
        .read_scopes
        .iter()
        .map(|scope| &scope.recipe_digest)
        .chain(card.write_scopes.iter().map(|scope| &scope.recipe_digest))
        .chain(
            card.pending_child
                .iter()
                .map(|scope| &scope.populate_recipe_digest),
        )
        .map(|digest| {
            resource_audience(&commitment, card.delegation.partition_generation, digest).unwrap()
        })
        .collect();
    extra.push(Audience::parse(&format!("mcp://{PARTICIPANT_SERVICE}")).unwrap());
    let anchors = context
        .trust_anchors()
        .iter()
        .map(|anchor| {
            let mut audiences = anchor.audiences().as_slice().to_vec();
            audiences.extend_from_slice(&extra);
            audiences.sort();
            audiences.dedup();
            let mut permissions = anchor.permissions().as_slice().to_vec();
            permissions.push(control.permission().unwrap());
            for tool in [
                crate::participant_enrollment::ENROLL_PARTICIPANT_TOOL,
                crate::participant_enrollment::ACCEPT_PARTICIPANT_TOOL,
            ] {
                permissions.push(
                    McpToolCall::new(PARTICIPANT_SERVICE, tool, Map::new())
                        .unwrap()
                        .permission()
                        .unwrap(),
                );
            }
            permissions.sort();
            permissions.dedup();
            let mut namespaces = anchor.resource_namespaces().to_vec();
            namespaces.push(ResourceId::parse(&format!("mcp://{PARTICIPANT_SERVICE}/")).unwrap());
            TrustAnchor::new(
                anchor.id().clone(),
                anchor.principal().clone(),
                anchor.accepted_methods().to_vec(),
                anchor.profiles().to_vec(),
                PermissionSet::new(permissions).unwrap(),
                namespaces,
                AudienceSet::new(audiences).unwrap(),
                anchor.validity(),
                anchor.budget_ceiling().cloned(),
                anchor.max_delegation_depth(),
                anchor.assurance_policy().clone(),
                anchor.status_policy().clone(),
            )
            .unwrap()
        })
        .collect();
    TrustedContext::new(
        context.configuration(),
        context.composition(),
        anchors,
        context.accepted_registries().clone(),
        context.expected_audience().clone(),
        context.expected_challenge(),
        context.evaluation_time(),
        context.assurance_policy().clone(),
        context.principal_status_snapshot().clone(),
        context.grant_status_snapshot().clone(),
        context.resource_matcher().clone(),
        context.profile_policy().clone(),
        context.channel_policy().clone(),
        context.limits().clone(),
    )
    .unwrap()
    .with_observer_anchors(context.observer_anchors().to_vec())
    .unwrap()
    .with_approvals(
        context.approver_anchors().to_vec(),
        context.approval_requirements().to_vec(),
    )
    .unwrap()
}

/// Issue native task-scoped resource grants and publish the complete signed root.
/// There is no direct assignment to the tree or journal's participant fields.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "one native test fixture retains explicit operator trust, resource signing and root publication"
)]
pub(crate) fn bootstrap(
    ledger: &FileReleaseTaskLedger,
    task: &ApprovedAgentTask,
    recipes: &TaskEnrollmentRecipes<'_>,
    context: &TrustedContext,
    pins: &TaskActivationPins,
    time: &crate::QualificationGate,
    issuer: &Signer,
    agent: &Signer,
    now: u64,
) -> BTreeMap<String, SignedGrant> {
    let projections = scopes(task.descriptor(), recipes).unwrap();
    let control_audience = Audience::parse(&format!("mcp://{PARTICIPANT_SERVICE}")).unwrap();
    let control = grant_for_audiences_at(
        issuer,
        agent,
        PARTICIPANT_SERVICE,
        &[ACTIVATE_ROOT_TOOL],
        None,
        task.descriptor().delegation.max_depth,
        vec![control_audience.clone()],
        now,
    );
    let grants: BTreeMap<_, _> = projections
        .iter()
        .map(|scope| {
            let audience = resource_audience(
                task.commitment(),
                task.descriptor().delegation.partition_generation,
                &scope.recipe_digest,
            )
            .unwrap();
            let grant = grant_for_audiences_at(
                issuer,
                agent,
                &scope.service,
                &[&scope.tool],
                None,
                task.descriptor().delegation.max_depth,
                vec![audience],
                now,
            );
            (scope.recipe_digest.clone(), grant)
        })
        .collect();
    let authority = TaskRootAuthority {
        control_grant: *auths_codec::grant_id(control.statement())
            .unwrap()
            .as_bytes(),
        resource_grants: projections
            .iter()
            .map(|scope| {
                (
                    scope.scope_id.clone(),
                    *auths_codec::grant_id(grants[&scope.recipe_digest].statement())
                        .unwrap()
                        .as_bytes(),
                )
            })
            .collect(),
    };
    let root = root_pins(task, recipes, &authority).unwrap();
    let activation = submission_for_audience(
        issuer,
        agent,
        &control,
        json!({"root_enrollment_commitment": root.enrollment_commitment})
            .as_object()
            .unwrap(),
        &[],
        PARTICIPANT_SERVICE,
        ACTIVATE_ROOT_TOOL,
        now,
        control_audience,
    );
    let witnesses: Vec<_> = projections
        .iter()
        .map(|scope| {
            let value = match &scope.resource {
                EnrollmentResourceBinding::Exact { handle } => handle.as_str(),
                EnrollmentResourceBinding::CreatedChild { .. } => "unresolved-witness-only",
            };
            submission_for_audience(
                issuer,
                agent,
                &grants[&scope.recipe_digest],
                json!({&scope.resource_argument: value})
                    .as_object()
                    .unwrap(),
                &[],
                &scope.service,
                &scope.tool,
                now,
                resource_audience(
                    task.commitment(),
                    task.descriptor().delegation.partition_generation,
                    &scope.recipe_digest,
                )
                .unwrap(),
            )
        })
        .collect();
    let witnesses: Vec<_> = projections
        .iter()
        .zip(&witnesses)
        .map(|(scope, signed)| EnrollmentResourceWitness {
            scope_id: &scope.scope_id,
            invocation: EnrollmentInvocation {
                proof: &signed.proof,
                action: &signed.action,
            },
        })
        .collect();
    ledger
        .bootstrap_participants(
            &task.descriptor().task_id,
            &EnrollmentTransaction {
                context,
                pins,
                time,
            },
            recipes,
            &authority,
            &RootEnrollmentProofs {
                activation: EnrollmentInvocation {
                    proof: &activation.proof,
                    action: &activation.action,
                },
                resources: &witnesses,
            },
        )
        .unwrap();
    grants
}

/// Sign at the exact sole audience of a native grant in an installed task fixture.
#[allow(
    clippy::too_many_arguments,
    reason = "native fixture retains the ordinary signing helper's explicit inputs"
)]
pub(crate) fn submission(
    issuer: &Signer,
    agent: &Signer,
    grant: &SignedGrant,
    arguments: &Map<String, serde_json::Value>,
    observations: &[Vec<u8>],
    service: &str,
    tool: &str,
    now: u64,
) -> crate::observed_tests::Submission {
    let [audience] = grant.statement().audiences().as_slice() else {
        panic!("exclusive grant audience")
    };
    submission_for_audience(
        issuer,
        agent,
        grant,
        arguments,
        observations,
        service,
        tool,
        now,
        audience.clone(),
    )
}

mod delegated;
pub(crate) use delegated::{DelegatedEnrollment, bootstrap_delegated};
