//! A new employee signature over one independently checked lost-create child.
//!
//! The original create/populate plan cannot authorize an ID that Google never
//! returned to Auths. This action binds a separately reviewed candidate and
//! evidence digest to the original plan before a fresh metadata GET or bind.

use crate::engine::{
    GatewaySubmitResult, authorized_action, not_entered, verify_sealed_for_audience,
};
use crate::task_activation::{ApprovedAgentTask, TASK_SERVICE, WriteApprovalMode};
use crate::task_effect_plan::VerifiedEffectPlan;
use crate::task_recovery_attestation::VerifiedRecoveryAttestation;
use auths_model::{Audience, TrustedContext, VerifierLimits};
use auths_profile_api::ActionProfile as _;
use auths_profile_mcp::McpProfile;
use serde::Deserialize;
use serde_json::Value;

pub(crate) const RECOVERY_TOOL: &str = "confirm_agent_recovered_child_v1";
const RECOVERY_SCHEMA: &str = "auths.agent-recovered-child/1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct RecoveryConfirmation {
    schema: String,
    task_id: String,
    task_commitment: String,
    plan_commitment: String,
    create_operation_id: String,
    candidate_id: String,
    parent_id: String,
    title: String,
    marker: String,
    content_commitment: String,
    attestation_commitment: String,
    expires_at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryArguments {
    recovery: RecoveryConfirmation,
}

fn matches_original(
    recovery: &RecoveryConfirmation,
    task: &ApprovedAgentTask,
    plan: &VerifiedEffectPlan,
    attestation: &VerifiedRecoveryAttestation,
    now: u64,
) -> bool {
    let card = task.descriptor();
    let Some(pending) = card.pending_child.as_ref() else {
        return false;
    };
    recovery.schema == RECOVERY_SCHEMA
        && card.write_approval_mode == WriteApprovalMode::Exact
        && card.not_before <= now
        && now < card.expires_at
        && now < plan.expires_at
        && now < attestation.valid_until()
        && recovery.task_id == card.task_id
        && recovery.task_commitment == hex::encode(task.commitment())
        && recovery.plan_commitment == plan.plan_commitment
        && recovery.create_operation_id == plan.create.operation_id
        && recovery.create_operation_id == pending.create_operation_id
        && recovery.candidate_id == attestation.candidate_id()
        && recovery.parent_id == pending.parent_handle
        && recovery.title == pending.title
        && recovery.marker == pending.marker
        && recovery.content_commitment == plan.content_commitment
        && recovery.attestation_commitment == attestation.commitment()
        && recovery.expires_at > now
        && recovery.expires_at <= card.expires_at
        && recovery.expires_at <= plan.expires_at
        && recovery.expires_at <= attestation.valid_until()
}

/// Verify a fresh human action specifically for a recovered child. Its native
/// proof must come from the enrolled human key, with one exact tool action and
/// no unreviewed extensions or delegated budget semantics.
pub(crate) fn verify_recovery_confirmation(
    context: &TrustedContext,
    task: &ApprovedAgentTask,
    plan: &VerifiedEffectPlan,
    attestation: &VerifiedRecoveryAttestation,
    proof_cbor: &[u8],
    action_cbor: &[u8],
    now: u64,
) -> Result<String, GatewaySubmitResult> {
    let audience = Audience::parse(&format!("mcp://{TASK_SERVICE}"))
        .map_err(|_| not_entered("gateway.task.recovery-profile"))?;
    let sealed = verify_sealed_for_audience(context, audience, now, proof_cbor, action_cbor)?;
    let action = authorized_action(&sealed)?;
    if action.action_ids().len() != 1 {
        return Err(not_entered("gateway.task.single-human-action-required"));
    }
    let command = McpProfile
        .decode_verified(action)
        .map_err(|_| not_entered("gateway.task.recovery-projection"))?;
    if command.call().service() != TASK_SERVICE || command.name() != RECOVERY_TOOL {
        return Err(not_entered("gateway.task.recovery-profile"));
    }
    let arguments: RecoveryArguments =
        serde_json::from_value(Value::Object(command.arguments().clone()))
            .map_err(|_| not_entered("gateway.task.invalid-recovery-action"))?;
    if !matches_original(&arguments.recovery, task, plan, attestation, now) {
        return Err(not_entered("gateway.task.recovery-action-mismatch"));
    }
    let branches = crate::bounds::authorized_chains(proof_cbor, action)
        .map_err(|_| not_entered("gateway.policy.proof-unavailable"))?;
    let [branch] = branches.as_slice() else {
        return Err(not_entered("gateway.task.single-human-action-required"));
    };
    if branch.actor.as_str() != task.descriptor().human_principal
        || branch.chain.is_empty()
        || branch
            .chain
            .last()
            .is_none_or(|grant| grant.statement().subject() != &branch.actor)
    {
        return Err(not_entered("gateway.task.human-authority"));
    }
    let bundle = auths_codec::decode_bundle(proof_cbor, &VerifierLimits::default())
        .map_err(|_| not_entered("gateway.policy.proof-unavailable"))?;
    if bundle.actions().len() != 1
        || !bundle.actions()[0]
            .envelope()
            .extensions()
            .as_slice()
            .is_empty()
        || branch.chain.iter().any(|grant| {
            !grant.statement().extensions().as_slice().is_empty()
                || grant.statement().budget_ceiling().is_some()
        })
    {
        return Err(not_entered("gateway.task.unsupported-policy"));
    }
    let canonical = serde_json_canonicalizer::to_vec(&command.arguments())
        .map_err(|_| not_entered("gateway.task.invalid-recovery-action"))?;
    let commitment = auths_codec::domain_commitment("auths.agent-recovered-child.v1", &canonical)
        .map_err(|_| not_entered("gateway.task.invalid-recovery-action"))?;
    Ok(hex::encode(commitment.as_bytes()))
}
