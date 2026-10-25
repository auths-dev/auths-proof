//! One human signature over a task-bound create and its initial population.
//! This module only verifies and projects the plan. Provider admission must
//! separately compare both closed requests and fresh late-bound read values.

use crate::bounds::authorized_chains;
use crate::engine::{
    GatewaySubmitResult, authorized_action, not_entered, verify_sealed_for_audience,
};
use crate::task_activation::{ApprovedAgentTask, TASK_SERVICE, TaskWriteVerb, WriteApprovalMode};
use crate::task_write::ExactWriteIntent;
use auths_model::{Audience, TrustedContext, VerifierLimits};
use auths_profile_api::ActionProfile as _;
use auths_profile_mcp::McpProfile;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

pub(crate) const EFFECT_PLAN_TOOL: &str = "confirm_agent_effect_plan_v1";
const EFFECT_PLAN_SCHEMA: &str = "auths.agent-effect-plan/1";
const CONTENT_DOMAIN: &[u8] = b"auths.agent-effect-plan-content/1\0";
const MAX_INITIAL_TEXT_BYTES: usize = 192;

/// The full text stays in the private native action and the human's review.
/// The shared task journal retains only its length and private commitment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskEffectPlan {
    schema: String,
    task_id: String,
    task_commitment: String,
    create: ExactWriteIntent,
    populate_recipe_digest: String,
    populate_operation_id: String,
    initial_text: String,
    expires_at: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VerifiedEffectPlan {
    pub(crate) plan_commitment: String,
    pub(crate) create: ExactWriteIntent,
    pub(crate) populate_recipe_digest: String,
    pub(crate) populate_operation_id: String,
    pub(crate) content_commitment: String,
    pub(crate) content_length: u16,
    pub(crate) expires_at: u64,
}

impl VerifiedEffectPlan {
    pub(crate) fn matches_content(&self, bytes: &[u8]) -> bool {
        bytes.len() == usize::from(self.content_length)
            && content_commitment(bytes) == self.content_commitment
    }
}

fn content_commitment(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(CONTENT_DOMAIN);
    digest.update(bytes);
    hex::encode(digest.finalize())
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EffectPlanArguments {
    plan: TaskEffectPlan,
}

/// Verify the employee's sole native effect-plan action against the active
/// task and an independently verified, closed create intent. The signed text
/// remains private; its digest is not suitable for a public receipt.
pub(crate) fn verify_effect_plan(
    context: &TrustedContext,
    task: &ApprovedAgentTask,
    create: &ExactWriteIntent,
    now: u64,
    proof_cbor: &[u8],
    action_cbor: &[u8],
) -> Result<VerifiedEffectPlan, GatewaySubmitResult> {
    let card = task.descriptor();
    let pending = card
        .pending_child
        .as_ref()
        .ok_or_else(|| not_entered("gateway.task.effect-plan-no-child"))?;
    if card.write_approval_mode != WriteApprovalMode::Exact
        || now < card.not_before
        || now >= card.expires_at
        || create.task_id != card.task_id
        || create.task_commitment != hex::encode(task.commitment())
        || create.verb != TaskWriteVerb::Create
        || create.operation_id != pending.create_operation_id
        || create.recipe_digest != pending.create_recipe_digest
        || create.resource_handle != pending.parent_handle
    {
        return Err(not_entered("gateway.task.effect-plan-create"));
    }
    let audience = Audience::parse(&format!("mcp://{TASK_SERVICE}"))
        .map_err(|_| not_entered("gateway.task.effect-plan-profile"))?;
    let sealed = verify_sealed_for_audience(context, audience, now, proof_cbor, action_cbor)?;
    let action = authorized_action(&sealed)?;
    if action.action_ids().len() != 1 {
        return Err(not_entered("gateway.task.single-human-action-required"));
    }
    let command = McpProfile
        .decode_verified(action)
        .map_err(|_| not_entered("gateway.task.effect-plan-projection"))?;
    if command.call().service() != TASK_SERVICE || command.name() != EFFECT_PLAN_TOOL {
        return Err(not_entered("gateway.task.effect-plan-profile"));
    }
    let arguments: EffectPlanArguments =
        serde_json::from_value(Value::Object(command.arguments().clone()))
            .map_err(|_| not_entered("gateway.task.invalid-effect-plan"))?;
    let plan = arguments.plan;
    if plan.schema != EFFECT_PLAN_SCHEMA
        || plan.task_id != card.task_id
        || plan.task_commitment != hex::encode(task.commitment())
        || &plan.create != create
        || plan.populate_recipe_digest != pending.populate_recipe_digest
        || !valid_digest(&plan.populate_recipe_digest)
        || !valid_id(&plan.populate_operation_id)
        || plan.populate_operation_id == create.operation_id
        || plan.expires_at <= now
        || plan.expires_at > card.expires_at
        || plan.initial_text.is_empty()
        || plan.initial_text.len() > MAX_INITIAL_TEXT_BYTES
    {
        return Err(not_entered("gateway.task.effect-plan-mismatch"));
    }
    let branches = authorized_chains(proof_cbor, action)
        .map_err(|_| not_entered("gateway.policy.proof-unavailable"))?;
    let [branch] = branches.as_slice() else {
        return Err(not_entered("gateway.task.single-human-action-required"));
    };
    if branch.actor.as_str() != card.human_principal
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
    let canonical = serde_json_canonicalizer::to_vec(&plan)
        .map_err(|_| not_entered("gateway.task.invalid-effect-plan"))?;
    let plan_commitment = auths_codec::domain_commitment("auths.agent-effect-plan.v1", &canonical)
        .map_err(|_| not_entered("gateway.task.invalid-effect-plan"))?;
    Ok(VerifiedEffectPlan {
        plan_commitment: hex::encode(plan_commitment.as_bytes()),
        create: plan.create,
        populate_recipe_digest: plan.populate_recipe_digest,
        populate_operation_id: plan.populate_operation_id,
        content_commitment: content_commitment(plan.initial_text.as_bytes()),
        content_length: u16::try_from(plan.initial_text.len())
            .map_err(|_| not_entered("gateway.task.effect-plan-mismatch"))?,
        expires_at: plan.expires_at,
    })
}
