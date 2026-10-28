//! One human signature over a task-bound create and its initial population.
//! This module only verifies and projects the plan. Provider admission must
//! separately compare both closed requests and fresh late-bound read values.

use crate::CompiledRecipe;
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
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

pub(crate) const EFFECT_PLAN_TOOL: &str = "confirm_agent_effect_plan_v2";
const EFFECT_PLAN_SCHEMA: &str = "auths.agent-effect-plan/2";
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) preflight_rule_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) preflight_key_sha256: Option<String>,
}

/// Comparison inputs only. A caller may use these facts for admission only
/// after a separate credential-bearing preflight has authenticated and
/// durably bound them to the task and response-derived child.
#[allow(
    dead_code,
    reason = "submission binding follows authenticated preflight custody"
)]
pub(crate) struct PopulatePreflightFacts<'a> {
    pub(crate) child_id: &'a str,
    pub(crate) provider_values: &'a BTreeMap<String, String>,
    pub(crate) connection_subject: &'a str,
    pub(crate) connection_generation: u64,
    pub(crate) checked_at: u64,
    pub(crate) valid_until: u64,
}

impl VerifiedEffectPlan {
    pub(crate) fn bind_preflight_policy(mut self, policy: Option<(&str, &str)>) -> Self {
        if let Some((rule_digest, public_key_hex)) = policy {
            self.preflight_rule_digest = Some(rule_digest.to_owned());
            self.preflight_key_sha256 = Some(hex::encode(Sha256::digest(
                hex::decode(public_key_hex).expect("validated installation key"),
            )));
        }
        self
    }

    pub(crate) fn matches_content(&self, bytes: &[u8]) -> bool {
        bytes.len() == usize::from(self.content_length)
            && content_commitment(bytes) == self.content_commitment
    }

    /// The reviewed population recipe names every provider-affecting field.
    /// The child and every provider precondition must come from the task
    /// binding and a separately authenticated credential-bearing preflight.
    #[allow(
        dead_code,
        reason = "submission binding follows authenticated preflight custody"
    )]
    pub(crate) fn matches_populate_action(
        &self,
        recipe: &CompiledRecipe,
        intent: &ExactWriteIntent,
        arguments: &Map<String, Value>,
        preflight: &PopulatePreflightFacts<'_>,
        now: u64,
    ) -> bool {
        let Some((text_field, preflight_fields)) = recipe.task_populate_fields() else {
            return false;
        };
        let Some(text) = arguments.get(text_field).and_then(Value::as_str) else {
            return false;
        };
        self.expires_at > now
            && preflight.checked_at <= now
            && now < preflight.valid_until
            && preflight.valid_until <= self.expires_at
            && intent.writer == self.create.writer
            && intent.task_id == self.create.task_id
            && intent.task_commitment == self.create.task_commitment
            && intent.operation_id == self.populate_operation_id
            && intent.recipe_digest == self.populate_recipe_digest
            && intent.resource_handle == preflight.child_id
            && intent.verb == TaskWriteVerb::Edit
            && intent.connection_id == self.create.connection_id
            && intent.connection_generation == self.create.connection_generation
            && intent.connection_subject == self.create.connection_subject
            && preflight.connection_subject == self.create.connection_subject
            && preflight.connection_generation == self.create.connection_generation
            && self.matches_content(text.as_bytes())
            && preflight.provider_values.len() == preflight_fields.len()
            && preflight_fields.iter().all(|field| {
                arguments.get(field).and_then(Value::as_str)
                    == preflight.provider_values.get(field).map(String::as_str)
            })
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
    if branch.actor.as_str() != card.approver_principal
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
    let plan_commitment = auths_codec::domain_commitment("auths.agent-effect-plan.v2", &canonical)
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
        preflight_rule_digest: None,
        preflight_key_sha256: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn assert_todoist_population(
        plan: &VerifiedEffectPlan,
        populate: &ExactWriteIntent,
        recipe: &CompiledRecipe,
        wrong_google_fields: &PopulatePreflightFacts<'_>,
    ) {
        let todoist = CompiledRecipe::compile(
            include_bytes!("../../../../demos/todoist-gateway/populate_reference/recipe.json"),
            include_bytes!(
                "../../../../demos/todoist-gateway/populate_reference/profile.lock.json"
            ),
        )
        .expect("independent populate recipe");
        let mut todoist_plan = plan.clone();
        todoist_plan.populate_recipe_digest = todoist.digest_hex();
        let mut todoist_action = populate.clone();
        todoist_action.recipe_digest = todoist.digest_hex();
        let todoist_preflight = PopulatePreflightFacts {
            child_id: "child-1",
            provider_values: &BTreeMap::new(),
            connection_subject: "jules",
            connection_generation: 7,
            checked_at: 99,
            valid_until: 110,
        };
        let mut todoist_arguments = json!({"text": "Approved text"})
            .as_object()
            .expect("arguments")
            .clone();
        assert!(todoist_plan.matches_populate_action(
            &todoist,
            &todoist_action,
            &todoist_arguments,
            &todoist_preflight,
            100,
        ));
        todoist_arguments.insert("text".into(), json!("Different text"));
        assert!(!todoist_plan.matches_populate_action(
            &todoist,
            &todoist_action,
            &todoist_arguments,
            &todoist_preflight,
            100,
        ));
        todoist_arguments.insert("text".into(), json!("Approved text"));
        let mut mismatched_child = todoist_action.clone();
        mismatched_child.resource_handle = "other-child".into();
        assert!(!todoist_plan.matches_populate_action(
            &todoist,
            &mismatched_child,
            &todoist_arguments,
            &todoist_preflight,
            100,
        ));
        assert!(!todoist_plan.matches_populate_action(
            &todoist,
            &todoist_action,
            &todoist_arguments,
            wrong_google_fields,
            100,
        ));
        assert!(!todoist_plan.matches_populate_action(
            &todoist,
            &todoist_action,
            &todoist_arguments,
            &todoist_preflight,
            110,
        ));
        let wrong_todoist_subject = PopulatePreflightFacts {
            connection_subject: "other-human",
            ..todoist_preflight
        };
        assert!(!todoist_plan.matches_populate_action(
            &todoist,
            &todoist_action,
            &todoist_arguments,
            &wrong_todoist_subject,
            100,
        ));
        let mut wrong_todoist_recipe = todoist_action.clone();
        wrong_todoist_recipe.recipe_digest = recipe.digest_hex();
        assert!(!todoist_plan.matches_populate_action(
            &todoist,
            &wrong_todoist_recipe,
            &todoist_arguments,
            &todoist_preflight,
            100,
        ));
    }

    #[test]
    fn planned_population_matches_only_approved_content_and_fresh_fields() {
        let recipe = CompiledRecipe::compile(
            include_bytes!(
                "../../../../demos/google-employee-delegation/populate_reference/recipe.json"
            ),
            include_bytes!(
                "../../../../demos/google-employee-delegation/populate_reference/profile.lock.json"
            ),
        )
        .expect("reviewed populate recipe");
        let create = ExactWriteIntent {
            writer: crate::participant_enrollment::EnrolledParticipant::for_test(
                "test-agent",
                &[0xaa; 32],
                1,
                1,
            ),
            task_id: "task-1".into(),
            task_commitment: "a".repeat(64),
            operation_id: "create-1".into(),
            action_commitment: "b".repeat(64),
            request_commitment: "c".repeat(64),
            recipe_digest: "d".repeat(64),
            resource_handle: "project-a".into(),
            verb: TaskWriteVerb::Create,
            connection_id: "connection-1".into(),
            connection_generation: 7,
            connection_subject: "jules".into(),
        };
        let plan = VerifiedEffectPlan {
            plan_commitment: "e".repeat(64),
            create: create.clone(),
            populate_recipe_digest: recipe.digest_hex(),
            populate_operation_id: "populate-1".into(),
            content_commitment: content_commitment(b"Approved text"),
            content_length: 13,
            expires_at: 200,
            preflight_rule_digest: None,
            preflight_key_sha256: None,
        };
        let mut populate = create;
        populate.operation_id = "populate-1".into();
        populate.recipe_digest = recipe.digest_hex();
        populate.resource_handle = "child-1".into();
        populate.verb = TaskWriteVerb::Edit;
        let mut arguments = json!({
            "text": "Approved text", "tab_id": "t.0",
            "required_revision_id": "revision-1"
        })
        .as_object()
        .expect("arguments")
        .clone();
        let preflight = PopulatePreflightFacts {
            child_id: "child-1",
            provider_values: &BTreeMap::from([
                ("required_revision_id".to_owned(), "revision-1".to_owned()),
                ("tab_id".to_owned(), "t.0".to_owned()),
            ]),
            connection_subject: "jules",
            connection_generation: 7,
            checked_at: 99,
            valid_until: 110,
        };
        let matches = |arguments: &Map<String, Value>, intent: &ExactWriteIntent| {
            plan.matches_populate_action(&recipe, intent, arguments, &preflight, 100)
        };
        assert!(matches(&arguments, &populate));
        arguments.insert("text".into(), json!("Changed text"));
        assert!(!matches(&arguments, &populate));
        arguments.insert("text".into(), json!("Approved text"));
        arguments.insert("tab_id".into(), json!("other-tab"));
        assert!(!matches(&arguments, &populate));
        arguments.insert("tab_id".into(), json!("t.0"));
        let mut wrong_child = populate.clone();
        wrong_child.resource_handle = "other-child".into();
        assert!(!matches(&arguments, &wrong_child));
        assert!(!plan.matches_populate_action(&recipe, &populate, &arguments, &preflight, 110,));
        let unexpected_values = BTreeMap::from([("extra".to_owned(), "value".to_owned())]);
        let wrong_google_fields = PopulatePreflightFacts {
            provider_values: &unexpected_values,
            ..preflight
        };
        assert!(!plan.matches_populate_action(
            &recipe,
            &populate,
            &arguments,
            &wrong_google_fields,
            100,
        ));

        assert_todoist_population(&plan, &populate, &recipe, &wrong_google_fields);
    }
}
