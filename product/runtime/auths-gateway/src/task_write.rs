//! Task-bound write admission. The operator chooses the typed resource field
//! from a reviewed profile; the agent cannot choose how an action maps to a
//! task scope. This module verifies intent and exact human confirmation. The
//! task-aware engine path calls it before a write claim or lease. A
//! development-only operator CLI now supplies the private pins; the human UI
//! and isolated agent channel are still separate work.

use crate::CompiledRecipe;
use crate::bounds::authorized_chains;
use crate::engine::{
    GatewaySubmitResult, VerifiedCommand, authorized_action, not_entered,
    verify_sealed_for_audience,
};
use crate::task_activation::{
    AgentTaskDescriptor, ApprovedAgentTask, TASK_SERVICE, TaskWriteScope, TaskWriteVerb,
    WriteApprovalMode,
};
use auths_model::{Audience, TrustedContext, VerifierLimits};
use auths_profile_api::ActionProfile as _;
use auths_profile_mcp::McpProfile;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub(crate) const CONFIRMATION_TOOL: &str = "confirm_agent_write_v2";

/// Reviewed installation data, committed through the task's operator policy.
/// `resource_field` is a profile field name, never a runtime JSON pointer.
#[derive(Clone)]
pub(crate) struct TaskWriteBinding {
    pub(crate) resource_field: String,
    pub(crate) verb: TaskWriteVerb,
    pub(crate) connection_id: String,
    pub(crate) connection_generation: u64,
    pub(crate) connection_subject: String,
}

/// Secret-free exact action projection for the human confirmation. The
/// request commitment binds the closed provider method, URL, headers and
/// bytes shown by the UI. Neither digest is a public content receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactWriteIntent {
    pub(crate) writer: crate::participant_enrollment::EnrolledParticipant,
    pub(crate) task_id: String,
    pub(crate) task_commitment: String,
    pub(crate) operation_id: String,
    pub(crate) action_commitment: String,
    pub(crate) request_commitment: String,
    pub(crate) recipe_digest: String,
    pub(crate) resource_handle: String,
    pub(crate) verb: TaskWriteVerb,
    pub(crate) connection_id: String,
    pub(crate) connection_generation: u64,
    pub(crate) connection_subject: String,
}

/// Minted only after the agent proof and the human's exact confirmation (or
/// the separately enabled bounded-upfront task) match the closed request.
pub(crate) struct ApprovedTaskWrite {
    intent: ExactWriteIntent,
}

impl ApprovedTaskWrite {
    pub(crate) fn intent(&self) -> &ExactWriteIntent {
        &self.intent
    }

    /// The journal contains a native-verified immutable effect plan. Only its
    /// exact create request can use the plan without a second human signature.
    pub(crate) fn from_recorded_effect_plan_create(
        plan: &crate::task_effect_plan::VerifiedEffectPlan,
        intent: ExactWriteIntent,
        now: u64,
    ) -> Result<Self, GatewaySubmitResult> {
        if now >= plan.expires_at || intent.verb != TaskWriteVerb::Create || plan.create != intent {
            return Err(not_entered("gateway.task.effect-plan-create-mismatch"));
        }
        Ok(Self { intent })
    }

    /// The same human plan permits one population only when the recorded
    /// credential-bearing preflight supplied every late-bound field.
    pub(crate) fn from_recorded_effect_plan_populate(
        plan: &crate::task_effect_plan::VerifiedEffectPlan,
        recipe: &CompiledRecipe,
        intent: ExactWriteIntent,
        arguments: &Map<String, Value>,
        preflight: &crate::task_effect_plan::PopulatePreflightFacts<'_>,
        now: u64,
    ) -> Result<Self, GatewaySubmitResult> {
        if !plan.matches_populate_action(recipe, &intent, arguments, preflight, now) {
            return Err(not_entered("gateway.task.effect-plan-populate-mismatch"));
        }
        Ok(Self { intent })
    }

    /// Recovery only: expiry stops new provider entry, but cannot erase the
    /// evidence of a create already reserved and sent under this plan.
    pub(crate) fn from_recorded_effect_plan_reconciliation(
        plan: &crate::task_effect_plan::VerifiedEffectPlan,
        intent: ExactWriteIntent,
    ) -> Result<Self, GatewaySubmitResult> {
        if intent.verb != TaskWriteVerb::Create || plan.create != intent {
            return Err(not_entered("gateway.task.effect-plan-create-mismatch"));
        }
        Ok(Self { intent })
    }

    #[cfg(test)]
    pub(crate) fn from_test_intent(intent: ExactWriteIntent) -> Self {
        Self { intent }
    }
}

fn request_commitment(verified: &VerifiedCommand) -> Result<String, GatewaySubmitResult> {
    let request = &verified.request;
    let header_pairs: Vec<_> = request
        .headers()
        .iter()
        .map(|header| (header.name(), header.value()))
        .collect();
    let value = serde_json::json!({
        "method": request.method().as_str(),
        "url": request.url(),
        "content_type": request.content_type(),
        "headers": header_pairs,
        "body_hex": hex::encode(request.body()),
    });
    let canonical = serde_json_canonicalizer::to_vec(&value)
        .map_err(|_| not_entered("gateway.task.write-request"))?;
    auths_codec::domain_commitment("auths.agent-write-request.v1", &canonical)
        .map(|digest| hex::encode(digest.as_bytes()))
        .map_err(|_| not_entered("gateway.task.write-request"))
}

/// Project a native-verified agent write through the reviewed recipe and
/// installed resource-field binding. A caller must use the same verified
/// command and recipe for the eventual gateway submission.
#[cfg(unix)]
pub(crate) fn derive_exact_write_intent(
    task: &ApprovedAgentTask,
    verified: &VerifiedCommand,
    recipe: &CompiledRecipe,
    binding: &TaskWriteBinding,
    bound_child_scope: Option<&TaskWriteScope>,
    writer: &crate::participant_enrollment::EnrolledParticipant,
    now: u64,
) -> Result<ExactWriteIntent, GatewaySubmitResult> {
    let card = task.descriptor();
    if now < card.not_before || now >= card.expires_at {
        return Err(not_entered("gateway.task.inactive"));
    }
    if verified.actors.len() != 1
        || verified.actors[0].as_str() != writer.principal()
        || !writer.matches_task(task)
    {
        return Err(not_entered("gateway.task.agent-binding"));
    }
    if binding.resource_field.is_empty()
        || !binding
            .resource_field
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || binding.connection_id != card.connection_id
        || binding.connection_generation != card.connection_generation
        || binding.connection_subject != card.connection_subject
    {
        return Err(not_entered("gateway.task.connection-binding"));
    }
    if recipe
        .task_binding()
        .is_none_or(|(field, verb)| field != binding.resource_field || verb != binding.verb)
    {
        return Err(not_entered("gateway.task.recipe-binding"));
    }
    let arguments = &verified.arguments;
    let expected_task_commitment = hex::encode(task.commitment());
    if arguments.get("task_id").and_then(Value::as_str) != Some(card.task_id.as_str())
        || arguments.get("task_commitment").and_then(Value::as_str)
            != Some(expected_task_commitment.as_str())
    {
        return Err(not_entered("gateway.task.card-binding"));
    }
    let resource = arguments
        .get(&binding.resource_field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or_else(|| not_entered("gateway.task.write-resource"))?;
    let recipe_digest = recipe.digest_hex();
    let static_scope = card.write_scopes.iter().any(|scope| {
        scope.handle == resource
            && scope.recipe_digest == recipe_digest
            && scope.verb == binding.verb
            && scope.connection_id == binding.connection_id
            && scope.connection_generation == binding.connection_generation
            && scope.connection_subject == binding.connection_subject
    });
    let child_scope = bound_child_scope.is_some_and(|scope| {
        card.pending_child.as_ref().is_some_and(|pending| {
            pending.populate_recipe_digest == scope.recipe_digest
                && pending.populate_recipe_digest == recipe_digest
        }) && scope.handle == resource
            && scope.verb == TaskWriteVerb::Edit
            && scope.verb == binding.verb
            && scope.connection_id == binding.connection_id
            && scope.connection_generation == binding.connection_generation
            && scope.connection_subject == binding.connection_subject
    });
    if !static_scope && !child_scope {
        return Err(not_entered("gateway.task.write-scope"));
    }
    let intent = ExactWriteIntent {
        writer: writer.clone(),
        task_id: card.task_id.clone(),
        task_commitment: expected_task_commitment,
        operation_id: verified.request.operation_id().as_str().to_owned(),
        action_commitment: hex::encode(verified.request.action_commitment()),
        request_commitment: request_commitment(verified)?,
        recipe_digest,
        resource_handle: resource.to_owned(),
        verb: binding.verb.clone(),
        connection_id: binding.connection_id.clone(),
        connection_generation: binding.connection_generation,
        connection_subject: binding.connection_subject.clone(),
    };
    check_pending_create(card, recipe, arguments, &intent)?;
    Ok(intent)
}

fn check_pending_create(
    card: &AgentTaskDescriptor,
    recipe: &CompiledRecipe,
    arguments: &Map<String, Value>,
    intent: &ExactWriteIntent,
) -> Result<(), GatewaySubmitResult> {
    let Some(pending) = card.pending_child.as_ref() else {
        return Ok(());
    };
    if intent.verb != TaskWriteVerb::Create {
        return Ok(());
    }
    let fields = recipe
        .created_child_fields()
        .ok_or_else(|| not_entered("gateway.task.pending-create-mismatch"))?;
    if pending.create_operation_id != intent.operation_id
        || pending.create_recipe_digest != intent.recipe_digest
        || pending.parent_handle != intent.resource_handle
        || arguments.get(fields.0).and_then(Value::as_str) != Some(pending.parent_handle.as_str())
        || arguments.get(fields.1).and_then(Value::as_str) != Some(pending.title.as_str())
        || arguments.get(fields.2).and_then(Value::as_str) != Some(pending.marker.as_str())
    {
        return Err(not_entered("gateway.task.pending-create-mismatch"));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmationArguments {
    write: ExactWriteIntent,
}

/// Verifies the human's fresh signature over the entire exact intent. The
/// caller must independently make the rendered proposal correspond to the
/// closed request before asking the human to sign it.
pub(crate) fn verify_exact_write_confirmation(
    context: &TrustedContext,
    task: &ApprovedAgentTask,
    intent: ExactWriteIntent,
    now: u64,
    proof_cbor: &[u8],
    action_cbor: &[u8],
) -> Result<ApprovedTaskWrite, GatewaySubmitResult> {
    verify_exact_write_confirmation_for_profile(
        context,
        task,
        intent,
        now,
        proof_cbor,
        action_cbor,
        (TASK_SERVICE, CONFIRMATION_TOOL),
    )
}

fn verify_exact_write_confirmation_for_profile(
    context: &TrustedContext,
    task: &ApprovedAgentTask,
    intent: ExactWriteIntent,
    now: u64,
    proof_cbor: &[u8],
    action_cbor: &[u8],
    profile: (&str, &str),
) -> Result<ApprovedTaskWrite, GatewaySubmitResult> {
    let card = task.descriptor();
    if card.write_approval_mode != WriteApprovalMode::Exact
        || now < card.not_before
        || now >= card.expires_at
        || intent.task_id != card.task_id
        || intent.task_commitment != hex::encode(task.commitment())
    {
        return Err(not_entered("gateway.task.exact-write-binding"));
    }
    let audience = Audience::parse(&format!("mcp://{}", profile.0))
        .map_err(|_| not_entered("gateway.task.confirmation-profile"))?;
    let sealed = verify_sealed_for_audience(context, audience, now, proof_cbor, action_cbor)?;
    let action = authorized_action(&sealed)?;
    if action.action_ids().len() != 1 {
        return Err(not_entered("gateway.task.single-human-action-required"));
    }
    let command = McpProfile
        .decode_verified(action)
        .map_err(|_| not_entered("gateway.task.confirmation-projection"))?;
    if command.call().service() != profile.0 || command.name() != profile.1 {
        return Err(not_entered("gateway.task.confirmation-profile"));
    }
    let arguments: ConfirmationArguments =
        serde_json::from_value(Value::Object(command.arguments().clone()))
            .map_err(|_| not_entered("gateway.task.invalid-confirmation"))?;
    if arguments.write != intent {
        return Err(not_entered("gateway.task.exact-write-mismatch"));
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
    Ok(ApprovedTaskWrite { intent })
}

/// Bounded upfront approval is a separate mode that never accepts an exact
/// confirmation as a substitute. Its one-step entry still needs the task's
/// scope, write budget and operator policy rechecked at the claim.
pub(crate) fn admit_bounded_upfront_write(
    task: &ApprovedAgentTask,
    intent: ExactWriteIntent,
    arguments: &Map<String, Value>,
    now: u64,
) -> Result<ApprovedTaskWrite, GatewaySubmitResult> {
    let card = task.descriptor();
    if card.write_approval_mode != WriteApprovalMode::BoundedUpfront
        || intent.writer.principal() != card.agent_principal
        || now < card.not_before
        || now >= card.expires_at
        || intent.task_id != card.task_id
        || intent.task_commitment != hex::encode(task.commitment())
    {
        return Err(not_entered("gateway.task.upfront-write-binding"));
    }
    let proposed: BTreeMap<String, Value> = arguments
        .iter()
        .filter(|(name, _)| {
            !matches!(
                name.as_str(),
                "operator_namespace"
                    | "operation_id"
                    | "recipe_digest"
                    | "task_id"
                    | "task_commitment"
            )
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    if !card.upfront_allowed_arguments.contains(&proposed) {
        return Err(not_entered("gateway.task.upfront-arguments-not-approved"));
    }
    Ok(ApprovedTaskWrite { intent })
}

#[cfg(test)]
mod tests {
    fn test_writer(task: &ApprovedAgentTask) -> crate::participant_enrollment::EnrolledParticipant {
        crate::participant_enrollment::EnrolledParticipant::for_test(
            &task.descriptor().agent_principal,
            task.commitment(),
            task.descriptor().delegation.partition_generation,
            task.descriptor().delegation.root_instance_generation,
        )
    }

    use super::*;
    use crate::GatewayObserver;
    use crate::engine::verify_detailed;
    use crate::harness::{self, Signer};
    use crate::observed_tests::{submission, submission_for};
    use crate::task_activation::{AgentTaskDescriptor, TaskPendingChild};
    use serde_json::{Map, json};

    const NOW: u64 = 1_790_000_000;

    #[allow(
        clippy::too_many_lines,
        reason = "fixture ties native action, recipe and task card together"
    )]
    fn setup() -> (
        ApprovedAgentTask,
        ExactWriteIntent,
        TrustedContext,
        Signer,
        Signer,
    ) {
        let root = Signer::new(0x11);
        let human = Signer::new(0x22);
        let agent = Signer::new(0x44);
        let observer = GatewayObserver::from_test_seed(0x33);
        let context = harness::context_for_agent_and_task(&root, observer.principal(), NOW)
            .expect("installed context");
        let (source, lock) = harness::recipe_sources(
            &json!({
                "task_id": {"kind": "string", "minimum": 1, "maximum": 128},
                "task_commitment": {"kind": "string", "minimum": 64, "maximum": 64}
            }),
            &json!({}),
        )
        .expect("recipe source");
        let mut source: Value = serde_json::from_slice(&source).expect("source JSON");
        source
            .as_object_mut()
            .expect("source object")
            .remove("preconditions");
        source["task_binding"] = json!({"resource_field": "record_id", "verb": "edit"});
        let recipe =
            CompiledRecipe::compile(&serde_json::to_vec(&source).expect("source bytes"), &lock)
                .expect("task-bound recipe");
        let card: AgentTaskDescriptor = serde_json::from_value(json!({
            "schema": "auths.agent-task/4",
            "task_id": "task-1",
            "company_id": "atlas",
            "initiator_principal": human.principal.as_str(),
            "approver_principal": human.principal.as_str(),
            "agent_principal": agent.principal.as_str(),
            "agent_key_fingerprint": "a".repeat(64),
            "connection_id": "jules-google",
            "connection_generation": 3,
            "connection_subject": "jules-subject",
            "read_scopes": [],
            "write_scopes": [{
                "handle": harness::RECORD,
                "recipe_digest": recipe.digest_hex(),
                "verb": "edit",
                "connection_id": "jules-google",
                "connection_generation": 3,
                "connection_subject": "jules-subject"
            }],
            "delivery_channel": "agent-channel",
            "delegation": crate::task_activation::TaskDelegationPolicy::single(&agent.principal, "agent-channel"),
            "not_before": NOW - 30,
            "expires_at": NOW + 900,
            "max_provider_calls": 0,
            "max_releases": 0,
            "max_release_bytes": 0,
            "max_writes": 1,
            "write_approval_mode": "exact",
            "operator_policy_digest": "d".repeat(64),
            "purpose": "Update a status"
        }))
        .expect("card");
        let task = ApprovedAgentTask::from_test_card(card, [0x45; 32]);
        let grant = harness::grant(&root, &agent.principal, None, NOW).expect("agent grant");
        let mut args = Map::new();
        for (key, value) in json!({
            "operator_namespace": harness::NAMESPACE,
            "operation_id": "write-1",
            "recipe_digest": recipe.digest_hex(),
            "record_id": harness::RECORD,
            "replacement": "Approved",
            "task_id": "task-1",
            "task_commitment": "45".repeat(32)
        })
        .as_object()
        .expect("object")
        {
            args.insert(key.clone(), value.clone());
        }
        let signed = submission(&root, &agent, &grant, &args, &[]);
        let verified = verify_detailed(&recipe, &context, NOW, &signed.proof, &signed.action)
            .expect("native agent verification");
        let binding = TaskWriteBinding {
            resource_field: "record_id".to_owned(),
            verb: TaskWriteVerb::Edit,
            connection_id: "jules-google".to_owned(),
            connection_generation: 3,
            connection_subject: "jules-subject".to_owned(),
        };
        let intent = derive_exact_write_intent(
            &task,
            &verified,
            &recipe,
            &binding,
            None,
            &test_writer(&task),
            NOW,
        )
        .expect("task-bound intent");
        assert_eq!(intent.resource_handle, harness::RECORD);
        assert_eq!(intent.action_commitment, hex::encode(signed.commitment));
        let wrong_connection = TaskWriteBinding {
            connection_generation: 4,
            ..binding.clone()
        };
        assert!(
            derive_exact_write_intent(
                &task,
                &verified,
                &recipe,
                &wrong_connection,
                None,
                &test_writer(&task),
                NOW
            )
            .is_err()
        );
        let wrong_resource = TaskWriteBinding {
            resource_field: "task_id".to_owned(),
            ..binding.clone()
        };
        assert!(
            derive_exact_write_intent(
                &task,
                &verified,
                &recipe,
                &wrong_resource,
                None,
                &test_writer(&task),
                NOW
            )
            .is_err()
        );
        let mut different_card = task.descriptor().clone();
        different_card.write_scopes[0].handle = "other-record".to_owned();
        let different_task = ApprovedAgentTask::from_test_card(different_card, *task.commitment());
        assert!(
            derive_exact_write_intent(
                &different_task,
                &verified,
                &recipe,
                &binding,
                None,
                &test_writer(&task),
                NOW
            )
            .is_err()
        );
        let mut different_card = task.descriptor().clone();
        different_card.delegation.partition_generation += 1;
        let different_task = ApprovedAgentTask::from_test_card(different_card, *task.commitment());
        assert!(
            derive_exact_write_intent(
                &different_task,
                &verified,
                &recipe,
                &binding,
                None,
                &test_writer(&task),
                NOW
            )
            .is_err()
        );
        (task, intent, context, root, human)
    }

    #[test]
    fn pending_create_requires_the_signed_operation_parent_title_and_marker() {
        let (task, mut intent, _, _, _) = setup();
        let recipe = CompiledRecipe::compile(
            include_bytes!(
                "../../../../demos/google-employee-delegation/create_reference/recipe.json"
            ),
            include_bytes!(
                "../../../../demos/google-employee-delegation/create_reference/profile.lock.json"
            ),
        )
        .expect("reviewed create recipe");
        let mut card = task.descriptor().clone();
        let pending = TaskPendingChild {
            create_operation_id: "create-1".to_owned(),
            create_recipe_digest: recipe.digest_hex(),
            populate_recipe_digest: "f".repeat(64),
            parent_handle: "project-a-folder".to_owned(),
            title: "Auths AP-071 Project A handoff".to_owned(),
            marker: format!("ap071_{}", "d".repeat(32)),
        };
        card.pending_child = Some(pending.clone());
        intent.verb = TaskWriteVerb::Create;
        intent.operation_id = pending.create_operation_id.clone();
        intent.recipe_digest = pending.create_recipe_digest.clone();
        intent.resource_handle = pending.parent_handle.clone();
        let arguments = Map::from_iter([
            ("parent_id".to_owned(), json!(pending.parent_handle)),
            ("title".to_owned(), json!(pending.title)),
            ("recovery_marker".to_owned(), json!(pending.marker)),
        ]);
        check_pending_create(&card, &recipe, &arguments, &intent).expect("exact create proposal");
        let mut wrong = intent.clone();
        wrong.operation_id = "other-create".to_owned();
        assert!(check_pending_create(&card, &recipe, &arguments, &wrong).is_err());
        wrong = intent.clone();
        wrong.resource_handle = "project-b-folder".to_owned();
        assert!(check_pending_create(&card, &recipe, &arguments, &wrong).is_err());
        wrong = intent.clone();
        wrong.recipe_digest = "0".repeat(64);
        assert!(check_pending_create(&card, &recipe, &arguments, &wrong).is_err());
        let mut changed = arguments;
        changed.insert(
            "recovery_marker".to_owned(),
            json!(format!("ap071_{}", "a".repeat(32))),
        );
        assert!(check_pending_create(&card, &recipe, &changed, &intent).is_err());
        changed.insert("recovery_marker".to_owned(), json!(pending.marker));
        changed.insert("title".to_owned(), json!("Different title"));
        assert!(check_pending_create(&card, &recipe, &changed, &intent).is_err());
        changed.insert("title".to_owned(), json!(pending.title));
        let mut source: Value = serde_json::from_slice(include_bytes!(
            "../../../../demos/google-employee-delegation/create_reference/recipe.json"
        ))
        .expect("create source");
        source
            .as_object_mut()
            .expect("recipe object")
            .remove("created_child");
        let without_mapping = CompiledRecipe::compile(
            &serde_json::to_vec(&source).expect("source bytes"),
            include_bytes!(
                "../../../../demos/google-employee-delegation/create_reference/profile.lock.json"
            ),
        )
        .expect("ordinary create recipe");
        assert!(check_pending_create(&card, &without_mapping, &changed, &intent).is_err());
    }

    fn populate_card(
        human: &Signer,
        agent: &Signer,
        recipe: &CompiledRecipe,
    ) -> AgentTaskDescriptor {
        serde_json::from_value(json!({
            "schema": "auths.agent-task/4",
            "task_id": "task-1",
            "company_id": "atlas",
            "initiator_principal": human.principal.as_str(),
            "approver_principal": human.principal.as_str(),
            "agent_principal": agent.principal.as_str(),
            "agent_key_fingerprint": "a".repeat(64),
            "connection_id": "jules-google",
            "connection_generation": 3,
            "connection_subject": "jules-subject",
            "read_scopes": [],
            "write_scopes": [{"handle": "project-a-folder", "recipe_digest": "e".repeat(64),
                "verb": "create", "connection_id": "jules-google",
                "connection_generation": 3, "connection_subject": "jules-subject"}],
            "pending_child": {"create_operation_id": "create-1",
                "create_recipe_digest": "e".repeat(64),
                "populate_recipe_digest": recipe.digest_hex(),
                "parent_handle": "project-a-folder",
                "title": "Auths AP-071 Project A handoff",
                "marker": format!("ap071_{}", "d".repeat(32))},
            "delivery_channel": "agent-channel",
            "delegation": crate::task_activation::TaskDelegationPolicy::single(&agent.principal, "agent-channel"),
            "not_before": NOW - 30,
            "expires_at": NOW + 900,
            "max_provider_calls": 0,
            "max_releases": 0,
            "max_release_bytes": 0,
            "max_writes": 2,
            "write_approval_mode": "exact",
            "operator_policy_digest": "d".repeat(64),
            "purpose": "Populate one Project A child"
        }))
        .expect("card")
    }

    #[test]
    fn populate_intent_requires_the_durable_child_scope() {
        let root = Signer::new(0x11);
        let human = Signer::new(0x22);
        let agent = Signer::new(0x44);
        let observer = GatewayObserver::from_test_seed(0x33);
        let context = harness::context_for_agent_and_task_profile(
            &root,
            observer.principal(),
            NOW,
            "google-docs-delegation-demo",
            "populate_created_project_a_document_v1",
        )
        .expect("installed context");
        let recipe = CompiledRecipe::compile(
            include_bytes!(
                "../../../../demos/google-employee-delegation/populate_reference/recipe.json"
            ),
            include_bytes!(
                "../../../../demos/google-employee-delegation/populate_reference/profile.lock.json"
            ),
        )
        .expect("reviewed populate recipe");
        let card = populate_card(&human, &agent, &recipe);
        let task = ApprovedAgentTask::from_test_card(card, [0x45; 32]);
        let grant = harness::grant_for(
            &root,
            &agent.principal,
            NOW,
            "google-docs-delegation-demo",
            "populate_created_project_a_document_v1",
        )
        .expect("agent grant");
        let args = json!({
            "operator_namespace": "google-docs-populate-demo",
            "operation_id": "populate-1",
            "recipe_digest": recipe.digest_hex(),
            "task_id": "task-1",
            "task_commitment": "45".repeat(32),
            "document_id": "child_ABC-123",
            "tab_id": "t.0",
            "text": "Project A handoff draft.",
            "required_revision_id": "revision-1"
        });
        let signed = submission_for(
            &root,
            &agent,
            &grant,
            args.as_object().expect("args"),
            &[],
            "google-docs-delegation-demo",
            "populate_created_project_a_document_v1",
            NOW,
        );
        let verified = verify_detailed(&recipe, &context, NOW, &signed.proof, &signed.action)
            .expect("native agent action");
        let binding = TaskWriteBinding {
            resource_field: "document_id".to_owned(),
            verb: TaskWriteVerb::Edit,
            connection_id: "jules-google".to_owned(),
            connection_generation: 3,
            connection_subject: "jules-subject".to_owned(),
        };
        let derive = |scope: Option<&TaskWriteScope>| {
            derive_exact_write_intent(
                &task,
                &verified,
                &recipe,
                &binding,
                scope,
                &test_writer(&task),
                NOW,
            )
        };
        assert!(derive(None).is_err());
        let child_scope = TaskWriteScope {
            handle: "child_ABC-123".to_owned(),
            recipe_digest: recipe.digest_hex(),
            verb: TaskWriteVerb::Edit,
            connection_id: binding.connection_id.clone(),
            connection_generation: binding.connection_generation,
            connection_subject: binding.connection_subject.clone(),
        };
        let intent = derive(Some(&child_scope)).expect("bound child intent");
        assert_eq!(intent.resource_handle, "child_ABC-123");
        let mut wrong = child_scope.clone();
        wrong.handle = "other-child".to_owned();
        assert!(derive(Some(&wrong)).is_err());
        wrong = child_scope;
        wrong.recipe_digest = "0".repeat(64);
        assert!(derive(Some(&wrong)).is_err());
    }

    fn confirmation(
        root: &Signer,
        human: &Signer,
        intent: &ExactWriteIntent,
    ) -> (Vec<u8>, Vec<u8>) {
        let grant = harness::grant(root, &human.principal, None, NOW).expect("human grant");
        let mut arguments = Map::new();
        arguments.insert(
            "write".to_owned(),
            serde_json::to_value(intent).expect("intent"),
        );
        let signed = submission(root, human, &grant, &arguments, &[]);
        (signed.proof, signed.action)
    }

    fn confirmation_for_exact_profile(
        root: &Signer,
        human: &Signer,
        intent: &ExactWriteIntent,
    ) -> (Vec<u8>, Vec<u8>) {
        let grant =
            harness::grant_for(root, &human.principal, NOW, TASK_SERVICE, CONFIRMATION_TOOL)
                .expect("human confirmation grant");
        let mut arguments = Map::new();
        arguments.insert(
            "write".to_owned(),
            serde_json::to_value(intent).expect("intent"),
        );
        let signed = submission_for(
            root,
            human,
            &grant,
            &arguments,
            &[],
            TASK_SERVICE,
            CONFIRMATION_TOOL,
            NOW,
        );
        (signed.proof, signed.action)
    }

    #[test]
    fn exact_human_signature_binds_the_native_agent_action_and_closed_request() {
        let (task, intent, context, root, human) = setup();
        let (proof, action) = confirmation_for_exact_profile(&root, &human, &intent);
        let approved =
            verify_exact_write_confirmation(&context, &task, intent.clone(), NOW, &proof, &action)
                .expect("exact confirmation");
        assert_eq!(approved.intent(), &intent);

        let mut changed = intent.clone();
        changed.request_commitment = "0".repeat(64);
        assert!(
            verify_exact_write_confirmation(&context, &task, changed, NOW, &proof, &action,)
                .is_err()
        );
        let mut changed = intent.clone();
        changed.operation_id = "write-2".to_owned();
        assert!(
            verify_exact_write_confirmation(&context, &task, changed, NOW, &proof, &action,)
                .is_err()
        );
        let wrong_human = Signer::new(0x66);
        let (proof, action) = confirmation_for_exact_profile(&root, &wrong_human, &intent);
        assert!(
            verify_exact_write_confirmation(&context, &task, intent, NOW, &proof, &action,)
                .is_err()
        );
    }

    #[test]
    fn exact_and_bounded_upfront_modes_are_distinct() {
        let (task, intent, context, root, human) = setup();
        let approved_arguments = Map::from_iter([
            ("record_id".to_owned(), json!(harness::RECORD)),
            ("replacement".to_owned(), json!("Approved")),
        ]);
        assert!(
            admit_bounded_upfront_write(&task, intent.clone(), &approved_arguments, NOW).is_err()
        );
        let mut card = task.descriptor().clone();
        card.write_approval_mode = WriteApprovalMode::BoundedUpfront;
        card.upfront_allowed_arguments = vec![approved_arguments.clone().into_iter().collect()];
        let upfront = ApprovedAgentTask::from_test_card(card, *task.commitment());
        assert!(
            admit_bounded_upfront_write(&upfront, intent.clone(), &approved_arguments, NOW).is_ok()
        );
        let mut changed = approved_arguments.clone();
        changed.insert("replacement".to_owned(), json!("Unapproved"));
        assert_eq!(
            admit_bounded_upfront_write(&upfront, intent.clone(), &changed, NOW).err(),
            Some(not_entered("gateway.task.upfront-arguments-not-approved")),
        );
        changed = approved_arguments.clone();
        changed.insert("extra".to_owned(), json!("unexpected"));
        assert!(admit_bounded_upfront_write(&upfront, intent.clone(), &changed, NOW).is_err());
        let mut bound = approved_arguments.clone();
        bound.insert("operation_id".to_owned(), json!("any-valid-operation"));
        assert!(admit_bounded_upfront_write(&upfront, intent.clone(), &bound, NOW).is_ok());
        let (proof, action) = confirmation(&root, &human, &intent);
        assert!(
            verify_exact_write_confirmation_for_profile(
                &context,
                &upfront,
                intent,
                NOW,
                &proof,
                &action,
                (harness::SERVICE, harness::TOOL),
            )
            .is_err()
        );
    }
}
