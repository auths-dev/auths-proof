//! Provider-neutral task envelope with distinct initiator and approver roles.
//! Native verification authenticates activation by the pinned initiator; exact
//! effects require the independent approver. Provider access is a later check.

use crate::bounds::authorized_chains;
use crate::engine::{
    GatewaySubmitResult, authorized_action, not_entered, verify_sealed_for_audience,
};
use crate::release_state::{ReleaseResourceScope, ReleaseTaskPolicy};
use auths_model::{Audience, PrincipalId, TrustedContext, VerifierLimits};
use auths_profile_api::ActionProfile as _;
use auths_profile_mcp::McpProfile;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const TASK_SCHEMA: &str = "auths.agent-task/3";
pub(crate) const TASK_SERVICE: &str = "auths-agent-task";
pub(crate) const APPROVAL_TOOL: &str = "approve_agent_task_v1";
const MAX_SCOPES: usize = 16;
const MAX_TASK_SECONDS: u64 = 86_400;
const MAX_WRITES: u32 = 32;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskReadScope {
    handle: String,
    recipe_digest: String,
    connection_id: String,
    connection_generation: u64,
    connection_subject: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TaskWriteVerb {
    Edit,
    Create,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskWriteScope {
    pub(crate) handle: String,
    pub(crate) recipe_digest: String,
    pub(crate) verb: TaskWriteVerb,
    pub(crate) connection_id: String,
    pub(crate) connection_generation: u64,
    pub(crate) connection_subject: String,
}

/// A human-approved child that does not exist at task activation. This is a
/// proposal, not an executable write scope: only a later verified binding
/// may make `populate_recipe_digest` usable for the returned child ID.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskPendingChild {
    pub(crate) create_operation_id: String,
    pub(crate) create_recipe_digest: String,
    pub(crate) populate_recipe_digest: String,
    pub(crate) parent_handle: String,
    pub(crate) title: String,
    pub(crate) marker: String,
}

impl TaskPendingChild {
    fn valid_for(&self, card: &AgentTaskDescriptor) -> bool {
        card.write_approval_mode == WriteApprovalMode::Exact
            && card.max_writes >= 2
            && bounded_text(&self.create_operation_id, 128)
            && digest(&self.create_recipe_digest)
            && digest(&self.populate_recipe_digest)
            && self.create_recipe_digest != self.populate_recipe_digest
            && bounded_text(&self.parent_handle, 256)
            && bounded_text(&self.title, 256)
            && bounded_text(&self.marker, 256)
            && card
                .write_scopes
                .iter()
                .filter(|scope| scope.verb == TaskWriteVerb::Create)
                .count()
                == 1
            && card.write_scopes.iter().any(|scope| {
                scope.verb == TaskWriteVerb::Create
                    && scope.handle == self.parent_handle
                    && scope.recipe_digest == self.create_recipe_digest
            })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum WriteApprovalMode {
    Exact,
    BoundedUpfront,
}

/// Exact structured card the initiator signs as one native MCP
/// action. Handles and recipe digests are opaque to this shared contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentTaskDescriptor {
    schema: String,
    pub(crate) task_id: String,
    company_id: String,
    pub(crate) initiator_principal: String,
    pub(crate) approver_principal: String,
    pub(crate) agent_principal: String,
    pub(crate) agent_key_fingerprint: String,
    pub(crate) connection_id: String,
    pub(crate) connection_generation: u64,
    pub(crate) connection_subject: String,
    read_scopes: Vec<TaskReadScope>,
    pub(crate) write_scopes: Vec<TaskWriteScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) pending_child: Option<TaskPendingChild>,
    pub(crate) delivery_channel: String,
    pub(crate) not_before: u64,
    pub(crate) expires_at: u64,
    max_provider_calls: u32,
    max_releases: u32,
    max_release_bytes: u64,
    pub(crate) max_writes: u32,
    pub(crate) write_approval_mode: WriteApprovalMode,
    /// Complete profile arguments the human allows in upfront mode, except
    /// operation and task binding fields inserted by the gateway.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) upfront_allowed_arguments: Vec<BTreeMap<String, Value>>,
    operator_policy_digest: String,
    purpose: String,
}

/// Operator-installed values re-read at activation. These are independent of
/// the initiator's submitted action and must come from active company, agent and
/// connection records, including the provider's stable account subject.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskActivationPins {
    pub(crate) company_id: String,
    pub(crate) initiator_principal: String,
    pub(crate) approver_principal: String,
    pub(crate) agent_principal: String,
    pub(crate) agent_key_fingerprint: String,
    pub(crate) connection_id: String,
    pub(crate) connection_generation: u64,
    pub(crate) connection_subject: String,
    /// Operator-reviewed read recipe connections. The signed card may select
    /// a subset, but cannot invent a connection or substitute its subject.
    pub(crate) permitted_read_scopes: Vec<TaskReadScope>,
    pub(crate) delivery_channel: String,
    pub(crate) operator_policy_digest: String,
    pub(crate) allow_bounded_writes: bool,
}

impl TaskActivationPins {
    pub(crate) fn permits_read_recipe(&self, digest: &str) -> bool {
        self.permitted_read_scopes
            .iter()
            .any(|scope| scope.recipe_digest == digest)
    }
}

/// A verified activation of the exact task card by its initiator. No public constructor
/// exists; the read ledger can derive its policy only from this value.
pub(crate) struct ApprovedAgentTask {
    descriptor: AgentTaskDescriptor,
    commitment: [u8; 32],
}

impl ApprovedAgentTask {
    /// Reconstruct only a card already stored by the operator's successful
    /// activation. The original short-lived proof is not a task-session token.
    pub(crate) fn from_activated_card(
        descriptor: AgentTaskDescriptor,
        commitment: [u8; 32],
        pins: &TaskActivationPins,
        now: u64,
    ) -> Result<Self, GatewaySubmitResult> {
        descriptor.validate(pins, now)?;
        if descriptor.canonical_commitment()? != commitment {
            return Err(not_entered("gateway.task.activation-changed"));
        }
        Ok(Self {
            descriptor,
            commitment,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_test_card(descriptor: AgentTaskDescriptor, commitment: [u8; 32]) -> Self {
        Self {
            descriptor,
            commitment,
        }
    }
    pub(crate) fn task_policy(&self) -> ReleaseTaskPolicy {
        ReleaseTaskPolicy {
            task_id: self.descriptor.task_id.clone(),
            task_commitment: self.commitment,
            company_id: self.descriptor.company_id.clone(),
            initiator_principal: self.descriptor.initiator_principal.clone(),
            agent_principal: self.descriptor.agent_principal.clone(),
            not_before: self.descriptor.not_before,
            expires_at: self.descriptor.expires_at,
            max_provider_calls: self.descriptor.max_provider_calls,
            max_releases: self.descriptor.max_releases,
            max_release_bytes: self.descriptor.max_release_bytes,
            max_writes: self.descriptor.max_writes,
            write_scopes: self.descriptor.write_scopes.clone(),
            connection_id: self.descriptor.connection_id.clone(),
            connection_generation: self.descriptor.connection_generation,
            connection_subject: self.descriptor.connection_subject.clone(),
            resources: self
                .descriptor
                .read_scopes
                .iter()
                .map(|scope| ReleaseResourceScope {
                    handle: scope.handle.clone(),
                    recipe_digest: scope.recipe_digest.clone(),
                    connection_id: scope.connection_id.clone(),
                    connection_generation: scope.connection_generation,
                    connection_subject: scope.connection_subject.clone(),
                })
                .collect(),
        }
    }

    pub(crate) const fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }

    pub(crate) fn descriptor(&self) -> &AgentTaskDescriptor {
        &self.descriptor
    }
}

fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_upfront_choices(choices: &[BTreeMap<String, Value>]) -> bool {
    let shapes_are_bounded = choices.iter().all(|allowed| {
        !allowed.is_empty()
            && allowed.len() <= 32
            && allowed.keys().all(|name| {
                !matches!(
                    name.as_str(),
                    "operator_namespace"
                        | "operation_id"
                        | "recipe_digest"
                        | "task_id"
                        | "task_commitment"
                )
            })
            && serde_json_canonicalizer::to_vec(allowed).is_ok_and(|bytes| bytes.len() <= 4_096)
    });
    shapes_are_bounded
        && !choices
            .iter()
            .enumerate()
            .any(|(index, allowed)| choices[index + 1..].contains(allowed))
}

impl AgentTaskDescriptor {
    /// One owner for task canonicalization and its versioned commitment domain.
    fn canonical_commitment(&self) -> Result<[u8; 32], GatewaySubmitResult> {
        let canonical = serde_json_canonicalizer::to_vec(self)
            .map_err(|_| not_entered("gateway.task.invalid-card"))?;
        auths_codec::domain_commitment("auths.agent-task.v3", &canonical)
            .map(|commitment| *commitment.as_bytes())
            .map_err(|_| not_entered("gateway.task.invalid-card"))
    }

    pub(crate) fn recipes_installed(&self, digests: &[String]) -> bool {
        self.write_scopes
            .iter()
            .all(|scope| digests.contains(&scope.recipe_digest))
            && self.pending_child.as_ref().is_none_or(|pending| {
                digests.contains(&pending.create_recipe_digest)
                    && digests.contains(&pending.populate_recipe_digest)
            })
    }

    fn roles_valid(&self) -> bool {
        [
            &self.initiator_principal,
            &self.approver_principal,
            &self.agent_principal,
        ]
        .into_iter()
        .all(|principal| PrincipalId::parse(principal).is_ok())
            && self.initiator_principal != self.agent_principal
            && self.approver_principal != self.agent_principal
            && (self.write_approval_mode != WriteApprovalMode::BoundedUpfront
                || self.initiator_principal == self.approver_principal)
    }

    fn validate(&self, pins: &TaskActivationPins, now: u64) -> Result<(), GatewaySubmitResult> {
        if self.schema != TASK_SCHEMA
            || !bounded_text(&self.task_id, 128)
            || !bounded_text(&self.company_id, 128)
            || !bounded_text(&self.connection_id, 128)
            || !bounded_text(&self.connection_subject, 256)
            || !bounded_text(&self.delivery_channel, 256)
            || !bounded_text(&self.purpose, 512)
            || !digest(&self.agent_key_fingerprint)
            || !digest(&self.operator_policy_digest)
            || !self.roles_valid()
            || self.connection_generation == 0
            || self.not_before > now
            || now >= self.expires_at
            || self.expires_at - self.not_before > MAX_TASK_SECONDS
            || self.read_scopes.len() > MAX_SCOPES
            || self.write_scopes.len() > MAX_SCOPES
            || (self.read_scopes.is_empty() && self.write_scopes.is_empty())
            || self.max_provider_calls > 64
            || self.max_releases > self.max_provider_calls
            || self.max_release_bytes > 16 * 1_048_576
            || self.max_writes > MAX_WRITES
            || (self.read_scopes.is_empty()
                != (self.max_provider_calls == 0
                    && self.max_releases == 0
                    && self.max_release_bytes == 0))
            || (!self.read_scopes.is_empty()
                && (self.max_releases == 0 || self.max_release_bytes == 0))
            || (self.write_scopes.is_empty() != (self.max_writes == 0))
            || (self.write_approval_mode == WriteApprovalMode::BoundedUpfront
                && !pins.allow_bounded_writes)
            || (self.write_approval_mode == WriteApprovalMode::Exact
                && !self.upfront_allowed_arguments.is_empty())
            || (self.write_approval_mode == WriteApprovalMode::BoundedUpfront
                && (self.max_writes != 1
                    || self.upfront_allowed_arguments.is_empty()
                    || self.upfront_allowed_arguments.len() > 4))
            || (self.write_scopes.is_empty()
                && self.write_approval_mode != WriteApprovalMode::Exact)
        {
            return Err(not_entered("gateway.task.invalid-card"));
        }
        if !valid_upfront_choices(&self.upfront_allowed_arguments) {
            return Err(not_entered("gateway.task.invalid-upfront-allowance"));
        }
        let mut reads = BTreeSet::new();
        for scope in &self.read_scopes {
            if !bounded_text(&scope.handle, 256)
                || !digest(&scope.recipe_digest)
                || !bounded_text(&scope.connection_id, 128)
                || scope.connection_generation == 0
                || !bounded_text(&scope.connection_subject, 256)
                || !pins.permitted_read_scopes.contains(scope)
                || !reads.insert(&scope.handle)
            {
                return Err(not_entered("gateway.task.invalid-read-scope"));
            }
        }
        let mut writes = BTreeSet::new();
        for scope in &self.write_scopes {
            if !bounded_text(&scope.handle, 256)
                || !digest(&scope.recipe_digest)
                || scope.connection_id != self.connection_id
                || scope.connection_generation != self.connection_generation
                || scope.connection_subject != self.connection_subject
                || !writes.insert((&scope.handle, &scope.verb))
            {
                return Err(not_entered("gateway.task.invalid-write-scope"));
            }
        }
        if self
            .pending_child
            .as_ref()
            .is_some_and(|pending| !pending.valid_for(self))
        {
            return Err(not_entered("gateway.task.invalid-pending-child"));
        }
        if self.company_id != pins.company_id
            || self.initiator_principal != pins.initiator_principal
            || self.approver_principal != pins.approver_principal
            || self.agent_principal != pins.agent_principal
            || self.agent_key_fingerprint != pins.agent_key_fingerprint
            || self.connection_id != pins.connection_id
            || self.connection_generation != pins.connection_generation
            || self.connection_subject != pins.connection_subject
            || self.delivery_channel != pins.delivery_channel
            || self.operator_policy_digest != pins.operator_policy_digest
        {
            return Err(not_entered("gateway.task.operator-binding"));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskApprovalArguments {
    task: AgentTaskDescriptor,
}

/// Verify the initiator's exact structured card under the company's pinned
/// native trust. The operator supplies a fresh challenge in `context` and
/// re-reads `pins` from installed records before this call.
pub(crate) fn verify_task_activation(
    context: &TrustedContext,
    pins: &TaskActivationPins,
    now: u64,
    proof_cbor: &[u8],
    action_cbor: &[u8],
) -> Result<ApprovedAgentTask, GatewaySubmitResult> {
    verify_task_activation_for_profile(
        context,
        pins,
        now,
        proof_cbor,
        action_cbor,
        TASK_SERVICE,
        APPROVAL_TOOL,
    )
}

fn verify_task_activation_for_profile(
    context: &TrustedContext,
    pins: &TaskActivationPins,
    now: u64,
    proof_cbor: &[u8],
    action_cbor: &[u8],
    service: &str,
    tool: &str,
) -> Result<ApprovedAgentTask, GatewaySubmitResult> {
    let audience = Audience::parse(&format!("mcp://{service}"))
        .map_err(|_| not_entered("gateway.task.approval-profile"))?;
    let sealed = verify_sealed_for_audience(context, audience, now, proof_cbor, action_cbor)?;
    let action = authorized_action(&sealed)?;
    if action.action_ids().len() != 1 {
        return Err(not_entered("gateway.task.single-initiator-action-required"));
    }
    let command = McpProfile
        .decode_verified(action)
        .map_err(|_| not_entered("gateway.task.action-projection"))?;
    if command.call().service() != service || command.name() != tool {
        return Err(not_entered("gateway.task.approval-profile"));
    }
    let arguments: TaskApprovalArguments =
        serde_json::from_value(Value::Object(command.arguments().clone()))
            .map_err(|_| not_entered("gateway.task.invalid-card"))?;
    arguments.task.validate(pins, now)?;
    let branches = authorized_chains(proof_cbor, action)
        .map_err(|_| not_entered("gateway.policy.proof-unavailable"))?;
    let [branch] = branches.as_slice() else {
        return Err(not_entered("gateway.task.single-initiator-action-required"));
    };
    if branch.actor.as_str() != arguments.task.initiator_principal
        || branch.chain.is_empty()
        || branch
            .chain
            .last()
            .is_none_or(|grant| grant.statement().subject() != &branch.actor)
    {
        return Err(not_entered("gateway.task.initiator-authority"));
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
    let commitment = arguments.task.canonical_commitment()?;
    Ok(ApprovedAgentTask {
        descriptor: arguments.task,
        commitment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GatewayObserver;
    use crate::harness::{self, Signer};
    use crate::observed_tests::{submission, submission_for};
    use crate::recipe::VerifiedCreatedChild;
    use crate::release_state::FileReleaseTaskLedger;
    use crate::task_write::{ApprovedTaskWrite, ExactWriteIntent};
    use serde_json::{Map, json};
    use std::fs;

    const NOW: u64 = 1_790_000_000;

    fn card(human: &Signer, agent: &Signer) -> AgentTaskDescriptor {
        AgentTaskDescriptor {
            schema: TASK_SCHEMA.to_owned(),
            task_id: "task-1".to_owned(),
            company_id: "atlas".to_owned(),
            initiator_principal: human.principal.as_str().to_owned(),
            approver_principal: human.principal.as_str().to_owned(),
            agent_principal: agent.principal.as_str().to_owned(),
            agent_key_fingerprint: "a".repeat(64),
            connection_id: "jules-google".to_owned(),
            connection_generation: 3,
            connection_subject: "jules-subject".to_owned(),
            read_scopes: vec![TaskReadScope {
                handle: "source-1".to_owned(),
                recipe_digest: "b".repeat(64),
                connection_id: "jules-read".to_owned(),
                connection_generation: 5,
                connection_subject: "jules-subject".to_owned(),
            }],
            write_scopes: vec![TaskWriteScope {
                handle: "working-doc".to_owned(),
                recipe_digest: "c".repeat(64),
                verb: TaskWriteVerb::Edit,
                connection_id: "jules-google".to_owned(),
                connection_generation: 3,
                connection_subject: "jules-subject".to_owned(),
            }],
            pending_child: None,
            delivery_channel: "registered-agent-channel".to_owned(),
            not_before: NOW - 30,
            expires_at: NOW + 900,
            max_provider_calls: 2,
            max_releases: 1,
            max_release_bytes: 16_384,
            max_writes: 1,
            write_approval_mode: WriteApprovalMode::Exact,
            upfront_allowed_arguments: Vec::new(),
            operator_policy_digest: "d".repeat(64),
            purpose: "Draft a Project A update".to_owned(),
        }
    }

    fn pins(card: &AgentTaskDescriptor) -> TaskActivationPins {
        TaskActivationPins {
            company_id: card.company_id.clone(),
            initiator_principal: card.initiator_principal.clone(),
            approver_principal: card.approver_principal.clone(),
            agent_principal: card.agent_principal.clone(),
            agent_key_fingerprint: card.agent_key_fingerprint.clone(),
            connection_id: card.connection_id.clone(),
            connection_generation: card.connection_generation,
            connection_subject: card.connection_subject.clone(),
            permitted_read_scopes: card.read_scopes.clone(),
            delivery_channel: card.delivery_channel.clone(),
            operator_policy_digest: card.operator_policy_digest.clone(),
            allow_bounded_writes: false,
        }
    }

    fn signed_card(
        root: &Signer,
        human: &Signer,
        card: &AgentTaskDescriptor,
    ) -> (Vec<u8>, Vec<u8>) {
        let grant = harness::grant(root, &human.principal, None, NOW).expect("human grant");
        let mut arguments = Map::new();
        arguments.insert("task".to_owned(), serde_json::to_value(card).expect("card"));
        let signed = submission(root, human, &grant, &arguments, &[]);
        (signed.proof, signed.action)
    }

    fn signed_card_for_approval(
        root: &Signer,
        human: &Signer,
        card: &AgentTaskDescriptor,
    ) -> (Vec<u8>, Vec<u8>) {
        let grant = harness::grant_for(root, &human.principal, NOW, TASK_SERVICE, APPROVAL_TOOL)
            .expect("human approval grant");
        let mut arguments = Map::new();
        arguments.insert("task".to_owned(), serde_json::to_value(card).expect("card"));
        let signed = submission_for(
            root,
            human,
            &grant,
            &arguments,
            &[],
            TASK_SERVICE,
            APPROVAL_TOOL,
            NOW,
        );
        (signed.proof, signed.action)
    }

    #[test]
    fn human_signed_card_initializes_exact_read_policy() {
        let root = Signer::new(0x11);
        let human = Signer::new(0x22);
        let agent = Signer::new(0x44);
        let card = card(&human, &agent);
        let observer = GatewayObserver::from_test_seed(0x33);
        let context = harness::context_for_agent_and_task(&root, observer.principal(), NOW)
            .expect("installed context");
        let (proof, action) = signed_card_for_approval(&root, &human, &card);
        let approved = verify_task_activation(&context, &pins(&card), NOW, &proof, &action)
            .expect("human approval");
        assert_eq!(approved.descriptor(), &card);
        assert_ne!(approved.commitment(), &[0; 32]);
        let policy = approved.task_policy();
        assert_eq!(policy.task_id, card.task_id);
        assert_eq!(policy.initiator_principal, human.principal.as_str());
        assert_eq!(policy.resources.len(), 1);
        assert_eq!(policy.resources[0].handle, "source-1");
        assert_eq!(policy.resources[0].connection_id, "jules-read");
        assert_eq!(policy.resources[0].connection_generation, 5);

        let root = tempfile::tempdir().expect("tempdir");
        let path = fs::canonicalize(root.path()).expect("path").join("release");
        let ledger = FileReleaseTaskLedger::open(path).expect("ledger");
        let state = ledger.initialize(&approved).expect("signed activation");
        assert_eq!(state.counts(), (0, 0, 0));
        assert_eq!(
            state.digest().expect("digest"),
            ledger
                .load("task-1")
                .expect("load")
                .expect("task")
                .digest()
                .expect("digest")
        );
    }

    fn assert_pending_card_integrity(
        card: AgentTaskDescriptor,
        approved: &ApprovedAgentTask,
        installed: &TaskActivationPins,
    ) {
        assert!(!card.recipes_installed(&["c".repeat(64), "e".repeat(64)]));
        assert!(card.recipes_installed(&["c".repeat(64), "e".repeat(64), "f".repeat(64),]));
        let mut changed = card.clone();
        changed.pending_child.as_mut().expect("pending").title = "Different title".to_owned();
        assert!(
            ApprovedAgentTask::from_activated_card(changed, *approved.commitment(), installed, NOW)
                .is_err(),
            "stored signed card cannot change title after activation"
        );
        let mut invalid = card.clone();
        invalid
            .pending_child
            .as_mut()
            .expect("pending")
            .parent_handle = "project-b-folder".to_owned();
        assert_eq!(
            invalid.validate(installed, NOW).err(),
            Some(not_entered("gateway.task.invalid-pending-child"))
        );
        let mut invalid = card.clone();
        invalid.write_approval_mode = WriteApprovalMode::BoundedUpfront;
        assert!(invalid.validate(installed, NOW).is_err());
        let mut invalid = card;
        invalid
            .pending_child
            .as_mut()
            .expect("pending")
            .populate_recipe_digest = "e".repeat(64);
        assert_eq!(
            invalid.validate(installed, NOW).err(),
            Some(not_entered("gateway.task.invalid-pending-child"))
        );
    }

    fn bind_only_reserved_child(
        reopened: &FileReleaseTaskLedger,
        create: &ApprovedTaskWrite,
    ) -> (ExactWriteIntent, ApprovedTaskWrite) {
        assert!(
            reopened
                .bind_created_child(
                    create,
                    &VerifiedCreatedChild::from_test("child_ABC-123"),
                    &[9; 32],
                    NOW + 1
                )
                .is_err(),
            "unreserved create cannot bind a child"
        );
        reopened
            .reserve_write(create, NOW + 1)
            .expect("reserve create");
        let mut populate_intent = create.intent().clone();
        populate_intent.operation_id = "populate-1".to_owned();
        populate_intent.recipe_digest = "f".repeat(64);
        populate_intent.resource_handle = "child_ABC-123".to_owned();
        populate_intent.verb = TaskWriteVerb::Edit;
        populate_intent.request_commitment = "b".repeat(64);
        let populate = ApprovedTaskWrite::from_test_intent(populate_intent.clone());
        assert!(
            reopened.reserve_write(&populate, NOW + 1).is_err(),
            "a pending child is not an executable scope"
        );
        assert!(
            reopened
                .bind_created_child(
                    create,
                    &VerifiedCreatedChild::from_test("child/other"),
                    &[9; 32],
                    NOW + 1
                )
                .is_err(),
            "unsafe child ID cannot bind"
        );
        let mut changed_intent = create.intent().clone();
        changed_intent.request_commitment = "9".repeat(64);
        assert!(
            reopened
                .bind_created_child(
                    &ApprovedTaskWrite::from_test_intent(changed_intent),
                    &VerifiedCreatedChild::from_test("child_ABC-123"),
                    &[9; 32],
                    NOW + 1
                )
                .is_err(),
            "changed request cannot bind"
        );
        let mut changed_action = create.intent().clone();
        changed_action.action_commitment = "8".repeat(64);
        assert!(
            reopened
                .bind_created_child(
                    &ApprovedTaskWrite::from_test_intent(changed_action),
                    &VerifiedCreatedChild::from_test("child_ABC-123"),
                    &[9; 32],
                    NOW + 1
                )
                .is_err(),
            "a different signed action cannot bind the reserved create"
        );
        reopened
            .bind_created_child(
                create,
                &VerifiedCreatedChild::from_test("child_ABC-123"),
                &[9; 32],
                NOW + 1,
            )
            .expect("bind observed child");
        assert!(
            reopened
                .bind_created_child(
                    create,
                    &VerifiedCreatedChild::from_test("other-child"),
                    &[9; 32],
                    NOW + 1
                )
                .is_err(),
            "binding is immutable"
        );
        (populate_intent, populate)
    }

    fn assert_population_is_single_use(
        reopened: &FileReleaseTaskLedger,
        populate_intent: ExactWriteIntent,
        populate: &ApprovedTaskWrite,
    ) {
        let mut wrong_child = populate_intent.clone();
        wrong_child.resource_handle = "arbitrary-child".to_owned();
        assert!(
            reopened
                .reserve_write(&ApprovedTaskWrite::from_test_intent(wrong_child), NOW + 1)
                .is_err()
        );
        let mut wrong_recipe = populate_intent.clone();
        wrong_recipe.recipe_digest = "a".repeat(64);
        assert!(
            reopened
                .reserve_write(&ApprovedTaskWrite::from_test_intent(wrong_recipe), NOW + 1)
                .is_err()
        );
        reopened
            .reserve_write(populate, NOW + 1)
            .expect("bound child population reserves once");
        assert!(
            reopened.reserve_write(populate, NOW + 1).is_err(),
            "population replays are refused"
        );
        let mut second_populate = populate_intent;
        second_populate.operation_id = "populate-2".to_owned();
        assert!(
            reopened
                .reserve_write(
                    &ApprovedTaskWrite::from_test_intent(second_populate),
                    NOW + 1
                )
                .is_err(),
            "a new operation ID cannot populate the same child again"
        );
    }

    #[test]
    fn machine_activation_requires_initiator_and_commits_independent_approver() {
        let root = Signer::new(0x11);
        let machine = Signer::new(0x55);
        let human = Signer::new(0x22);
        let agent = Signer::new(0x44);
        let mut descriptor = card(&machine, &agent);
        descriptor.approver_principal = human.principal.as_str().to_owned();
        let installed = pins(&descriptor);
        let observer = GatewayObserver::from_test_seed(0x33);
        let context = harness::context_for_agent_and_task(&root, observer.principal(), NOW)
            .expect("installed context");
        let (proof, action) = signed_card_for_approval(&root, &machine, &descriptor);
        let activated = verify_task_activation(&context, &installed, NOW, &proof, &action)
            .expect("machine activation with independent approver");
        assert_eq!(
            activated.descriptor().approver_principal,
            human.principal.as_str()
        );
        for impostor in [&human, &agent] {
            let (proof, action) = signed_card_for_approval(&root, impostor, &descriptor);
            assert_eq!(
                verify_task_activation(&context, &installed, NOW, &proof, &action).err(),
                Some(not_entered("gateway.task.initiator-authority"))
            );
        }
        for changed in [
            AgentTaskDescriptor {
                initiator_principal: human.principal.as_str().to_owned(),
                ..descriptor.clone()
            },
            AgentTaskDescriptor {
                approver_principal: machine.principal.as_str().to_owned(),
                ..descriptor.clone()
            },
        ] {
            assert_eq!(
                changed.validate(&installed, NOW).err(),
                Some(not_entered("gateway.task.operator-binding"))
            );
            let changed_pins = pins(&changed);
            assert_eq!(
                ApprovedAgentTask::from_activated_card(
                    changed,
                    *activated.commitment(),
                    &changed_pins,
                    NOW
                )
                .err(),
                Some(not_entered("gateway.task.activation-changed"))
            );
        }
    }

    #[test]
    fn task_roles_reject_self_approval_unapproved_upfront_and_obsolete_cards() {
        let machine = Signer::new(0x55);
        let human = Signer::new(0x22);
        let agent = Signer::new(0x44);
        let mut descriptor = card(&machine, &agent);
        descriptor.approver_principal = human.principal.as_str().to_owned();
        let installed = pins(&descriptor);
        descriptor
            .validate(&installed, NOW)
            .expect("separate roles");
        let mut self_approved = descriptor.clone();
        self_approved.approver_principal = agent.principal.as_str().to_owned();
        assert!(!self_approved.roles_valid());
        descriptor.write_approval_mode = WriteApprovalMode::BoundedUpfront;
        descriptor.upfront_allowed_arguments = vec![BTreeMap::from([(
            "replacement".to_owned(),
            json!("Approved"),
        )])];
        let mut installed = pins(&descriptor);
        installed.allow_bounded_writes = true;
        assert_eq!(
            descriptor.validate(&installed, NOW).err(),
            Some(not_entered("gateway.task.invalid-card"))
        );
        descriptor.approver_principal = machine.principal.as_str().to_owned();
        installed.approver_principal = machine.principal.as_str().to_owned();
        descriptor
            .validate(&installed, NOW)
            .expect("explicit same-principal upfront approval");
        let mut obsolete = serde_json::to_value(&descriptor).expect("card");
        obsolete["schema"] = json!("auths.agent-task/2");
        let old: AgentTaskDescriptor =
            serde_json::from_value(obsolete.clone()).expect("shape only");
        assert!(old.validate(&installed, NOW).is_err());
        let object = obsolete.as_object_mut().expect("card object");
        object.remove("initiator_principal");
        object.remove("approver_principal");
        object.insert(
            "human_principal".to_owned(),
            json!(machine.principal.as_str()),
        );
        assert!(serde_json::from_value::<AgentTaskDescriptor>(obsolete).is_err());
    }

    #[test]
    fn signed_pending_child_names_one_create_and_one_future_populate_recipe() {
        let root = Signer::new(0x11);
        let human = Signer::new(0x22);
        let agent = Signer::new(0x44);
        let mut card = card(&human, &agent);
        card.write_scopes.push(TaskWriteScope {
            handle: "project-a-folder".to_owned(),
            recipe_digest: "e".repeat(64),
            verb: TaskWriteVerb::Create,
            connection_id: card.connection_id.clone(),
            connection_generation: card.connection_generation,
            connection_subject: card.connection_subject.clone(),
        });
        card.max_writes = 3;
        card.pending_child = Some(TaskPendingChild {
            create_operation_id: "create-1".to_owned(),
            create_recipe_digest: "e".repeat(64),
            populate_recipe_digest: "f".repeat(64),
            parent_handle: "project-a-folder".to_owned(),
            title: "Auths AP-071 Project A handoff".to_owned(),
            marker: format!("ap071_{}", "d".repeat(32)),
        });
        let installed = pins(&card);
        card.validate(&installed, NOW).expect("pending task card");
        let observer = GatewayObserver::from_test_seed(0x33);
        let context = harness::context_for_agent_and_task(&root, observer.principal(), NOW)
            .expect("installed context");
        let (proof, action) = signed_card_for_approval(&root, &human, &card);
        let approved = verify_task_activation(&context, &installed, NOW, &proof, &action)
            .expect("human signed pending child");
        assert_eq!(approved.descriptor().pending_child, card.pending_child);
        let root = tempfile::tempdir().expect("private task journal");
        let path = fs::canonicalize(root.path())
            .expect("canonical directory")
            .join("task");
        let ledger = FileReleaseTaskLedger::open(&path).expect("journal");
        ledger.initialize(&approved).expect("durable activation");
        drop(ledger);
        let reopened = FileReleaseTaskLedger::open(path.clone()).expect("reopen journal");
        let retained = reopened
            .load(&card.task_id)
            .expect("load")
            .expect("stored task")
            .activated_task(&installed, NOW + 1)
            .expect("revalidate signed card");
        assert_eq!(retained.descriptor().pending_child, card.pending_child);
        let create = ApprovedTaskWrite::from_test_intent(ExactWriteIntent {
            task_id: card.task_id.clone(),
            task_commitment: hex::encode(approved.commitment()),
            operation_id: "create-1".to_owned(),
            action_commitment: "7".repeat(64),
            request_commitment: "8".repeat(64),
            recipe_digest: "e".repeat(64),
            resource_handle: "project-a-folder".to_owned(),
            verb: TaskWriteVerb::Create,
            connection_id: card.connection_id.clone(),
            connection_generation: card.connection_generation,
            connection_subject: card.connection_subject.clone(),
        });
        let (populate_intent, populate) = bind_only_reserved_child(&reopened, &create);
        drop(reopened);
        let reopened = FileReleaseTaskLedger::open(path).expect("reopen");
        let state = reopened.load(&card.task_id).expect("load").expect("state");
        assert_eq!(state.bound_child_id(), Some("child_ABC-123"));
        assert_population_is_single_use(&reopened, populate_intent, &populate);
        assert_pending_card_integrity(card, &approved, &installed);
    }

    #[test]
    fn signed_but_unpinned_or_changed_cards_cannot_activate() {
        let root = Signer::new(0x11);
        let human = Signer::new(0x22);
        let agent = Signer::new(0x44);
        let card = card(&human, &agent);
        let observer = GatewayObserver::from_test_seed(0x33);
        let context = harness::context(&root, observer.principal(), None, NOW).expect("context");
        let (proof, action) = signed_card(&root, &human, &card);
        let mut wrong = pins(&card);
        wrong.connection_generation += 1;
        assert!(
            verify_task_activation_for_profile(
                &context,
                &wrong,
                NOW,
                &proof,
                &action,
                harness::SERVICE,
                harness::TOOL,
            )
            .is_err()
        );
        let mut wrong = pins(&card);
        wrong.delivery_channel = "other-channel".to_owned();
        assert!(
            verify_task_activation_for_profile(
                &context,
                &wrong,
                NOW,
                &proof,
                &action,
                harness::SERVICE,
                harness::TOOL,
            )
            .is_err()
        );
        let mut changed = card.clone();
        changed.write_approval_mode = WriteApprovalMode::BoundedUpfront;
        let (proof, action) = signed_card(&root, &human, &changed);
        assert!(
            verify_task_activation_for_profile(
                &context,
                &pins(&changed),
                NOW,
                &proof,
                &action,
                harness::SERVICE,
                harness::TOOL,
            )
            .is_err()
        );
        let mut changed = card.clone();
        changed.read_scopes.push(TaskReadScope {
            handle: "source-1".to_owned(),
            recipe_digest: "e".repeat(64),
            connection_id: "jules-read".to_owned(),
            connection_generation: 5,
            connection_subject: "jules-subject".to_owned(),
        });
        let (proof, action) = signed_card(&root, &human, &changed);
        assert!(
            verify_task_activation_for_profile(
                &context,
                &pins(&changed),
                NOW,
                &proof,
                &action,
                harness::SERVICE,
                harness::TOOL,
            )
            .is_err()
        );
        let (proof, mut action) = signed_card(&root, &human, &card);
        action.pop();
        assert!(
            verify_task_activation_for_profile(
                &context,
                &pins(&card),
                NOW,
                &proof,
                &action,
                harness::SERVICE,
                harness::TOOL,
            )
            .is_err()
        );
    }

    #[test]
    fn per_scope_connection_pins_refuse_subject_generation_and_write_substitution() {
        let root = Signer::new(0x11);
        let human = Signer::new(0x22);
        let agent = Signer::new(0x44);
        let card = card(&human, &agent);
        let observer = GatewayObserver::from_test_seed(0x33);
        let context = harness::context(&root, observer.principal(), None, NOW).expect("context");
        let (proof, action) = signed_card(&root, &human, &card);
        for drift in [
            TaskReadScope {
                connection_subject: "different-subject".to_owned(),
                ..card.read_scopes[0].clone()
            },
            TaskReadScope {
                connection_generation: 6,
                ..card.read_scopes[0].clone()
            },
        ] {
            let mut wrong = pins(&card);
            wrong.permitted_read_scopes[0] = drift;
            assert!(
                verify_task_activation_for_profile(
                    &context,
                    &wrong,
                    NOW,
                    &proof,
                    &action,
                    harness::SERVICE,
                    harness::TOOL,
                )
                .is_err()
            );
        }
        let mut changed = card.clone();
        changed.write_scopes[0].connection_id = "other-write".to_owned();
        let (changed_proof, changed_action) = signed_card(&root, &human, &changed);
        assert!(
            verify_task_activation_for_profile(
                &context,
                &pins(&card),
                NOW,
                &changed_proof,
                &changed_action,
                harness::SERVICE,
                harness::TOOL,
            )
            .is_err()
        );
    }

    #[test]
    fn exact_mode_is_default_and_bounded_mode_needs_operator_opt_in() {
        let root = Signer::new(0x11);
        let human = Signer::new(0x22);
        let agent = Signer::new(0x44);
        let mut card = card(&human, &agent);
        card.write_approval_mode = WriteApprovalMode::BoundedUpfront;
        card.upfront_allowed_arguments = vec![BTreeMap::from([
            ("record_id".to_owned(), json!("working-doc")),
            ("replacement".to_owned(), json!("Approved")),
        ])];
        let observer = GatewayObserver::from_test_seed(0x33);
        let context = harness::context(&root, observer.principal(), None, NOW).expect("context");
        let (proof, action) = signed_card(&root, &human, &card);
        let mut installed = pins(&card);
        assert!(
            verify_task_activation_for_profile(
                &context,
                &installed,
                NOW,
                &proof,
                &action,
                harness::SERVICE,
                harness::TOOL,
            )
            .is_err()
        );
        installed.allow_bounded_writes = true;
        let approved = verify_task_activation_for_profile(
            &context,
            &installed,
            NOW,
            &proof,
            &action,
            harness::SERVICE,
            harness::TOOL,
        )
        .expect("explicit operator opt-in");
        assert_eq!(
            approved.descriptor().write_approval_mode,
            WriteApprovalMode::BoundedUpfront
        );
        assert_eq!(json!(approved.descriptor().max_writes), json!(1));
    }

    #[test]
    fn upfront_card_requires_a_small_unique_complete_choice_set() {
        let human = Signer::new(0x22);
        let agent = Signer::new(0x44);
        let mut original = card(&human, &agent);
        let mut installed = pins(&original);
        installed.allow_bounded_writes = true;
        original.write_approval_mode = WriteApprovalMode::BoundedUpfront;
        assert!(original.validate(&installed, NOW).is_err());

        let choice = BTreeMap::from([
            ("document_id".to_owned(), json!("working-doc")),
            ("replacement".to_owned(), json!("Approved")),
        ]);
        original.upfront_allowed_arguments = vec![choice.clone()];
        assert!(original.validate(&installed, NOW).is_ok());

        let mut changed = original.clone();
        changed.max_writes = 2;
        assert!(changed.validate(&installed, NOW).is_err());
        changed = original.clone();
        changed.upfront_allowed_arguments.push(choice);
        assert!(changed.validate(&installed, NOW).is_err());
        changed = original.clone();
        changed.upfront_allowed_arguments[0].insert("operation_id".to_owned(), json!("run-1"));
        assert!(changed.validate(&installed, NOW).is_err());
        changed = original;
        changed.write_approval_mode = WriteApprovalMode::Exact;
        assert!(changed.validate(&installed, NOW).is_err());
    }
}
