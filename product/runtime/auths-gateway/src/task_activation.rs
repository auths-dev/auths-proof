//! Provider-neutral, human-signed task envelope. Native verification proves
//! who signed the exact card; operator pins still decide whether that human,
//! agent and connection are installed. Provider access remains a later check.

use crate::bounds::authorized_chains;
use crate::engine::{GatewaySubmitResult, authorized_action, not_entered, verify_sealed};
use crate::release_state::{ReleaseResourceScope, ReleaseTaskPolicy};
use auths_model::{PrincipalId, TrustedContext, VerifierLimits};
use auths_profile_api::ActionProfile as _;
use auths_profile_mcp::McpProfile;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

const TASK_SCHEMA: &str = "auths.agent-task/1";
const APPROVAL_SERVICE: &str = "auths-agent-task";
const APPROVAL_TOOL: &str = "approve_agent_task_v1";
const MAX_SCOPES: usize = 16;
const MAX_TASK_SECONDS: u64 = 86_400;
const MAX_WRITES: u32 = 32;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskReadScope {
    handle: String,
    recipe_digest: String,
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
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum WriteApprovalMode {
    Exact,
    BoundedUpfront,
}

/// Exact structured card the employee reviews and signs as one native MCP
/// action. Handles and recipe digests are opaque to this shared contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentTaskDescriptor {
    schema: String,
    pub(crate) task_id: String,
    company_id: String,
    pub(crate) human_principal: String,
    pub(crate) agent_principal: String,
    agent_key_fingerprint: String,
    pub(crate) connection_id: String,
    pub(crate) connection_generation: u64,
    pub(crate) connection_subject: String,
    read_scopes: Vec<TaskReadScope>,
    pub(crate) write_scopes: Vec<TaskWriteScope>,
    delivery_channel: String,
    pub(crate) not_before: u64,
    pub(crate) expires_at: u64,
    max_provider_calls: u32,
    max_releases: u32,
    max_release_bytes: u64,
    pub(crate) max_writes: u32,
    pub(crate) write_approval_mode: WriteApprovalMode,
    operator_policy_digest: String,
    purpose: String,
}

/// Operator-installed values re-read at activation. These are independent of
/// the human's submitted action and must come from active company, agent and
/// connection records, including the provider's stable account subject.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskActivationPins {
    pub(crate) company_id: String,
    pub(crate) human_principal: String,
    pub(crate) agent_principal: String,
    pub(crate) agent_key_fingerprint: String,
    pub(crate) connection_id: String,
    pub(crate) connection_generation: u64,
    pub(crate) connection_subject: String,
    pub(crate) delivery_channel: String,
    pub(crate) operator_policy_digest: String,
    pub(crate) allow_bounded_writes: bool,
}

/// A verified human approval of the exact task card. No public constructor
/// exists; the read ledger can derive its policy only from this value.
pub(crate) struct ApprovedAgentTask {
    descriptor: AgentTaskDescriptor,
    commitment: [u8; 32],
}

impl ApprovedAgentTask {
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
            human_principal: self.descriptor.human_principal.clone(),
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
                    connection_id: self.descriptor.connection_id.clone(),
                    connection_generation: self.descriptor.connection_generation,
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

impl AgentTaskDescriptor {
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
            || PrincipalId::parse(&self.human_principal).is_err()
            || PrincipalId::parse(&self.agent_principal).is_err()
            || self.human_principal == self.agent_principal
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
            || (self.write_scopes.is_empty()
                && self.write_approval_mode != WriteApprovalMode::Exact)
        {
            return Err(not_entered("gateway.task.invalid-card"));
        }
        let mut reads = BTreeSet::new();
        for scope in &self.read_scopes {
            if !bounded_text(&scope.handle, 256)
                || !digest(&scope.recipe_digest)
                || !reads.insert(&scope.handle)
            {
                return Err(not_entered("gateway.task.invalid-read-scope"));
            }
        }
        let mut writes = BTreeSet::new();
        for scope in &self.write_scopes {
            if !bounded_text(&scope.handle, 256)
                || !digest(&scope.recipe_digest)
                || !writes.insert((&scope.handle, &scope.verb))
            {
                return Err(not_entered("gateway.task.invalid-write-scope"));
            }
        }
        if self.company_id != pins.company_id
            || self.human_principal != pins.human_principal
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

/// Verify the human's exact structured card under the company's pinned
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
        APPROVAL_SERVICE,
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
    let sealed = verify_sealed(context, now, proof_cbor, action_cbor)?;
    let action = authorized_action(&sealed)?;
    if action.action_ids().len() != 1 {
        return Err(not_entered("gateway.task.single-human-action-required"));
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
        return Err(not_entered("gateway.task.single-human-action-required"));
    };
    if branch.actor.as_str() != arguments.task.human_principal
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
    let canonical = serde_json_canonicalizer::to_vec(&arguments.task)
        .map_err(|_| not_entered("gateway.task.invalid-card"))?;
    let commitment = auths_codec::domain_commitment("auths.agent-task.v1", &canonical)
        .map_err(|_| not_entered("gateway.task.invalid-card"))?;
    Ok(ApprovedAgentTask {
        descriptor: arguments.task,
        commitment: *commitment.as_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GatewayObserver;
    use crate::harness::{self, Signer};
    use crate::observed_tests::{submission, submission_for};
    use crate::release_state::FileReleaseTaskLedger;
    use serde_json::{Map, json};
    use std::fs;

    const NOW: u64 = 1_790_000_000;

    fn card(human: &Signer, agent: &Signer) -> AgentTaskDescriptor {
        AgentTaskDescriptor {
            schema: TASK_SCHEMA.to_owned(),
            task_id: "task-1".to_owned(),
            company_id: "atlas".to_owned(),
            human_principal: human.principal.as_str().to_owned(),
            agent_principal: agent.principal.as_str().to_owned(),
            agent_key_fingerprint: "a".repeat(64),
            connection_id: "jules-google".to_owned(),
            connection_generation: 3,
            connection_subject: "jules-subject".to_owned(),
            read_scopes: vec![TaskReadScope {
                handle: "source-1".to_owned(),
                recipe_digest: "b".repeat(64),
            }],
            write_scopes: vec![TaskWriteScope {
                handle: "working-doc".to_owned(),
                recipe_digest: "c".repeat(64),
                verb: TaskWriteVerb::Edit,
            }],
            delivery_channel: "registered-agent-channel".to_owned(),
            not_before: NOW - 30,
            expires_at: NOW + 900,
            max_provider_calls: 2,
            max_releases: 1,
            max_release_bytes: 16_384,
            max_writes: 1,
            write_approval_mode: WriteApprovalMode::Exact,
            operator_policy_digest: "d".repeat(64),
            purpose: "Draft a Project A update".to_owned(),
        }
    }

    fn pins(card: &AgentTaskDescriptor) -> TaskActivationPins {
        TaskActivationPins {
            company_id: card.company_id.clone(),
            human_principal: card.human_principal.clone(),
            agent_principal: card.agent_principal.clone(),
            agent_key_fingerprint: card.agent_key_fingerprint.clone(),
            connection_id: card.connection_id.clone(),
            connection_generation: card.connection_generation,
            connection_subject: card.connection_subject.clone(),
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
        let grant =
            harness::grant_for(root, &human.principal, NOW, APPROVAL_SERVICE, APPROVAL_TOOL)
                .expect("human approval grant");
        let mut arguments = Map::new();
        arguments.insert("task".to_owned(), serde_json::to_value(card).expect("card"));
        let signed = submission_for(
            root,
            human,
            &grant,
            &arguments,
            &[],
            APPROVAL_SERVICE,
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
        let context = harness::context_for_task_profile(
            &root,
            observer.principal(),
            NOW,
            APPROVAL_SERVICE,
            APPROVAL_TOOL,
        )
        .expect("approval context");
        let (proof, action) = signed_card_for_approval(&root, &human, &card);
        let approved = verify_task_activation(&context, &pins(&card), NOW, &proof, &action)
            .expect("human approval");
        assert_eq!(approved.descriptor(), &card);
        assert_ne!(approved.commitment(), &[0; 32]);
        let policy = approved.task_policy();
        assert_eq!(policy.task_id, card.task_id);
        assert_eq!(policy.human_principal, human.principal.as_str());
        assert_eq!(policy.resources.len(), 1);
        assert_eq!(policy.resources[0].handle, "source-1");

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
    fn exact_mode_is_default_and_bounded_mode_needs_operator_opt_in() {
        let root = Signer::new(0x11);
        let human = Signer::new(0x22);
        let agent = Signer::new(0x44);
        let mut card = card(&human, &agent);
        card.write_approval_mode = WriteApprovalMode::BoundedUpfront;
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
}
