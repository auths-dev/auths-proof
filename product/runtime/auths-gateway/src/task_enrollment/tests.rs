use super::*;
use crate::harness::{self, Signer};
use crate::participant_enrollment::tests::{chained, grant, grant_for_audiences, invocation};
use crate::participant_enrollment::*;
use crate::release_state::{EnrollmentTransaction, FileReleaseTaskLedger, ReleaseStateError};
use crate::task_activation::{
    APPROVAL_TOOL, TASK_SERVICE, TaskActivationPins, verify_task_activation,
};
use crate::{FixedClock, GatewayObserver, QualificationGate, QualificationPolicy};
use auths_codec::grant_id;
use auths_model::{CompositionRequirement, SignedGrant, TrustedContext};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

pub(crate) const NOW: u64 = 1_790_000_000;
pub(crate) const TASK: &str = "machine-engagement";
const CONTROL_TOOLS: &[&str] = &[
    ACTIVATE_ROOT_TOOL,
    ENROLL_PARTICIPANT_TOOL,
    ACCEPT_PARTICIPANT_TOOL,
];

pub(crate) struct Fixture {
    _directory: tempfile::TempDir,
    pub(crate) path: PathBuf,
    company: Signer,
    machine: Signer,
    agent: Signer,
    child: Signer,
    human: Signer,
    context: TrustedContext,
    pins: TaskActivationPins,
    task: ApprovedAgentTask,
    reads: Vec<CompiledReleaseRecipe>,
    writes: Vec<CompiledRecipe>,
    authority: TaskRootAuthority,
    root: ParentEnrollmentPins,
    controls: Vec<SignedGrant>,
    resources: BTreeMap<String, Vec<SignedGrant>>,
    pub(crate) clock: Arc<FixedClock>,
    pub(crate) time: QualificationGate,
}

fn chain_grants(
    company: &Signer,
    machine: &Signer,
    agent: &Signer,
    child: &Signer,
    service: &str,
    tools: &[&str],
) -> Vec<SignedGrant> {
    chain_grants_for_audience(
        company,
        machine,
        agent,
        child,
        service,
        tools,
        auths_model::Audience::parse(&format!("mcp://{service}")).unwrap(),
    )
}

fn chain_grants_for_audience(
    company: &Signer,
    machine: &Signer,
    agent: &Signer,
    child: &Signer,
    service: &str,
    tools: &[&str],
    audience: auths_model::Audience,
) -> Vec<SignedGrant> {
    let first = grant_for_audiences(
        company,
        machine,
        service,
        tools,
        None,
        2,
        vec![audience.clone()],
    );
    let second = grant_for_audiences(
        machine,
        agent,
        service,
        tools,
        Some(grant_id(first.statement()).unwrap()),
        1,
        vec![audience.clone()],
    );
    let third = grant_for_audiences(
        agent,
        child,
        service,
        tools,
        Some(grant_id(second.statement()).unwrap()),
        0,
        vec![audience],
    );
    vec![first, second, third]
}

fn write_recipe() -> CompiledRecipe {
    let (source, lock) = harness::recipe_sources(
        &json!({
            "task_id": {"kind": "string", "minimum": 1, "maximum": 128},
            "task_commitment": {"kind": "string", "minimum": 64, "maximum": 64}
        }),
        &json!({}),
    )
    .unwrap();
    let mut source: serde_json::Value = serde_json::from_slice(&source).unwrap();
    source.as_object_mut().unwrap().remove("preconditions");
    source["task_binding"] = json!({"resource_field": "record_id", "verb": "edit"});
    CompiledRecipe::compile(&serde_json::to_vec(&source).unwrap(), &lock).unwrap()
}

impl Fixture {
    pub(crate) fn new() -> Self {
        Self::with_writes(false)
    }

    fn with_writes(include_write: bool) -> Self {
        Self::with_limits(include_write, 4, 4, 128)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one native fixture retains the full company-machine-agent grant paths and signed installation"
    )]
    pub(crate) fn with_limits(
        include_write: bool,
        reads_limit: u32,
        releases: u32,
        bytes: u64,
    ) -> Self {
        let company = Signer::new(0x11);
        let machine = Signer::new(0x21);
        let agent = Signer::new(0x22);
        let child = Signer::new(0x44);
        let human = Signer::new(0x55);
        let observer = GatewayObserver::from_test_seed(0x33);
        let reads = vec![crate::release_verify::tests::recipe()];
        let writes: Vec<_> = include_write.then(write_recipe).into_iter().collect();
        let write_scopes: Vec<_> = writes.iter().map(|recipe| json!({
            "handle": harness::RECORD, "recipe_digest": recipe.digest_hex(), "verb": "edit",
            "connection_id": "source", "connection_generation": 4, "connection_subject": "synthetic-account"
        })).collect();
        let read_scopes = json!([{"handle": harness::RECORD, "recipe_digest": reads[0].digest_hex(),
            "connection_id": "source", "connection_generation": 4, "connection_subject": "synthetic-account"}]);
        let delegation = json!({"partition_generation": 7, "root_instance_generation": 3, "max_depth": 1,
            "permitted_channels": {"agent-a": {"principal": agent.principal.as_str(), "instance_generation": 3},
                "agent-b": {"principal": child.principal.as_str(), "instance_generation": 5}}});
        let card: AgentTaskDescriptor = serde_json::from_value(json!({
            "schema": "auths.agent-task/4", "task_id": TASK, "company_id": "example-company",
            "initiator_principal": machine.principal.as_str(), "approver_principal": human.principal.as_str(),
            "agent_principal": agent.principal.as_str(), "agent_key_fingerprint": "a".repeat(64),
            "connection_id": "source", "connection_generation": 4, "connection_subject": "synthetic-account",
            "read_scopes": read_scopes, "write_scopes": write_scopes, "delivery_channel": "agent-a", "delegation": delegation,
            "not_before": NOW - 10, "expires_at": NOW + 600, "max_provider_calls": reads_limit,
            "max_releases": releases, "max_release_bytes": bytes, "max_writes": u32::from(include_write),
            "write_approval_mode": "exact", "operator_policy_digest": "b".repeat(64), "purpose": "M delegates to A and B"
        })).unwrap();
        let context = harness::context_for_profiles_and_audiences(
            &[&company],
            observer.principal(),
            None,
            NOW,
            3,
            CompositionRequirement::new(None, 1, 1, 1).unwrap(),
            &[auths_raw_key::RAW_KEY_V1],
            &[
                (TASK_SERVICE, APPROVAL_TOOL),
                (TASK_SERVICE, crate::task_write::CONFIRMATION_TOOL),
                (PARTICIPANT_SERVICE, ACTIVATE_ROOT_TOOL),
                (PARTICIPANT_SERVICE, ENROLL_PARTICIPANT_TOOL),
                (PARTICIPANT_SERVICE, ACCEPT_PARTICIPANT_TOOL),
                (harness::SERVICE, harness::TOOL),
            ],
            &card
                .read_scopes
                .iter()
                .map(|scope| &scope.recipe_digest)
                .chain(card.write_scopes.iter().map(|scope| &scope.recipe_digest))
                .map(|digest| {
                    resource_audience(
                        &card.canonical_commitment().unwrap(),
                        card.delegation.partition_generation,
                        digest,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let pins = serde_json::from_value(json!({
            "company_id": "example-company", "initiator_principal": machine.principal.as_str(),
            "approver_principal": human.principal.as_str(), "agent_principal": agent.principal.as_str(),
            "agent_key_fingerprint": "a".repeat(64), "connection_id": "source", "connection_generation": 4,
            "connection_subject": "synthetic-account", "permitted_read_scopes": read_scopes,
            "delivery_channel": "agent-a", "delegation": delegation, "operator_policy_digest": "b".repeat(64),
            "allow_bounded_writes": false
        })).unwrap();
        let task_grant = grant(&company, &machine, TASK_SERVICE, &[APPROVAL_TOOL], None, 0);
        let signed = chained(
            &[&company, &machine],
            &[&task_grant],
            TASK_SERVICE,
            APPROVAL_TOOL,
            json!({"task": card}).as_object().unwrap(),
        );
        let task =
            verify_task_activation(&context, &pins, NOW, &signed.proof, &signed.action).unwrap();
        let controls = chain_grants(
            &company,
            &machine,
            &agent,
            &child,
            PARTICIPANT_SERVICE,
            CONTROL_TOOLS,
        );
        let recipes = TaskEnrollmentRecipes {
            reads: &reads,
            writes: &writes,
        };
        let resources: BTreeMap<_, _> = scopes(&card, &recipes)
            .unwrap()
            .into_iter()
            .map(|scope| {
                let audience = resource_audience(
                    task.commitment(),
                    card.delegation.partition_generation,
                    &scope.recipe_digest,
                )
                .unwrap();
                let chain = chain_grants_for_audience(
                    &company,
                    &machine,
                    &agent,
                    &child,
                    &scope.service,
                    &[&scope.tool],
                    audience,
                );
                (scope.recipe_digest, chain)
            })
            .collect();
        let authority = TaskRootAuthority {
            control_grant: *grant_id(controls[1].statement()).unwrap().as_bytes(),
            resource_grants: scopes(&card, &recipes)
                .unwrap()
                .into_iter()
                .map(|scope| {
                    (
                        scope.scope_id,
                        *grant_id(resources[&scope.recipe_digest][1].statement())
                            .unwrap()
                            .as_bytes(),
                    )
                })
                .collect(),
        };
        let root = root_pins(&task, &recipes, &authority).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(directory.path())
            .unwrap()
            .join("task-state");
        FileReleaseTaskLedger::open(&path)
            .unwrap()
            .initialize(&task)
            .unwrap();
        let clock = Arc::new(FixedClock::at(NOW));
        let time = QualificationGate::new(
            QualificationPolicy::Optional,
            None,
            None,
            Box::new(clock.clone()),
            auths_recipe_qualification::VerifierState::default(),
        );
        Self {
            _directory: directory,
            path,
            company,
            machine,
            agent,
            child,
            human,
            context,
            pins,
            task,
            reads,
            writes,
            authority,
            root,
            controls,
            resources,
            clock,
            time,
        }
    }

    fn write(
        &self,
        operation_id: &str,
    ) -> (
        crate::task_write::ApprovedTaskWrite,
        crate::engine::VerifiedCommand,
    ) {
        let recipe = &self.writes[0];
        let resources = &self.resources[&recipe.digest_hex()];
        let arguments = json!({"operator_namespace": harness::NAMESPACE,
            "operation_id": operation_id, "recipe_digest": recipe.digest_hex(),
            "record_id": harness::RECORD, "replacement": "Approved",
            "task_id": TASK, "task_commitment": hex::encode(self.task.commitment())});
        let signed = chained(
            &[&self.company, &self.machine, &self.agent],
            &[&resources[0], &resources[1]],
            harness::SERVICE,
            harness::TOOL,
            arguments.as_object().unwrap(),
        );
        let verified = crate::engine::verify_task_command(
            &self.task,
            recipe,
            &self.context,
            NOW,
            &signed.proof,
            &signed.action,
        )
        .unwrap();
        let binding = crate::task_write::TaskWriteBinding {
            resource_field: "record_id".into(),
            verb: crate::task_activation::TaskWriteVerb::Edit,
            connection_id: "source".into(),
            connection_generation: 4,
            connection_subject: "synthetic-account".into(),
        };
        let intent = crate::task_write::derive_exact_write_intent(
            &self.task, &verified, recipe, &binding, None, NOW,
        )
        .unwrap();
        let grant = grant(
            &self.company,
            &self.human,
            TASK_SERVICE,
            &[crate::task_write::CONFIRMATION_TOOL],
            None,
            0,
        );
        let confirmation = chained(
            &[&self.company, &self.human],
            &[&grant],
            TASK_SERVICE,
            crate::task_write::CONFIRMATION_TOOL,
            json!({"write": intent}).as_object().unwrap(),
        );
        let approved = crate::task_write::verify_exact_write_confirmation(
            &self.context,
            &self.task,
            intent,
            NOW,
            &confirmation.proof,
            &confirmation.action,
        )
        .unwrap();
        (approved, verified)
    }

    fn read_arguments(
        &self,
        recipient: &Signer,
        operation: &str,
    ) -> serde_json::Map<String, serde_json::Value> {
        let mut arguments =
            crate::release_verify::tests::arguments(&self.reads[0], recipient.principal.as_str());
        arguments.insert("task_id".into(), json!(TASK));
        arguments.insert(
            "task_commitment".into(),
            json!(hex::encode(self.task.commitment())),
        );
        arguments.insert("operation_id".into(), json!(operation));
        arguments
    }

    pub(crate) fn read(
        &self,
        child: bool,
        operation: &str,
    ) -> crate::release_verify::VerifiedReleaseRequest {
        let resources = &self.resources[&self.reads[0].digest_hex()];
        let mut signers = vec![&self.company, &self.machine, &self.agent];
        let mut grants = vec![&resources[0], &resources[1]];
        let recipient = if child {
            signers.push(&self.child);
            grants.push(&resources[2]);
            &self.child
        } else {
            &self.agent
        };
        let signed = chained(
            &signers,
            &grants,
            harness::SERVICE,
            harness::TOOL,
            &self.read_arguments(recipient, operation),
        );
        crate::release_verify::verify_task_release_request(
            &self.task,
            &self.reads[0],
            &self.context,
            NOW,
            &signed.proof,
            &signed.action,
        )
        .unwrap()
    }

    pub(crate) fn reserve_read(
        &self,
        verified: &crate::release_verify::VerifiedReleaseRequest,
    ) -> Result<(), ReleaseStateError> {
        self.ledger()
            .reserve_verified_request(verified, "source", 4, "synthetic-account", &self.time)
            .map(|_| ())
    }

    pub(crate) fn ledger(&self) -> FileReleaseTaskLedger {
        FileReleaseTaskLedger::open(&self.path).unwrap()
    }

    fn transaction(&self) -> EnrollmentTransaction<'_> {
        EnrollmentTransaction {
            context: &self.context,
            pins: &self.pins,
            time: &self.time,
        }
    }

    pub(crate) fn bootstrap(&self) -> Result<[u8; 32], ReleaseStateError> {
        let signers = [&self.company, &self.machine, &self.agent];
        let control = chained(
            &signers,
            &[&self.controls[0], &self.controls[1]],
            PARTICIPANT_SERVICE,
            ACTIVATE_ROOT_TOOL,
            json!({"root_enrollment_commitment": self.root.enrollment_commitment})
                .as_object()
                .unwrap(),
        );
        let signed_resources: Vec<_> = self
            .root
            .scopes
            .iter()
            .map(|scope| {
                let grants = &self.resources[&scope.recipe_digest];
                chained(
                    &signers,
                    &[&grants[0], &grants[1]],
                    &scope.service,
                    &scope.tool,
                    json!({&scope.resource_argument: match &scope.resource { EnrollmentResourceBinding::Exact { handle } => handle, EnrollmentResourceBinding::CreatedChild { .. } => panic!("static fixture") }})
                        .as_object()
                        .unwrap(),
                )
            })
            .collect();
        let witnesses: Vec<_> = self
            .root
            .scopes
            .iter()
            .zip(&signed_resources)
            .map(|(scope, resource)| EnrollmentResourceWitness {
                scope_id: &scope.scope_id,
                invocation: invocation(resource),
            })
            .collect();
        self.ledger().bootstrap_participants(
            TASK,
            &self.transaction(),
            &TaskEnrollmentRecipes {
                reads: &self.reads,
                writes: &self.writes,
            },
            &self.authority,
            &RootEnrollmentProofs {
                activation: invocation(&control),
                resources: &witnesses,
            },
        )
    }

    fn enrollment(&self) -> ParticipantEnrollment {
        ParticipantEnrollment {
            schema: PARTICIPANT_ENROLLMENT_SCHEMA.into(),
            engagement_commitment: *self.task.commitment(),
            partition_generation: 7,
            parent_enrollment: self.root.enrollment_commitment,
            parent_instance_generation: 3,
            enrollment_id: "agent-b-1".into(),
            child_principal: self.child.principal.as_str().into(),
            child_instance_generation: 5,
            delivery_channel: "agent-b".into(),
            control_grant: *grant_id(self.controls[2].statement()).unwrap().as_bytes(),
            scopes: self
                .root
                .scopes
                .iter()
                .map(|scope| ParticipantScopeGrant {
                    scope_id: scope.scope_id.clone(),
                    grant_id: *grant_id(self.resources[&scope.recipe_digest][2].statement())
                        .unwrap()
                        .as_bytes(),
                })
                .collect(),
            not_before: NOW,
            expires_at: NOW + 500,
            remaining_depth: 0,
            ceilings: self.root.ceilings,
        }
    }

    fn enroll(&self, accepted: &ParticipantEnrollment) -> Result<[u8; 32], ReleaseStateError> {
        self.enroll_proposal(&self.enrollment(), accepted)
    }

    fn enroll_proposal(
        &self,
        enrollment: &ParticipantEnrollment,
        accepted: &ParticipantEnrollment,
    ) -> Result<[u8; 32], ReleaseStateError> {
        let parent = chained(
            &[&self.company, &self.machine, &self.agent],
            &[&self.controls[0], &self.controls[1]],
            PARTICIPANT_SERVICE,
            ENROLL_PARTICIPANT_TOOL,
            json!({"enrollment": enrollment}).as_object().unwrap(),
        );
        let signers = [&self.company, &self.machine, &self.agent, &self.child];
        let child = chained(
            &signers,
            &self.controls.iter().collect::<Vec<_>>(),
            PARTICIPANT_SERVICE,
            ACCEPT_PARTICIPANT_TOOL,
            json!({"enrollment_commitment": accepted.commitment().unwrap()})
                .as_object()
                .unwrap(),
        );
        let signed_resources: Vec<_> = self
            .root
            .scopes
            .iter()
            .map(|scope| {
                let grants = &self.resources[&scope.recipe_digest];
                chained(
                    &signers,
                    &grants.iter().collect::<Vec<_>>(),
                    &scope.service,
                    &scope.tool,
                    json!({&scope.resource_argument: match &scope.resource { EnrollmentResourceBinding::Exact { handle } => handle, EnrollmentResourceBinding::CreatedChild { .. } => panic!("static fixture") }})
                        .as_object()
                        .unwrap(),
                )
            })
            .collect();
        let witnesses: Vec<_> = self
            .root
            .scopes
            .iter()
            .zip(&signed_resources)
            .map(|(scope, resource)| EnrollmentResourceWitness {
                scope_id: &scope.scope_id,
                invocation: invocation(resource),
            })
            .collect();
        self.ledger().enroll_participant(
            TASK,
            &self.transaction(),
            self.root.enrollment_commitment,
            &ParticipantEnrollmentProofs {
                parent: invocation(&parent),
                child: invocation(&child),
                resources: &witnesses,
            },
        )
    }

    pub(crate) fn digest(&self) -> [u8; 32] {
        self.ledger().load(TASK).unwrap().unwrap().digest().unwrap()
    }
}

#[test]
fn task_journal_persists_native_machine_agent_child_enrollment_without_new_capacity() {
    let fixture = Fixture::new();
    let root = fixture.bootstrap().unwrap();
    let initial = fixture.ledger().load(TASK).unwrap().unwrap().counts();
    let child = fixture.enroll(&fixture.enrollment()).unwrap();
    let reopened = fixture.ledger();
    let pins = reopened
        .participant_pins(TASK, &fixture.transaction(), child)
        .unwrap();
    assert_eq!(pins.principal, fixture.child.principal);
    assert_eq!(pins.instance_generation, 5);
    assert_eq!(reopened.load(TASK).unwrap().unwrap().counts(), initial);
    assert_eq!(initial, (0, 0, 0));
    let digest = fixture.digest();
    assert_eq!(fixture.bootstrap(), Err(ReleaseStateError::Replay));
    assert_eq!(
        fixture.enroll(&fixture.enrollment()),
        Err(ReleaseStateError::Replay)
    );
    assert_eq!(fixture.digest(), digest);
    assert_eq!(
        reopened
            .participant_pins(TASK, &fixture.transaction(), root)
            .unwrap()
            .principal,
        fixture.agent.principal
    );
}

#[test]
fn task_journal_enrollment_refusal_is_atomic_and_revocation_survives_reopening() {
    let fixture = Fixture::new();
    fixture.bootstrap().unwrap();
    let before = fixture.digest();
    let mut stale_acceptance = fixture.enrollment();
    stale_acceptance.enrollment_id = "other-id".into();
    assert!(fixture.enroll(&stale_acceptance).is_err());
    assert_eq!(before, fixture.digest());
    let child = fixture.enroll(&fixture.enrollment()).unwrap();
    fixture.ledger().revoke_participant(TASK, child).unwrap();
    assert_eq!(
        fixture
            .ledger()
            .participant_pins(TASK, &fixture.transaction(), child)
            .err(),
        Some(ReleaseStateError::Inactive)
    );
    let revoked = fixture.digest();
    fixture.ledger().revoke_participant(TASK, child).unwrap();
    assert_eq!(revoked, fixture.digest());
    assert_eq!(
        fixture.enroll(&fixture.enrollment()),
        Err(ReleaseStateError::Replay)
    );
    fixture.ledger().revoke(TASK).unwrap();
    assert_eq!(fixture.bootstrap(), Err(ReleaseStateError::Inactive));
    assert_eq!(
        fixture.enroll(&fixture.enrollment()),
        Err(ReleaseStateError::Inactive)
    );
    assert_eq!(
        fixture.ledger().load(TASK).unwrap().unwrap().counts(),
        (0, 0, 0)
    );
}

#[test]
fn task_journal_enrollment_rechecks_current_clock_under_the_partition_lock() {
    let fixture = Fixture::new();
    fixture.bootstrap().unwrap();
    let before = fixture.digest();
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(fixture.path.join(".release.lock"))
        .unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive).unwrap();
    std::thread::scope(|scope| {
        let (started, ready) = std::sync::mpsc::channel();
        let fixture_ref = &fixture;
        let worker = scope.spawn(move || {
            started.send(()).unwrap();
            fixture_ref.enroll(&fixture_ref.enrollment())
        });
        ready.recv().unwrap();
        fixture.clock.set(NOW + 600);
        drop(lock);
        assert_eq!(worker.join().unwrap(), Err(ReleaseStateError::Inactive));
    });
    assert_eq!(before, fixture.digest());
    fixture.clock.set(NOW);
    fixture.clock.trust_is(false);
    assert_eq!(
        fixture.enroll(&fixture.enrollment()),
        Err(ReleaseStateError::Inactive)
    );
    fixture
        .ledger()
        .revoke_participant(TASK, fixture.root.enrollment_commitment)
        .unwrap();
    fixture.clock.trust_is(true);
    assert_eq!(
        fixture.enroll(&fixture.enrollment()),
        Err(ReleaseStateError::Inactive)
    );
}

#[test]
fn task_root_projection_binds_recipe_connection_account_and_scope_kind() {
    let fixture = Fixture::new();
    let recipes = TaskEnrollmentRecipes {
        reads: &fixture.reads,
        writes: &[],
    };
    assert!(
        scopes(
            fixture.task.descriptor(),
            &TaskEnrollmentRecipes {
                reads: &[],
                writes: &[]
            }
        )
        .is_err()
    );
    let duplicates = [fixture.reads[0].clone(), fixture.reads[0].clone()];
    assert!(
        scopes(
            fixture.task.descriptor(),
            &TaskEnrollmentRecipes {
                reads: &duplicates,
                writes: &[]
            }
        )
        .is_err()
    );
    let mut authority = fixture.authority.clone();
    authority
        .resource_grants
        .insert("invented-scope".into(), [1; 32]);
    assert!(root_pins(&fixture.task, &recipes, &authority).is_err());
    for field in [
        "connection_id",
        "connection_generation",
        "connection_subject",
        "handle",
        "recipe_digest",
    ] {
        let mut changed = serde_json::to_value(fixture.task.descriptor()).unwrap();
        changed["read_scopes"][0][field] = if field == "connection_generation" {
            json!(5)
        } else {
            json!("substituted")
        };
        let changed: AgentTaskDescriptor = serde_json::from_value(changed).unwrap();
        assert_ne!(
            scope_id("read", &fixture.task.descriptor().read_scopes[0]).unwrap(),
            scope_id("read", &changed.read_scopes[0]).unwrap(),
            "{field}"
        );
    }
    assert_ne!(
        scope_id("read", &fixture.task.descriptor().read_scopes[0]).unwrap(),
        scope_id("write", &fixture.task.descriptor().read_scopes[0]).unwrap()
    );
}

#[test]
fn concurrent_root_and_child_publications_have_one_winner_each() {
    let fixture = Fixture::new();
    let barrier = std::sync::Barrier::new(2);
    for bootstrap in [true, false] {
        let outcomes = std::thread::scope(|scope| {
            let jobs: Vec<_> = (0..2)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        if bootstrap {
                            fixture.bootstrap()
                        } else {
                            fixture.enroll(&fixture.enrollment())
                        }
                    })
                })
                .collect();
            jobs.into_iter()
                .map(|job| job.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| **result == Err(ReleaseStateError::Replay))
                .count(),
            1
        );
    }
    let child = fixture.enrollment().commitment().unwrap();
    assert!(
        fixture
            .ledger()
            .participant_pins(TASK, &fixture.transaction(), child)
            .is_ok()
    );
    assert_eq!(
        fixture.ledger().load(TASK).unwrap().unwrap().counts(),
        (0, 0, 0)
    );
}

#[test]
fn concurrent_root_revocation_and_child_enrollment_follow_one_journal_order() {
    let fixture = Fixture::new();
    fixture.bootstrap().unwrap();
    let barrier = std::sync::Barrier::new(2);
    let enrolled = std::thread::scope(|scope| {
        let enrollment = scope.spawn(|| {
            barrier.wait();
            fixture.enroll(&fixture.enrollment())
        });
        let revocation = scope.spawn(|| {
            barrier.wait();
            fixture
                .ledger()
                .revoke_participant(TASK, fixture.root.enrollment_commitment)
        });
        revocation.join().unwrap().unwrap();
        enrollment.join().unwrap()
    });
    assert!(enrolled.is_ok() || enrolled == Err(ReleaseStateError::Inactive));
    assert_eq!(
        fixture
            .ledger()
            .participant_pins(
                TASK,
                &fixture.transaction(),
                fixture.enrollment().commitment().unwrap()
            )
            .err(),
        Some(ReleaseStateError::Inactive)
    );
    assert_eq!(
        fixture.enroll(&fixture.enrollment()),
        Err(ReleaseStateError::Inactive)
    );
}

#[test]
fn stored_root_cannot_change_the_signed_task_partition_even_with_a_new_root_commitment() {
    let fixture = Fixture::new();
    fixture.bootstrap().unwrap();
    let path = std::fs::read_dir(&fixture.path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .unwrap();
    let original = std::fs::read(&path).unwrap();
    let mut stored: serde_json::Value = serde_json::from_slice(&original).unwrap();
    let mut root: ParentEnrollmentPins =
        serde_json::from_value(stored["participants"]["tree"]["root"].clone()).unwrap();
    root.partition_generation += 1;
    root.enrollment_commitment = root_enrollment_commitment(&root).unwrap();
    stored["participants"]["tree"]["root"] = serde_json::to_value(root).unwrap();
    std::fs::write(&path, serde_json_canonicalizer::to_vec(&stored).unwrap()).unwrap();
    assert_eq!(
        fixture.ledger().load(TASK).err(),
        Some(ReleaseStateError::Corrupt)
    );
    let mut missing: serde_json::Value = serde_json::from_slice(&original).unwrap();
    missing.as_object_mut().unwrap().remove("participants");
    std::fs::write(&path, serde_json_canonicalizer::to_vec(&missing).unwrap()).unwrap();
    assert_eq!(
        fixture.ledger().load(TASK).err(),
        Some(ReleaseStateError::Corrupt)
    );
    std::fs::write(&path, original).unwrap();
    assert!(
        fixture
            .ledger()
            .participant_pins(
                TASK,
                &fixture.transaction(),
                fixture.root.enrollment_commitment
            )
            .is_ok()
    );
}

#[test]
fn native_read_reservation_samples_clock_after_journal_lock_acquisition() {
    let fixture = Fixture::new();
    fixture.bootstrap().unwrap();
    let mut arguments = crate::release_verify::tests::arguments(
        &fixture.reads[0],
        fixture.agent.principal.as_str(),
    );
    arguments.insert("task_id".into(), json!(TASK));
    arguments.insert(
        "task_commitment".into(),
        json!(hex::encode(fixture.task.commitment())),
    );
    let signed = chained(
        &[&fixture.company, &fixture.machine, &fixture.agent],
        &[
            &fixture.resources[&fixture.reads[0].digest_hex()][0],
            &fixture.resources[&fixture.reads[0].digest_hex()][1],
        ],
        harness::SERVICE,
        harness::TOOL,
        &arguments,
    );
    let verified = crate::release_verify::verify_task_release_request(
        &fixture.task,
        &fixture.reads[0],
        &fixture.context,
        NOW,
        &signed.proof,
        &signed.action,
    )
    .unwrap();
    let before = fixture.digest();
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(fixture.path.join(".release.lock"))
        .unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive).unwrap();
    let reserve = || {
        fixture.ledger().reserve_verified_request(
            &verified,
            "source",
            4,
            "synthetic-account",
            &fixture.time,
        )
    };
    std::thread::scope(|scope| {
        let (started, ready) = std::sync::mpsc::channel();
        let worker = scope.spawn(move || {
            started.send(()).unwrap();
            reserve()
        });
        ready.recv().unwrap();
        fixture.clock.set(NOW + 600);
        drop(lock);
        assert_eq!(
            worker.join().unwrap().err(),
            Some(ReleaseStateError::Inactive)
        );
    });
    assert_eq!(fixture.digest(), before);
    fixture.clock.set(NOW);
    fixture.clock.trust_is(false);
    assert_eq!(reserve().err(), Some(ReleaseStateError::Inactive));
    assert_eq!(fixture.digest(), before);
    fixture.clock.trust_is(true);
    reserve().unwrap();
    assert_eq!(
        fixture.ledger().load(TASK).unwrap().unwrap().counts(),
        (1, 0, 0)
    );
    assert_eq!(reserve().err(), Some(ReleaseStateError::Replay));
}

#[test]
fn write_reservation_samples_time_and_preflight_deadline_inside_journal_lock() {
    for delta in [None, Some(125)] {
        let fixture = Fixture::with_writes(true);
        fixture.bootstrap().unwrap();
        let (approved, verified) = fixture.write("write-1");
        let before = fixture.digest();
        let deadline = delta.map(|seconds| NOW + seconds);
        let reserve = || {
            fixture.ledger().reserve_write_with_namespace(
                &approved,
                &verified,
                harness::NAMESPACE,
                &fixture.time,
                deadline,
            )
        };
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(fixture.path.join(".release.lock"))
            .unwrap();
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive).unwrap();
        std::thread::scope(|scope| {
            let (started, ready) = std::sync::mpsc::channel();
            let worker = scope.spawn(move || {
                started.send(()).unwrap();
                reserve()
            });
            ready.recv().unwrap();
            fixture.clock.set(deadline.unwrap_or(NOW + 600));
            drop(lock);
            assert_eq!(
                worker.join().unwrap().err(),
                Some(ReleaseStateError::Inactive)
            );
        });
        assert_eq!(fixture.digest(), before);
        fixture.clock.set(NOW);
        fixture.clock.trust_is(false);
        assert_eq!(reserve().err(), Some(ReleaseStateError::Inactive));
        assert_eq!(fixture.digest(), before);
        fixture.clock.trust_is(true);
        reserve().unwrap();
        assert_eq!(reserve().err(), Some(ReleaseStateError::Replay));
        fixture.clock.trust_is(false);
        fixture.ledger().revoke(TASK).unwrap();
        assert_eq!(
            fixture.ledger().load(TASK).unwrap().unwrap().write_count(),
            1
        );
    }
}

#[test]
fn task_operations_require_native_root_and_exact_enrolled_scope_path() {
    let fixture = Fixture::with_writes(true);
    let read = fixture.read(false, "read-1");
    let (write, command) = fixture.write("write-1");
    let before = fixture.digest();
    assert_eq!(
        fixture.reserve_read(&read),
        Err(ReleaseStateError::Inactive)
    );
    assert_eq!(
        fixture
            .ledger()
            .reserve_write_with_namespace(&write, &command, harness::NAMESPACE, &fixture.time, None)
            .err(),
        Some(ReleaseStateError::Inactive)
    );
    assert_eq!(fixture.digest(), before);
    fixture.bootstrap().unwrap();
    let child_read = fixture.read(true, "child-read-1");
    assert_eq!(
        fixture.reserve_read(&child_read),
        Err(ReleaseStateError::Binding)
    );
    fixture.enroll(&fixture.enrollment()).unwrap();
    let unrelated = grant_for_audiences(
        &fixture.machine,
        &fixture.child,
        harness::SERVICE,
        &[harness::TOOL],
        Some(grant_id(fixture.resources[&fixture.reads[0].digest_hex()][0].statement()).unwrap()),
        0,
        vec![
            resource_audience(fixture.task.commitment(), 7, &fixture.reads[0].digest_hex())
                .unwrap(),
        ],
    );
    let substituted = chained(
        &[&fixture.company, &fixture.machine, &fixture.child],
        &[
            &fixture.resources[&fixture.reads[0].digest_hex()][0],
            &unrelated,
        ],
        harness::SERVICE,
        harness::TOOL,
        &fixture.read_arguments(&fixture.child, "child-read-1"),
    );
    let substituted = crate::release_verify::verify_task_release_request(
        &fixture.task,
        &fixture.reads[0],
        &fixture.context,
        NOW,
        &substituted.proof,
        &substituted.action,
    )
    .unwrap();
    let before = fixture.digest();
    assert_eq!(
        fixture.reserve_read(&substituted),
        Err(ReleaseStateError::Binding)
    );
    assert_eq!(fixture.digest(), before);
    fixture.reserve_read(&child_read).unwrap();
    fixture
        .ledger()
        .reserve_write_with_namespace(&write, &command, harness::NAMESPACE, &fixture.time, None)
        .unwrap();
    assert_eq!(
        fixture.reserve_read(&child_read),
        Err(ReleaseStateError::Replay)
    );
    assert_eq!(
        fixture.ledger().load(TASK).unwrap().unwrap().write_count(),
        1
    );
}

#[test]
fn descendant_reads_and_unknown_disclosures_keep_all_ancestor_charges() {
    let fixture = Fixture::new();
    fixture.bootstrap().unwrap();
    let mut child = fixture.enrollment();
    child.ceilings.provider_reads = 2;
    child.ceilings.disclosures = 1;
    child.ceilings.disclosure_bytes = 5;
    let child_id = fixture.enroll_proposal(&child, &child).unwrap();
    fixture
        .reserve_read(&fixture.read(true, "child-1"))
        .unwrap();
    fixture
        .reserve_read(&fixture.read(true, "child-2"))
        .unwrap();
    let before = fixture.digest();
    assert_eq!(
        fixture.reserve_read(&fixture.read(true, "child-3")),
        Err(ReleaseStateError::Exhausted)
    );
    assert_eq!(fixture.digest(), before);
    fixture
        .reserve_read(&fixture.read(false, "root-1"))
        .unwrap();
    fixture
        .reserve_read(&fixture.read(false, "root-2"))
        .unwrap();
    let key = crate::ReleaseCommitmentKey::new(2, zeroize::Zeroizing::new([0x93; 32])).unwrap();
    fixture
        .ledger()
        .enter_release(TASK, "child-1", b"Hello", &key, &fixture.time)
        .unwrap();
    let before = fixture.digest();
    assert_eq!(
        fixture
            .ledger()
            .enter_release(TASK, "child-2", b"x", &key, &fixture.time)
            .err(),
        Some(ReleaseStateError::Exhausted)
    );
    assert_eq!(fixture.digest(), before);
    let reopened = fixture.ledger().load(TASK).unwrap().unwrap();
    assert!(reopened.delivery_unknown("child-1"));
    assert_eq!(reopened.counts(), (4, 1, 5));
    fixture.ledger().revoke_participant(TASK, child_id).unwrap();
    assert_eq!(
        fixture.reserve_read(&fixture.read(false, "root-3")),
        Err(ReleaseStateError::Exhausted)
    );
    assert_eq!(
        fixture
            .ledger()
            .enter_release(TASK, "child-2", b"x", &key, &fixture.time)
            .err(),
        Some(ReleaseStateError::Inactive)
    );
    assert_eq!(
        fixture.ledger().load(TASK).unwrap().unwrap().counts(),
        (4, 1, 5)
    );
}

#[test]
fn root_and_child_contend_for_one_last_shared_provider_read() {
    let fixture = Fixture::new();
    fixture.bootstrap().unwrap();
    fixture.enroll(&fixture.enrollment()).unwrap();
    for id in ["root-1", "root-2", "root-3"] {
        fixture.reserve_read(&fixture.read(false, id)).unwrap();
    }
    let root = fixture.read(false, "root-4");
    let child = fixture.read(true, "child-1");
    let barrier = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let jobs: Vec<_> = [&root, &child]
            .into_iter()
            .map(|read| {
                let barrier = &barrier;
                let fixture = &fixture;
                scope.spawn(move || {
                    barrier.wait();
                    fixture.reserve_read(read)
                })
            })
            .collect();
        jobs.into_iter()
            .map(|job| job.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(ReleaseStateError::Exhausted))
            .count(),
        1
    );
    assert_eq!(
        fixture.ledger().load(TASK).unwrap().unwrap().counts(),
        (4, 0, 0)
    );
}

#[test]
fn enrolled_resources_cannot_escape_through_ordinary_entry_or_another_recipe() {
    let fixture = Fixture::with_writes(true);
    fixture.bootstrap().unwrap();
    let grants = &fixture.resources[&fixture.reads[0].digest_hex()];
    let signers = [&fixture.company, &fixture.machine, &fixture.agent];
    let args = fixture.read_arguments(&fixture.agent, "isolated-read");
    let signed = chained(
        &signers,
        &[&grants[0], &grants[1]],
        harness::SERVICE,
        harness::TOOL,
        &args,
    );
    assert!(
        crate::release_verify::verify_release_request(
            &fixture.reads[0],
            &fixture.context,
            NOW,
            &signed.proof,
            &signed.action
        )
        .is_err()
    );
    // A caller changing only the invocation audience cannot widen its grants.
    let ordinary = crate::observed_tests::submission_for(
        &fixture.machine,
        &fixture.agent,
        &grants[1],
        &args,
        &[],
        harness::SERVICE,
        harness::TOOL,
        NOW,
    );
    assert!(
        crate::release_verify::verify_release_request(
            &fixture.reads[0],
            &fixture.context,
            NOW,
            &ordinary.proof,
            &ordinary.action
        )
        .is_err()
    );
    // The same native MCP permission is not authority for a different recipe.
    assert!(
        crate::engine::verify_task_command(
            &fixture.task,
            &fixture.writes[0],
            &fixture.context,
            NOW,
            &signed.proof,
            &signed.action
        )
        .is_err()
    );
    let before = fixture.digest();
    for (commitment, generation) in [([0x77; 32], 7), (*fixture.task.commitment(), 8)] {
        let foreign = chain_grants_for_audience(
            &fixture.company,
            &fixture.machine,
            &fixture.agent,
            &fixture.child,
            harness::SERVICE,
            &[harness::TOOL],
            resource_audience(&commitment, generation, &fixture.reads[0].digest_hex()).unwrap(),
        );
        let signed = chained(
            &signers,
            &[&foreign[0], &foreign[1]],
            harness::SERVICE,
            harness::TOOL,
            &args,
        );
        assert!(
            crate::release_verify::verify_task_release_request(
                &fixture.task,
                &fixture.reads[0],
                &fixture.context,
                NOW,
                &signed.proof,
                &signed.action
            )
            .is_err()
        );
    }
    assert_eq!(fixture.digest(), before);
    fixture
        .reserve_read(&fixture.read(false, "isolated-read"))
        .unwrap();
}

#[test]
fn pending_child_projection_commits_lineage_without_substituting_parent_handle() {
    let fixture = Fixture::with_writes(true);
    let create = CompiledRecipe::compile(
        include_bytes!(
            "../../../../../demos/google-employee-delegation/create_reference/recipe.json"
        ),
        include_bytes!(
            "../../../../../demos/google-employee-delegation/create_reference/profile.lock.json"
        ),
    )
    .unwrap();
    let populate = CompiledRecipe::compile(
        include_bytes!(
            "../../../../../demos/google-employee-delegation/populate_reference/recipe.json"
        ),
        include_bytes!(
            "../../../../../demos/google-employee-delegation/populate_reference/profile.lock.json"
        ),
    )
    .unwrap();
    let mut card = fixture.task.descriptor().clone();
    card.write_scopes[0].recipe_digest = create.digest_hex();
    card.write_scopes[0].verb = crate::task_activation::TaskWriteVerb::Create;
    card.write_scopes[0].handle = "project-a-folder".into();
    card.max_writes = 2;
    card.pending_child = Some(crate::task_activation::TaskPendingChild {
        create_operation_id: "create-one".into(),
        create_recipe_digest: create.digest_hex(),
        populate_recipe_digest: populate.digest_hex(),
        parent_handle: "project-a-folder".into(),
        title: "Approved draft".into(),
        marker: "owned-marker".into(),
    });
    let writes = [create, populate];
    let recipes = TaskEnrollmentRecipes {
        reads: &fixture.reads,
        writes: &writes,
    };
    let projected = scopes(&card, &recipes).unwrap();
    let deferred = projected
        .iter()
        .find(|scope| scope.recipe_digest == writes[1].digest_hex())
        .unwrap();
    assert_eq!(deferred.scope_id, pending_scope_id(&card).unwrap());
    assert_eq!(
        deferred.resource,
        EnrollmentResourceBinding::CreatedChild {
            create_operation_id: "create-one".into(),
            create_recipe_digest: writes[0].digest_hex(),
            parent_scope_id: scope_id("write", &card.write_scopes[0]).unwrap(),
        }
    );
    for mutation in 0..5 {
        let mut changed = card.clone();
        let pending = changed.pending_child.as_mut().unwrap();
        match mutation {
            0 => pending.create_operation_id = "other-create".into(),
            1 => pending.title = "other-title".into(),
            2 => pending.marker = "other-marker".into(),
            3 => changed.write_scopes[0].connection_generation += 1,
            _ => changed.write_scopes[0].connection_subject = "other-account".into(),
        }
        assert_ne!(pending_scope_id(&changed).unwrap(), deferred.scope_id);
    }
    assert!(
        scopes(
            &card,
            &TaskEnrollmentRecipes {
                reads: &fixture.reads,
                writes: &writes[..1]
            }
        )
        .is_err()
    );
    let mut changed = card;
    changed.pending_child.as_mut().unwrap().parent_handle = "other-parent".into();
    assert!(scopes(&changed, &recipes).is_err());
}
