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

fn write_recipe_sources() -> (serde_json::Value, Vec<u8>) {
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
    (source, lock)
}

fn write_recipe() -> CompiledRecipe {
    let (source, lock) = write_recipe_sources();
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
        self.write_as(false, operation_id)
    }

    fn write_as(
        &self,
        child: bool,
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
        let mut signers = vec![&self.company, &self.machine, &self.agent];
        let mut grants = vec![&resources[0], &resources[1]];
        if child {
            signers.push(&self.child);
            grants.push(&resources[2]);
        }
        let signed = chained(
            &signers,
            &grants,
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
        let writer = if child {
            self.ledger()
                .load(TASK)
                .unwrap()
                .unwrap()
                .write_participant(&verified)
                .unwrap()
        } else {
            crate::participant_enrollment::EnrolledParticipant::from_pins(&self.root)
        };
        let intent = crate::task_write::derive_exact_write_intent(
            &self.task, &verified, recipe, &binding, None, &writer, NOW,
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

#[test]
fn enrolled_delivery_permit_binds_child_bytes_and_retains_late_ack_after_revocation() {
    let fixture = Fixture::new();
    let read = fixture.read(true, "child-delivery");
    assert!(
        fixture
            .ledger()
            .load(TASK)
            .unwrap()
            .unwrap()
            .read_delivery_binding(&read, NOW)
            .is_err()
    );
    fixture.bootstrap().unwrap();
    let enrollment = fixture.enroll(&fixture.enrollment()).unwrap();
    let state = fixture.ledger().load(TASK).unwrap().unwrap();
    let binding = state.read_delivery_binding(&read, NOW).unwrap();
    let other = state
        .read_delivery_binding(&fixture.read(true, "another-operation"), NOW)
        .unwrap();
    let fields = binding.message_fields().unwrap();
    assert_eq!(fields["recipient"], fixture.child.principal.as_str());
    assert_eq!(fields["delivery_channel"], "agent-b");
    assert_eq!(fields["enrollment_commitment"], hex::encode(enrollment));
    assert_eq!(fields["partition_generation"], 7);
    assert_eq!(fields["instance_generation"], 5);
    fixture.reserve_read(&read).unwrap();
    fixture
        .reserve_read(&fixture.read(true, "another-operation"))
        .unwrap();
    let key = crate::ReleaseCommitmentKey::new(2, zeroize::Zeroizing::new([0x93; 32])).unwrap();
    let (entered, permit) = fixture
        .ledger()
        .enter_release(TASK, "child-delivery", b"Hello", &key, &fixture.time)
        .unwrap();
    assert_eq!(
        permit.validate_content(&binding, b"Hello", &key).unwrap(),
        read.request().resource_handle()
    );
    assert!(permit.validate_content(&other, b"Hello", &key).is_err());
    assert!(permit.validate_content(&binding, b"Other", &key).is_err());
    let rotated = crate::ReleaseCommitmentKey::new(3, zeroize::Zeroizing::new([0x93; 32])).unwrap();
    assert!(
        permit
            .validate_content(&binding, b"Hello", &rotated)
            .is_err()
    );
    fixture
        .ledger()
        .revoke_participant(TASK, fixture.root.enrollment_commitment)
        .unwrap();
    assert_eq!(
        fixture
            .ledger()
            .enter_release(TASK, "another-operation", b"Hello", &key, &fixture.time)
            .err(),
        Some(ReleaseStateError::Inactive)
    );
    assert!(
        fixture
            .ledger()
            .load(TASK)
            .unwrap()
            .unwrap()
            .read_delivery_binding(&read, NOW)
            .is_err()
    );
    // The already entered permit describes a charged effect, even after revocation.
    assert!(permit.validate_content(&binding, b"Hello", &key).is_ok());
    let ack = child_delivery_ack(
        &fixture.child,
        &binding,
        read.request().resource_handle(),
        &key,
    );
    let retained = fixture.ledger().acknowledge(&ack).unwrap();
    assert_eq!(retained.counts(), entered.counts());
    assert_eq!(
        retained.stage("child-delivery"),
        Some(crate::release_state::ReleaseStage::AgentAcknowledged)
    );
    assert!(fixture.ledger().acknowledge(&ack).is_err());
}

fn child_delivery_ack(
    child: &Signer,
    binding: &crate::release_state::ReleaseDeliveryBinding,
    resource: &str,
    key: &crate::ReleaseCommitmentKey,
) -> crate::release_state::VerifiedAgentAcknowledgement {
    use crate::release_ack::{acknowledgement_message, verify_agent_acknowledgement};
    use auths_identity_raw_key::RawKeyIdentityMethod;
    use ed25519_dalek::Signer as _;

    let identity = RawKeyIdentityMethod::identity(
        auths_signature_ed25519::ED25519_V1,
        child.key.verifying_key().to_bytes().to_vec(),
    )
    .unwrap()
    .into_public_identity()
    .to_descriptor()
    .unwrap();
    let packet = identity.encode().unwrap();
    let message = acknowledgement_message(binding, resource, b"Hello", key).unwrap();
    let signature = child
        .key
        .sign(
            &identity
                .signing_preimage("default-signing", &message)
                .unwrap(),
        )
        .to_bytes();
    for name in [
        "task_commitment",
        "operation_id",
        "recipient",
        "delivery_channel",
        "enrollment_commitment",
        "partition_generation",
        "instance_generation",
    ] {
        let mut altered: serde_json::Value = serde_json::from_slice(&message).unwrap();
        altered[name] = json!("substituted");
        let bytes = serde_json_canonicalizer::to_vec(&altered).unwrap();
        let changed = child
            .key
            .sign(
                &identity
                    .signing_preimage("default-signing", &bytes)
                    .unwrap(),
            )
            .to_bytes();
        assert!(
            verify_agent_acknowledgement(binding, resource, b"Hello", key, &packet, &changed)
                .is_err(),
            "{name}"
        );
    }
    verify_agent_acknowledgement(binding, resource, b"Hello", key, &packet, &signature).unwrap()
}

async fn child_channel_peer(
    listener: tokio::net::UnixListener,
    key: ed25519_dalek::SigningKey,
    identity: auths_identity::IdentityDescriptor,
    fields: serde_json::Map<String, serde_json::Value>,
) -> Vec<u8> {
    use ed25519_dalek::Signer as _;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let (mut stream, _) = listener.accept().await.unwrap();
    let length = stream.read_u32().await.unwrap() as usize;
    assert!(length <= 4096);
    let mut challenge = vec![0; length];
    stream.read_exact(&mut challenge).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&challenge).unwrap();
    assert_eq!(parsed["schema"], "auths.agent-release-channel-challenge/2");
    for (name, expected) in &fields {
        assert_eq!(&parsed[name], expected);
    }
    let signature = key
        .sign(
            &identity
                .signing_preimage("default-signing", &challenge)
                .unwrap(),
        )
        .to_bytes();
    stream.write_u32(64).await.unwrap();
    stream.write_all(&signature).await.unwrap();
    let length = stream.read_u32().await.unwrap() as usize;
    assert!(length <= 262_144);
    let mut content = vec![0; length];
    stream.read_exact(&mut content).await.unwrap();
    let length = stream.read_u32().await.unwrap() as usize;
    assert!(length <= 4096);
    let mut message = vec![0; length];
    stream.read_exact(&mut message).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&message).unwrap();
    assert_eq!(parsed["schema"], "auths.agent-release-ack/2");
    for (name, expected) in &fields {
        assert_eq!(&parsed[name], expected);
    }
    let signature = key
        .sign(
            &identity
                .signing_preimage("default-signing", &message)
                .unwrap(),
        )
        .to_bytes();
    stream.write_u32(64).await.unwrap();
    stream.write_all(&signature).await.unwrap();
    content
}

#[tokio::test]
async fn enrolled_child_channel_consumes_its_durable_permit_and_acknowledges_after_revocation() {
    use crate::release_channel::{ReleaseChannelError, UnixAgentReleaseChannel};
    use auths_identity_raw_key::RawKeyIdentityMethod;
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::new();
    fixture.bootstrap().unwrap();
    fixture.enroll(&fixture.enrollment()).unwrap();
    let read = fixture.read(true, "child-channel");
    let binding = fixture
        .ledger()
        .load(TASK)
        .unwrap()
        .unwrap()
        .read_delivery_binding(&read, NOW)
        .unwrap();
    let fields = binding.message_fields().unwrap();
    let identity = RawKeyIdentityMethod::identity(
        auths_signature_ed25519::ED25519_V1,
        fixture.child.key.verifying_key().to_bytes().to_vec(),
    )
    .unwrap()
    .into_public_identity()
    .to_descriptor()
    .unwrap();
    let packet = identity.encode().unwrap();
    let socket = fixture.path.join("child.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let wrong = UnixAgentReleaseChannel::new(&socket, "agent-a".into(), packet.clone()).unwrap();
    assert!(matches!(
        wrong.authenticate(binding.clone()).await,
        Err(ReleaseChannelError::Binding)
    ));
    let peer = tokio::spawn(child_channel_peer(
        listener,
        fixture.child.key.clone(),
        identity,
        fields,
    ));
    let channel = UnixAgentReleaseChannel::new(&socket, "agent-b".into(), packet).unwrap();
    let authenticated = channel.authenticate(binding).await.unwrap();
    fixture.reserve_read(&read).unwrap();
    let key = crate::ReleaseCommitmentKey::new(2, zeroize::Zeroizing::new([0x93; 32])).unwrap();
    let (entered, permit) = fixture
        .ledger()
        .enter_release(TASK, "child-channel", b"Hello", &key, &fixture.time)
        .unwrap();
    fixture
        .ledger()
        .revoke_participant(TASK, fixture.root.enrollment_commitment)
        .unwrap();
    let evidence = authenticated.deliver(permit, b"Hello", &key).await.unwrap();
    let retained = fixture.ledger().acknowledge(&evidence).unwrap();
    assert_eq!(retained.counts(), entered.counts());
    assert_eq!(
        retained.stage("child-channel"),
        Some(crate::release_state::ReleaseStage::AgentAcknowledged)
    );
    assert_eq!(peer.await.unwrap(), b"Hello");
}

#[test]
fn exact_child_write_approval_cannot_be_reused_by_another_enrolled_writer() {
    let fixture = Fixture::with_writes(true);
    fixture.bootstrap().unwrap();
    let enrolled = fixture.enroll(&fixture.enrollment()).unwrap();
    let (child, child_command) = fixture.write_as(true, "same-write");
    let (root, root_command) = fixture.write("same-write");
    assert_eq!(
        child.intent().action_commitment,
        root.intent().action_commitment
    );
    assert_eq!(
        child.intent().request_commitment,
        root.intent().request_commitment
    );
    assert_ne!(child.intent().writer, root.intent().writer);
    assert_confirmation_writer_is_exact(&fixture, &child, &root);
    let before = fixture.digest();
    assert_eq!(
        fixture
            .ledger()
            .reserve_write_with_namespace(
                &child,
                &root_command,
                harness::NAMESPACE,
                &fixture.time,
                None
            )
            .err(),
        Some(ReleaseStateError::Binding)
    );
    assert_writer_substitutions_refused(&fixture, &child, &child_command);
    assert_eq!(fixture.digest(), before);
    let retained = fixture
        .ledger()
        .reserve_write_with_namespace(
            &child,
            &child_command,
            harness::NAMESPACE,
            &fixture.time,
            None,
        )
        .unwrap();
    let stored = serde_json::to_value(&retained).unwrap();
    assert_eq!(
        stored["writes"]["same-write"]["writer"],
        serde_json::to_value(&child.intent().writer).unwrap()
    );
    fixture.ledger().revoke_participant(TASK, enrolled).unwrap();
    let reopened = fixture.ledger().load(TASK).unwrap().unwrap();
    assert_eq!(reopened.write_count(), 1);
    assert!(!reopened.write_participant_active(&child.intent().writer, NOW));
    assert_eq!(
        reopened.write_participant(&child_command).unwrap(),
        child.intent().writer
    );
    let (other, other_command) = fixture.write("other-write");
    assert_eq!(
        fixture
            .ledger()
            .reserve_write_with_namespace(
                &other,
                &other_command,
                harness::NAMESPACE,
                &fixture.time,
                None
            )
            .err(),
        Some(ReleaseStateError::Exhausted)
    );
}

fn assert_confirmation_writer_is_exact(
    fixture: &Fixture,
    child: &crate::task_write::ApprovedTaskWrite,
    root: &crate::task_write::ApprovedTaskWrite,
) {
    let human_grant = grant(
        &fixture.company,
        &fixture.human,
        TASK_SERVICE,
        &[crate::task_write::CONFIRMATION_TOOL],
        None,
        0,
    );
    let signature = chained(
        &[&fixture.company, &fixture.human],
        &[&human_grant],
        TASK_SERVICE,
        crate::task_write::CONFIRMATION_TOOL,
        json!({"write": child.intent()}).as_object().unwrap(),
    );
    assert!(
        crate::task_write::verify_exact_write_confirmation(
            &fixture.context,
            &fixture.task,
            root.intent().clone(),
            NOW,
            &signature.proof,
            &signature.action
        )
        .is_err()
    );
}

fn assert_writer_substitutions_refused(
    fixture: &Fixture,
    approved: &crate::task_write::ApprovedTaskWrite,
    command: &crate::engine::VerifiedCommand,
) {
    for (field, value) in [
        ("principal", json!(fixture.agent.principal.as_str())),
        ("enrollment_commitment", json!("ef".repeat(32))),
        ("engagement_commitment", json!("ef".repeat(32))),
        ("instance_generation", json!(6)),
        ("partition_generation", json!(8)),
    ] {
        let mut intent = serde_json::to_value(approved.intent()).unwrap();
        intent["writer"][field] = value;
        let intent = serde_json::from_value(intent).unwrap();
        let substituted = crate::task_write::ApprovedTaskWrite::from_test_intent(intent);
        assert_eq!(
            fixture
                .ledger()
                .reserve_write_with_namespace(
                    &substituted,
                    command,
                    harness::NAMESPACE,
                    &fixture.time,
                    None
                )
                .err(),
            Some(ReleaseStateError::Binding)
        );
    }
}

#[test]
fn root_and_child_contend_for_one_write_and_revocation_stops_unreserved_child() {
    let fixture = Fixture::with_writes(true);
    fixture.bootstrap().unwrap();
    let enrolled = fixture.enroll(&fixture.enrollment()).unwrap();
    let child = fixture.write_as(true, "child-write");
    let root = fixture.write("root-write");
    let barrier = std::sync::Barrier::new(2);
    let reserve = |approval: &crate::task_write::ApprovedTaskWrite,
                   command: &crate::engine::VerifiedCommand| {
        barrier.wait();
        fixture
            .ledger()
            .reserve_write_with_namespace(
                approval,
                command,
                harness::NAMESPACE,
                &fixture.time,
                None,
            )
            .map(|_| ())
    };
    let results = std::thread::scope(|scope| {
        let child = scope.spawn(|| reserve(&child.0, &child.1));
        let root = scope.spawn(|| reserve(&root.0, &root.1));
        [child.join().unwrap(), root.join().unwrap()]
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(ReleaseStateError::Exhausted))
            .count(),
        1
    );
    fixture.ledger().revoke_participant(TASK, enrolled).unwrap();
    assert_eq!(
        fixture.ledger().load(TASK).unwrap().unwrap().write_count(),
        1
    );

    let fixture = Fixture::with_writes(true);
    fixture.bootstrap().unwrap();
    let enrolled = fixture.enroll(&fixture.enrollment()).unwrap();
    let (child, command) = fixture.write_as(true, "revoked-write");
    fixture.ledger().revoke_participant(TASK, enrolled).unwrap();
    let before = fixture.digest();
    assert_eq!(
        fixture
            .ledger()
            .reserve_write_with_namespace(&child, &command, harness::NAMESPACE, &fixture.time, None)
            .err(),
        Some(ReleaseStateError::Inactive)
    );
    assert_eq!(fixture.digest(), before);
}

#[test]
fn enrolled_writer_review_fixture_matches_native_approval_payload() {
    let fixture = Fixture::with_writes(true);
    fixture.bootstrap().unwrap();
    fixture.enroll(&fixture.enrollment()).unwrap();
    let (approved, command) = fixture.write_as(true, "fixture-write");
    fixture
        .ledger()
        .load(TASK)
        .unwrap()
        .unwrap()
        .admit_write_participant(&command, approved.intent(), NOW)
        .unwrap();
    let review = crate::engine::task_submission_review(command, approved.intent().clone()).unwrap();
    let value = json!({
        "schema": "auths.gateway-enrolled-write-review-fixture/1",
        "card": fixture.task.descriptor(),
        "recipe": write_recipe_sources().0,
        "recipe_digest": fixture.writes[0].digest_hex(),
        "review": review,
    });
    let bytes = serde_json_canonicalizer::to_vec(&value).unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/enrolled-write-review-v1.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &bytes).unwrap();
    }
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

fn reserved_child_write(
    fixture: &Fixture,
) -> (
    crate::task_write::ApprovedTaskWrite,
    crate::engine::VerifiedCommand,
    [u8; 32],
) {
    fixture.bootstrap().unwrap();
    let child = fixture.enroll(&fixture.enrollment()).unwrap();
    let (approval, command) = fixture.write_as(true, "entry-write");
    fixture
        .ledger()
        .reserve_write_with_namespace(&approval, &command, harness::NAMESPACE, &fixture.time, None)
        .unwrap();
    (approval, command, child)
}

#[test]
fn write_entry_orders_revocation_and_never_reopens_after_restart() {
    for revoke_first in [true, false] {
        let fixture = Fixture::with_writes(true);
        let (approval, command, child) = reserved_child_write(&fixture);
        if revoke_first {
            fixture.ledger().revoke_participant(TASK, child).unwrap();
        }
        let before = fixture.digest();
        let entered = fixture.ledger().enter_write(
            &approval,
            command.clone(),
            &fixture.pins,
            &fixture.time,
            None,
        );
        if revoke_first {
            assert_eq!(entered.err(), Some(ReleaseStateError::Inactive));
            assert_eq!(fixture.digest(), before);
        } else {
            // Losing a granted in-memory permit models a crash before socket entry.
            drop(entered.unwrap());
            let reopened = fixture.ledger().load(TASK).unwrap().unwrap();
            let stored = serde_json::to_value(&reopened).unwrap();
            assert_eq!(
                stored["writes"]["entry-write"]["entry"],
                json!({"stage": "granted", "at": NOW})
            );
            assert_eq!(
                fixture
                    .ledger()
                    .enter_write(
                        &approval,
                        command.clone(),
                        &fixture.pins,
                        &fixture.time,
                        None,
                    )
                    .err(),
                Some(ReleaseStateError::Replay)
            );
            fixture.ledger().revoke_participant(TASK, child).unwrap();
            assert_eq!(
                fixture
                    .ledger()
                    .enter_write(&approval, command, &fixture.pins, &fixture.time, None,)
                    .err(),
                Some(ReleaseStateError::Inactive)
            );
        }
        assert_eq!(
            fixture.ledger().load(TASK).unwrap().unwrap().write_count(),
            1
        );
    }
}

#[test]
fn write_entry_refuses_writer_request_and_preflight_substitution() {
    let fixture = Fixture::with_writes(true);
    let (approval, command, _) = reserved_child_write(&fixture);
    let before = fixture.digest();
    let (_, root_command) = fixture.write("entry-write");
    assert_eq!(
        fixture
            .ledger()
            .enter_write(&approval, root_command, &fixture.pins, &fixture.time, None,)
            .err(),
        Some(ReleaseStateError::Binding)
    );
    for field in [
        "request_commitment",
        "action_commitment",
        "recipe_digest",
        "task_commitment",
    ] {
        let mut substituted = serde_json::to_value(approval.intent()).unwrap();
        substituted[field] = json!("ef".repeat(32));
        let changed = crate::task_write::ApprovedTaskWrite::from_test_intent(
            serde_json::from_value(substituted).unwrap(),
        );
        assert_eq!(
            fixture
                .ledger()
                .enter_write(
                    &changed,
                    command.clone(),
                    &fixture.pins,
                    &fixture.time,
                    None,
                )
                .err(),
            Some(ReleaseStateError::Binding)
        );
        assert_eq!(fixture.digest(), before);
    }
    assert_eq!(
        fixture
            .ledger()
            .enter_write(&approval, command, &fixture.pins, &fixture.time, Some(NOW),)
            .err(),
        Some(ReleaseStateError::Binding)
    );
    assert_eq!(fixture.digest(), before);
}

#[test]
fn concurrent_write_entry_mints_only_one_exact_request_permit() {
    let fixture = Fixture::with_writes(true);
    let (approval, command, _) = reserved_child_write(&fixture);
    let barrier = std::sync::Barrier::new(2);
    let enter = || {
        barrier.wait();
        fixture
            .ledger()
            .enter_write(
                &approval,
                command.clone(),
                &fixture.pins,
                &fixture.time,
                None,
            )
            .map(|permit| *permit.into_request().action_commitment())
    };
    let results = std::thread::scope(|scope| {
        let first = scope.spawn(enter);
        let second = scope.spawn(enter);
        [first.join().unwrap(), second.join().unwrap()]
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(ReleaseStateError::Replay))
            .count(),
        1
    );
    assert_eq!(
        results.into_iter().find_map(Result::ok).unwrap(),
        *command.request.action_commitment()
    );
    assert_eq!(
        fixture.ledger().load(TASK).unwrap().unwrap().write_count(),
        1
    );
}

#[test]
fn write_entry_samples_expiry_after_acquiring_the_revocation_lock() {
    let fixture = Fixture::with_writes(true);
    let (approval, command, _) = reserved_child_write(&fixture);
    let before = fixture.digest();
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(fixture.path.join(".release.lock"))
        .unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive).unwrap();
    std::thread::scope(|scope| {
        let (started, ready) = std::sync::mpsc::channel();
        let fixture = &fixture;
        let worker = scope.spawn(move || {
            started.send(()).unwrap();
            fixture
                .ledger()
                .enter_write(&approval, command, &fixture.pins, &fixture.time, None)
                .map(|_| ())
        });
        ready.recv().unwrap();
        fixture.clock.set(NOW + 600);
        drop(lock);
        assert_eq!(worker.join().unwrap(), Err(ReleaseStateError::Inactive));
    });
    assert_eq!(fixture.digest(), before);
}

#[test]
fn concurrent_revocation_and_write_entry_have_one_durable_order() {
    let fixture = Fixture::with_writes(true);
    let (approval, command, child) = reserved_child_write(&fixture);
    let barrier = std::sync::Barrier::new(2);
    let result = std::thread::scope(|scope| {
        let entry = scope.spawn(|| {
            barrier.wait();
            fixture
                .ledger()
                .enter_write(
                    &approval,
                    command.clone(),
                    &fixture.pins,
                    &fixture.time,
                    None,
                )
                .map(|_| ())
        });
        let revoke = scope.spawn(|| {
            barrier.wait();
            fixture.ledger().revoke_participant(TASK, child).unwrap();
        });
        revoke.join().unwrap();
        entry.join().unwrap()
    });
    let state = fixture.ledger().load(TASK).unwrap().unwrap();
    assert!(!state.write_participant_active(&approval.intent().writer, NOW));
    assert_eq!(state.write_count(), 1);
    let state = serde_json::to_value(state).unwrap();
    match result {
        Ok(()) => assert_eq!(state["writes"]["entry-write"]["entry"]["stage"], "granted"),
        Err(ReleaseStateError::Inactive) => {
            assert_eq!(state["writes"]["entry-write"]["entry"]["stage"], "reserved");
        }
        other => panic!("entry must have one lock order relative to revocation: {other:?}"),
    }
    assert_eq!(
        fixture
            .ledger()
            .enter_write(&approval, command, &fixture.pins, &fixture.time, None,)
            .err(),
        Some(ReleaseStateError::Inactive)
    );
}

#[test]
fn stored_write_entry_refuses_missing_unknown_and_out_of_window_grants() {
    let fixture = Fixture::with_writes(true);
    let _reserved = reserved_child_write(&fixture);
    let path = std::fs::read_dir(&fixture.path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .unwrap();
    let original = std::fs::read(&path).unwrap();
    for entry in [
        serde_json::Value::Null,
        json!({"stage": "unknown"}),
        json!({"stage": "reserved", "at": NOW}),
        json!({"stage": "granted", "at": NOW - 11}),
        json!({"stage": "granted", "at": NOW + 600}),
    ] {
        let mut stored: serde_json::Value = serde_json::from_slice(&original).unwrap();
        if entry.is_null() {
            stored["writes"]["entry-write"]
                .as_object_mut()
                .unwrap()
                .remove("entry");
        } else {
            stored["writes"]["entry-write"]["entry"] = entry;
        }
        std::fs::write(&path, serde_json_canonicalizer::to_vec(&stored).unwrap()).unwrap();
        assert_eq!(
            fixture.ledger().load(TASK).err(),
            Some(ReleaseStateError::Corrupt)
        );
    }
    let mut obsolete: serde_json::Value = serde_json::from_slice(&original).unwrap();
    obsolete["schema"] = json!("auths.gateway-agent-task-state/12");
    std::fs::write(&path, serde_json_canonicalizer::to_vec(&obsolete).unwrap()).unwrap();
    assert_eq!(
        fixture.ledger().load(TASK).err(),
        Some(ReleaseStateError::Corrupt)
    );
    std::fs::write(&path, original).unwrap();
    assert_eq!(
        fixture.ledger().load(TASK).unwrap().unwrap().write_count(),
        1
    );
}
