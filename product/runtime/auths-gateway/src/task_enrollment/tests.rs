use super::*;
use crate::harness::{self, Signer};
use crate::participant_enrollment::tests::{chained, grant, invocation};
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

const NOW: u64 = 1_790_000_000;
const TASK: &str = "machine-engagement";
const CONTROL_TOOLS: &[&str] = &[
    ACTIVATE_ROOT_TOOL,
    ENROLL_PARTICIPANT_TOOL,
    ACCEPT_PARTICIPANT_TOOL,
];

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    company: Signer,
    machine: Signer,
    agent: Signer,
    child: Signer,
    context: TrustedContext,
    pins: TaskActivationPins,
    task: ApprovedAgentTask,
    reads: Vec<CompiledReleaseRecipe>,
    authority: TaskRootAuthority,
    root: ParentEnrollmentPins,
    controls: Vec<SignedGrant>,
    resources: Vec<SignedGrant>,
    clock: Arc<FixedClock>,
    time: QualificationGate,
}

fn chain_grants(
    company: &Signer,
    machine: &Signer,
    agent: &Signer,
    child: &Signer,
    service: &str,
    tools: &[&str],
) -> Vec<SignedGrant> {
    let first = grant(company, machine, service, tools, None, 2);
    let second = grant(
        machine,
        agent,
        service,
        tools,
        Some(grant_id(first.statement()).unwrap()),
        1,
    );
    let third = grant(
        agent,
        child,
        service,
        tools,
        Some(grant_id(second.statement()).unwrap()),
        0,
    );
    vec![first, second, third]
}

impl Fixture {
    #[allow(
        clippy::too_many_lines,
        reason = "one native fixture retains the full company-machine-agent grant paths and signed installation"
    )]
    fn new() -> Self {
        let company = Signer::new(0x11);
        let machine = Signer::new(0x21);
        let agent = Signer::new(0x22);
        let child = Signer::new(0x44);
        let human = Signer::new(0x55);
        let observer = GatewayObserver::from_test_seed(0x33);
        let context = harness::context_for_profiles(
            &[&company],
            observer.principal(),
            None,
            NOW,
            3,
            CompositionRequirement::new(None, 1, 1, 1).unwrap(),
            &[auths_raw_key::RAW_KEY_V1],
            &[
                (TASK_SERVICE, APPROVAL_TOOL),
                (PARTICIPANT_SERVICE, ACTIVATE_ROOT_TOOL),
                (PARTICIPANT_SERVICE, ENROLL_PARTICIPANT_TOOL),
                (PARTICIPANT_SERVICE, ACCEPT_PARTICIPANT_TOOL),
                (harness::SERVICE, harness::TOOL),
            ],
        )
        .unwrap();
        let reads = vec![crate::release_verify::tests::recipe()];
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
            "read_scopes": read_scopes, "write_scopes": [], "delivery_channel": "agent-a", "delegation": delegation,
            "not_before": NOW - 10, "expires_at": NOW + 600, "max_provider_calls": 4,
            "max_releases": 4, "max_release_bytes": 128, "max_writes": 0,
            "write_approval_mode": "exact", "operator_policy_digest": "b".repeat(64), "purpose": "M delegates to A and B"
        })).unwrap();
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
        let resources = chain_grants(
            &company,
            &machine,
            &agent,
            &child,
            harness::SERVICE,
            &[harness::TOOL],
        );
        let recipes = TaskEnrollmentRecipes {
            reads: &reads,
            writes: &[],
        };
        let scope = scopes(&card, &recipes).unwrap().remove(0);
        let authority = TaskRootAuthority {
            control_grant: *grant_id(controls[1].statement()).unwrap().as_bytes(),
            resource_grants: BTreeMap::from([(
                scope.scope_id,
                *grant_id(resources[1].statement()).unwrap().as_bytes(),
            )]),
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
            context,
            pins,
            task,
            reads,
            authority,
            root,
            controls,
            resources,
            clock,
            time,
        }
    }

    fn ledger(&self) -> FileReleaseTaskLedger {
        FileReleaseTaskLedger::open(&self.path).unwrap()
    }

    fn transaction(&self) -> EnrollmentTransaction<'_> {
        EnrollmentTransaction {
            context: &self.context,
            pins: &self.pins,
            time: &self.time,
        }
    }

    fn bootstrap(&self) -> Result<[u8; 32], ReleaseStateError> {
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
        let resource = chained(
            &signers,
            &[&self.resources[0], &self.resources[1]],
            harness::SERVICE,
            harness::TOOL,
            json!({"record_id": harness::RECORD}).as_object().unwrap(),
        );
        let witnesses = [EnrollmentResourceWitness {
            scope_id: &self.root.scopes[0].scope_id,
            invocation: invocation(&resource),
        }];
        self.ledger().bootstrap_participants(
            TASK,
            &self.transaction(),
            &TaskEnrollmentRecipes {
                reads: &self.reads,
                writes: &[],
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
            scopes: vec![ParticipantScopeGrant {
                scope_id: self.root.scopes[0].scope_id.clone(),
                grant_id: *grant_id(self.resources[2].statement()).unwrap().as_bytes(),
            }],
            not_before: NOW,
            expires_at: NOW + 500,
            remaining_depth: 0,
            ceilings: self.root.ceilings,
        }
    }

    fn enroll(&self, accepted: &ParticipantEnrollment) -> Result<[u8; 32], ReleaseStateError> {
        let enrollment = self.enrollment();
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
        let resource = chained(
            &signers,
            &self.resources.iter().collect::<Vec<_>>(),
            harness::SERVICE,
            harness::TOOL,
            json!({"record_id": harness::RECORD}).as_object().unwrap(),
        );
        let witnesses = [EnrollmentResourceWitness {
            scope_id: &self.root.scopes[0].scope_id,
            invocation: invocation(&resource),
        }];
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

    fn digest(&self) -> [u8; 32] {
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
        &[&fixture.resources[0], &fixture.resources[1]],
        harness::SERVICE,
        harness::TOOL,
        &arguments,
    );
    let verified = crate::release_verify::verify_release_request(
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
