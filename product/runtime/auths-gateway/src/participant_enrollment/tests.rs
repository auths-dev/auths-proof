use super::*;
use crate::GatewayObserver;
use crate::harness::{self, Signer};
use crate::observed_tests::{Submission, submission_for_audience};
use auths_codec::{grant_id, grant_signing_preimage};
use auths_model::{
    ActionConstraint, AssurancePolicyId, AudienceSet, BundleHeader, CompositionRequirement,
    ControlBinding, CriticalExtensions, GrantStatement, PermissionSet, ProofBundle,
    SignatureEnvelope, StatementRef, StatusPolicy,
};
use auths_profile_mcp::McpToolCall;
use serde_json::{Map, json};

const NOW: u64 = 1_790_000_000;
const RESOURCE_SERVICE: &str = "engagement-records";
const RESOURCE_TOOL: &str = "read_record";
const CONTROL_TOOLS: &[&str] = &[
    ACTIVATE_ROOT_TOOL,
    ENROLL_PARTICIPANT_TOOL,
    ACCEPT_PARTICIPANT_TOOL,
];

pub(crate) fn grant(
    issuer: &Signer,
    subject: &Signer,
    service: &str,
    tools: &[&str],
    parent: Option<GrantId>,
    depth: u16,
) -> SignedGrant {
    grant_for_audiences(
        issuer,
        subject,
        service,
        tools,
        parent,
        depth,
        vec![Audience::parse(&format!("mcp://{service}")).unwrap()],
    )
}

pub(crate) fn grant_for_audiences(
    issuer: &Signer,
    subject: &Signer,
    service: &str,
    tools: &[&str],
    parent: Option<GrantId>,
    depth: u16,
    audiences: Vec<Audience>,
) -> SignedGrant {
    grant_for_audiences_at(
        issuer, subject, service, tools, parent, depth, audiences, NOW,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "native test authoring states the exact grant and time"
)]
pub(crate) fn grant_for_audiences_at(
    issuer: &Signer,
    subject: &Signer,
    service: &str,
    tools: &[&str],
    parent: Option<GrantId>,
    depth: u16,
    audiences: Vec<Audience>,
    now: u64,
) -> SignedGrant {
    let call = McpToolCall::new(service, tools[0], Map::new()).unwrap();
    let permissions = tools
        .iter()
        .map(|tool| {
            McpToolCall::new(service, *tool, Map::new())
                .unwrap()
                .permission()
                .unwrap()
        })
        .collect();
    let statement = GrantStatement::new(
        issuer.principal.clone(),
        subject.principal.clone(),
        call.profile_ref().unwrap(),
        PermissionSet::new(permissions).unwrap(),
        // submission_for signs an action with this exact test window. Product
        // enrollment pins are deliberately narrower than native authority.
        harness::window(now - 3_600, now + 3_600).unwrap(),
        AudienceSet::new(audiences).unwrap(),
        ActionConstraint::AnyBody,
        None,
        depth,
        parent,
        StatusPolicy::ExpiryOnly,
        AssurancePolicyId::parse(harness::ASSURANCE).unwrap(),
        CriticalExtensions::empty(),
    );
    let descriptor = issuer.descriptor();
    let signature = issuer.sign(&grant_signing_preimage(&statement, &descriptor).unwrap());
    SignedGrant::new(statement, SignatureEnvelope::new(descriptor, signature))
}

pub(crate) fn chained(
    signers: &[&Signer],
    grants: &[&SignedGrant],
    service: &str,
    tool: &str,
    arguments: &Map<String, Value>,
) -> Submission {
    chained_at(signers, grants, service, tool, arguments, NOW)
}

pub(crate) fn chained_at(
    signers: &[&Signer],
    grants: &[&SignedGrant],
    service: &str,
    tool: &str,
    arguments: &Map<String, Value>,
    now: u64,
) -> Submission {
    let mut signed = submission_for_audience(
        signers[signers.len() - 2],
        signers[signers.len() - 1],
        grants.last().unwrap(),
        arguments,
        &[],
        service,
        tool,
        now,
        grants.last().unwrap().statement().audiences().as_slice()[0].clone(),
    );
    let terminal = auths_codec::decode_bundle(&signed.proof, &VerifierLimits::default()).unwrap();
    let mut bindings: Vec<_> = grants
        .iter()
        .zip(signers)
        .map(|(grant, issuer)| {
            ControlBinding::new(
                StatementRef::Grant(grant_id(grant.statement()).unwrap()),
                vec![issuer.evidence().id()],
            )
            .unwrap()
        })
        .collect();
    bindings.extend(
        terminal
            .bindings()
            .iter()
            .filter(|binding| matches!(binding.statement(), StatementRef::Action(_)))
            .cloned(),
    );
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        grants.iter().map(|grant| (*grant).clone()).collect(),
        terminal.actions().to_vec(),
        terminal.plan().clone(),
        signers.iter().map(|signer| signer.evidence()).collect(),
        bindings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        terminal.canonical_body().map(<[u8]>::to_vec),
    )
    .unwrap();
    signed.proof = auths_codec::encode_bundle(&bundle).unwrap();
    signed
}

pub(crate) fn invocation(signed: &Submission) -> EnrollmentInvocation<'_> {
    EnrollmentInvocation {
        proof: &signed.proof,
        action: &signed.action,
    }
}

struct Fixture {
    root: Signer,
    parent: Signer,
    child: Signer,
    parent_control: SignedGrant,
    child_control: SignedGrant,
    parent_resource: SignedGrant,
    child_resource: SignedGrant,
    context: TrustedContext,
    pins: ParentEnrollmentPins,
    enrollment: ParticipantEnrollment,
}

impl Fixture {
    fn new() -> Self {
        Self::with_child(0x44)
    }

    fn with_child(child_seed: u8) -> Self {
        Self::with_depth(child_seed, 1)
    }

    fn with_depth(child_seed: u8, parent_depth: u16) -> Self {
        let root = Signer::new(0x11);
        let parent = Signer::new(0x22);
        let child = Signer::new(child_seed);
        let observer = GatewayObserver::from_test_seed(0x33);
        let context = harness::context_for_profiles_and_audiences(
            &[&root],
            observer.principal(),
            None,
            NOW,
            parent_depth + 1,
            CompositionRequirement::new(None, 1, 1, 1).unwrap(),
            &[auths_raw_key::RAW_KEY_V1],
            &[
                (PARTICIPANT_SERVICE, ACTIVATE_ROOT_TOOL),
                (PARTICIPANT_SERVICE, ENROLL_PARTICIPANT_TOOL),
                (PARTICIPANT_SERVICE, ACCEPT_PARTICIPANT_TOOL),
                (RESOURCE_SERVICE, RESOURCE_TOOL),
            ],
            &[resource_audience(&[1; 32], 2, &"ab".repeat(32)).unwrap()],
        )
        .unwrap();
        let parent_control = grant(
            &root,
            &parent,
            PARTICIPANT_SERVICE,
            CONTROL_TOOLS,
            None,
            parent_depth,
        );
        let child_control = grant(
            &parent,
            &child,
            PARTICIPANT_SERVICE,
            CONTROL_TOOLS,
            Some(grant_id(parent_control.statement()).unwrap()),
            parent_depth - 1,
        );
        let parent_resource = grant_for_audiences(
            &root,
            &parent,
            RESOURCE_SERVICE,
            &[RESOURCE_TOOL],
            None,
            parent_depth,
            vec![resource_audience(&[1; 32], 2, &"ab".repeat(32)).unwrap()],
        );
        let child_resource = grant_for_audiences(
            &parent,
            &child,
            RESOURCE_SERVICE,
            &[RESOURCE_TOOL],
            Some(grant_id(parent_resource.statement()).unwrap()),
            parent_depth - 1,
            vec![resource_audience(&[1; 32], 2, &"ab".repeat(32)).unwrap()],
        );
        let mut pins = parent_pins(&parent, &child, &parent_control, &parent_resource);
        pins.remaining_depth = parent_depth;
        let mut enrollment = child_descriptor(&child, &child_control, &child_resource, &pins);
        enrollment.remaining_depth = parent_depth - 1;
        Self {
            root,
            parent,
            child,
            parent_control,
            child_control,
            parent_resource,
            child_resource,
            context,
            pins,
            enrollment,
        }
    }

    fn parent_proof(&self, enrollment: &ParticipantEnrollment) -> Submission {
        chained(
            &[&self.root, &self.parent],
            &[&self.parent_control],
            PARTICIPANT_SERVICE,
            ENROLL_PARTICIPANT_TOOL,
            json!({"enrollment": enrollment}).as_object().unwrap(),
        )
    }

    fn child_proof(&self, enrollment: &ParticipantEnrollment) -> Submission {
        chained(
            &[&self.root, &self.parent, &self.child],
            &[&self.parent_control, &self.child_control],
            PARTICIPANT_SERVICE,
            ACCEPT_PARTICIPANT_TOOL,
            json!({"enrollment_commitment": enrollment.commitment().unwrap()})
                .as_object()
                .unwrap(),
        )
    }

    fn resource_proof(&self, resource: &str) -> Submission {
        chained(
            &[&self.root, &self.parent, &self.child],
            &[&self.parent_resource, &self.child_resource],
            RESOURCE_SERVICE,
            RESOURCE_TOOL,
            json!({"record_id": resource}).as_object().unwrap(),
        )
    }

    fn verify(
        &self,
        enrollment: &ParticipantEnrollment,
        accepted: &ParticipantEnrollment,
        resource: &Submission,
    ) -> Result<VerifiedParticipantEnrollment, ParticipantEnrollmentError> {
        let parent = self.parent_proof(enrollment);
        let child = self.child_proof(accepted);
        let resources = [EnrollmentResourceWitness {
            scope_id: "project-a-read",
            invocation: invocation(resource),
        }];
        verify_participant_enrollment(
            &self.context,
            &self.pins,
            NOW,
            &ParticipantEnrollmentProofs {
                parent: invocation(&parent),
                child: invocation(&child),
                resources: &resources,
            },
        )
    }
}

fn parent_pins(
    parent: &Signer,
    child: &Signer,
    parent_control: &SignedGrant,
    parent_resource: &SignedGrant,
) -> ParentEnrollmentPins {
    let ceilings = ParticipantCeilings {
        provider_reads: 2,
        disclosures: 1,
        disclosure_bytes: 512,
        writes: 1,
    };
    ParentEnrollmentPins {
        active: true,
        engagement_commitment: [1; 32],
        partition_generation: 2,
        enrollment_commitment: [3; 32],
        principal: parent.principal.clone(),
        instance_generation: 4,
        control_grant: grant_id(parent_control.statement()).unwrap(),
        not_before: NOW - 100,
        expires_at: NOW + 900,
        remaining_depth: 1,
        ceilings,
        permitted_channels: BTreeMap::from([(
            "agent-b-channel".to_owned(),
            EnrollmentChannelPins {
                principal: child.principal.clone(),
                instance_generation: 1,
            },
        )]),
        scopes: vec![EnrollmentScopePins {
            scope_id: "project-a-read".to_owned(),
            recipe_digest: "ab".repeat(32),
            parent_grant: grant_id(parent_resource.statement()).unwrap(),
            service: RESOURCE_SERVICE.to_owned(),
            tool: RESOURCE_TOOL.to_owned(),
            resource_argument: "record_id".to_owned(),
            resource: EnrollmentResourceBinding::Exact {
                handle: "record-a".into(),
            },
        }],
    }
}

fn child_descriptor(
    child: &Signer,
    child_control: &SignedGrant,
    child_resource: &SignedGrant,
    pins: &ParentEnrollmentPins,
) -> ParticipantEnrollment {
    ParticipantEnrollment {
        schema: PARTICIPANT_ENROLLMENT_SCHEMA.to_owned(),
        engagement_commitment: pins.engagement_commitment,
        partition_generation: pins.partition_generation,
        parent_enrollment: pins.enrollment_commitment,
        parent_instance_generation: pins.instance_generation,
        enrollment_id: "agent-b-1".to_owned(),
        child_principal: child.principal.as_str().to_owned(),
        child_instance_generation: 1,
        delivery_channel: "agent-b-channel".to_owned(),
        control_grant: *grant_id(child_control.statement()).unwrap().as_bytes(),
        scopes: vec![ParticipantScopeGrant {
            scope_id: "project-a-read".to_owned(),
            grant_id: *grant_id(child_resource.statement()).unwrap().as_bytes(),
        }],
        not_before: NOW - 10,
        expires_at: NOW + 600,
        remaining_depth: 0,
        ceilings: pins.ceilings,
    }
}

#[test]
fn native_enrollment_requires_parent_child_and_separate_resource_grants() {
    let fixture = Fixture::new();
    let resource = fixture.resource_proof("record-a");
    let verified = fixture
        .verify(&fixture.enrollment, &fixture.enrollment, &resource)
        .unwrap();
    assert_eq!(verified.enrollment(), &fixture.enrollment);
    assert_eq!(
        verified.commitment(),
        &fixture.enrollment.commitment().unwrap()
    );
    assert_ne!(
        fixture.pins.control_grant,
        fixture.pins.scopes[0].parent_grant
    );
    assert_ne!(
        fixture.enrollment.control_grant,
        fixture.enrollment.scopes[0].grant_id
    );
}

#[test]
fn native_enrollment_child_acceptance_binds_generation_ceiling_and_id() {
    let mut fixture = Fixture::new();
    let resource = fixture.resource_proof("record-a");
    let mut changed = fixture.enrollment.clone();
    changed.child_instance_generation += 1;
    // This is an operator-permitted new instance, so the independent child
    // acceptance check, not the channel owner check, must reject the old proof.
    fixture
        .pins
        .permitted_channels
        .get_mut("agent-b-channel")
        .unwrap()
        .instance_generation = changed.child_instance_generation;
    assert_eq!(
        fixture
            .verify(&changed, &fixture.enrollment, &resource)
            .unwrap_err(),
        ParticipantEnrollmentError::Acceptance
    );
    fixture
        .pins
        .permitted_channels
        .get_mut("agent-b-channel")
        .unwrap()
        .instance_generation = fixture.enrollment.child_instance_generation;
    changed = fixture.enrollment.clone();
    changed.ceilings.disclosure_bytes -= 1;
    assert_eq!(
        fixture
            .verify(&changed, &fixture.enrollment, &resource)
            .unwrap_err(),
        ParticipantEnrollmentError::Acceptance
    );
    changed = fixture.enrollment.clone();
    changed.enrollment_id = "different-enrollment".to_owned();
    assert_eq!(
        fixture
            .verify(&changed, &fixture.enrollment, &resource)
            .unwrap_err(),
        ParticipantEnrollmentError::Acceptance
    );
}

#[test]
fn native_enrollment_refuses_scope_substitution_and_missing_resource_evidence() {
    let fixture = Fixture::new();
    let wrong = fixture.resource_proof("record-b");
    assert_eq!(
        fixture
            .verify(&fixture.enrollment, &fixture.enrollment, &wrong)
            .unwrap_err(),
        ParticipantEnrollmentError::ResourceAuthority
    );
    let parent = fixture.parent_proof(&fixture.enrollment);
    let child = fixture.child_proof(&fixture.enrollment);
    assert_eq!(
        verify_participant_enrollment(
            &fixture.context,
            &fixture.pins,
            NOW,
            &ParticipantEnrollmentProofs {
                parent: invocation(&parent),
                child: invocation(&child),
                resources: &[],
            }
        )
        .unwrap_err(),
        ParticipantEnrollmentError::ResourceAuthority
    );
}

#[test]
fn native_enrollment_refuses_other_valid_parent_grants_and_revoked_snapshots() {
    let mut fixture = Fixture::new();
    let resource = fixture.resource_proof("record-a");
    fixture.pins.control_grant = fixture.pins.scopes[0].parent_grant;
    assert_eq!(
        fixture
            .verify(&fixture.enrollment, &fixture.enrollment, &resource)
            .unwrap_err(),
        ParticipantEnrollmentError::ControlAuthority
    );
    fixture.pins.control_grant = grant_id(fixture.parent_control.statement()).unwrap();
    fixture.pins.active = false;
    assert_eq!(
        fixture
            .verify(&fixture.enrollment, &fixture.enrollment, &resource)
            .unwrap_err(),
        ParticipantEnrollmentError::ParentBinding
    );
}

#[test]
fn native_enrollment_cannot_widen_ceiling_channel_generation_or_depth() {
    let fixture = Fixture::new();
    let resource = fixture.resource_proof("record-a");
    let mut mutations = vec![fixture.enrollment.clone(); 6];
    mutations[0].ceilings.disclosure_bytes += 1;
    mutations[1].delivery_channel = "another-agent-channel".to_owned();
    mutations[2].partition_generation += 1;
    mutations[3].parent_instance_generation += 1;
    mutations[4].remaining_depth = 1;
    mutations[5].expires_at = fixture.pins.expires_at + 1;
    for changed in mutations {
        assert_eq!(
            fixture.verify(&changed, &changed, &resource).unwrap_err(),
            ParticipantEnrollmentError::ParentBinding
        );
    }
}

#[test]
fn native_enrollment_rejects_resource_authority_that_skips_the_enrolled_parent() {
    let mut fixture = Fixture::new();
    let direct = grant_for_audiences(
        &fixture.root,
        &fixture.child,
        RESOURCE_SERVICE,
        &[RESOURCE_TOOL],
        None,
        0,
        vec![resource_audience(&[1; 32], 2, &"ab".repeat(32)).unwrap()],
    );
    fixture.enrollment.scopes[0].grant_id = *grant_id(direct.statement()).unwrap().as_bytes();
    let resource = chained(
        &[&fixture.root, &fixture.child],
        &[&direct],
        RESOURCE_SERVICE,
        RESOURCE_TOOL,
        json!({"record_id": "record-a"}).as_object().unwrap(),
    );
    assert_eq!(
        fixture
            .verify(&fixture.enrollment, &fixture.enrollment, &resource)
            .unwrap_err(),
        ParticipantEnrollmentError::ResourceAuthority
    );
}

#[test]
fn native_enrollment_size_limit_precedes_native_decoding() {
    let fixture = Fixture::new();
    let oversized = vec![0; MAX_PROOF_BYTES + 1];
    let invalid = EnrollmentInvocation {
        proof: &oversized,
        action: &[1],
    };
    assert_eq!(
        verify_participant_enrollment(
            &fixture.context,
            &fixture.pins,
            NOW,
            &ParticipantEnrollmentProofs {
                parent: invalid,
                child: invalid,
                resources: &[],
            }
        )
        .unwrap_err(),
        ParticipantEnrollmentError::Invalid
    );
}

#[test]
fn native_enrollment_child_acceptance_requires_control_of_the_grant_holder() {
    let fixture = Fixture::new();
    let attacker = Signer::new(0x55);
    let parent = fixture.parent_proof(&fixture.enrollment);
    let forged = chained(
        &[&fixture.root, &fixture.parent, &attacker],
        &[&fixture.parent_control, &fixture.child_control],
        PARTICIPANT_SERVICE,
        ACCEPT_PARTICIPANT_TOOL,
        json!({"enrollment_commitment": fixture.enrollment.commitment().unwrap()})
            .as_object()
            .unwrap(),
    );
    let resource = fixture.resource_proof("record-a");
    let resources = [EnrollmentResourceWitness {
        scope_id: "project-a-read",
        invocation: invocation(&resource),
    }];
    assert!(matches!(
        verify_participant_enrollment(
            &fixture.context,
            &fixture.pins,
            NOW,
            &ParticipantEnrollmentProofs {
                parent: invocation(&parent),
                child: invocation(&forged),
                resources: &resources,
            }
        ),
        Err(ParticipantEnrollmentError::Native(_))
    ));
}

#[test]
fn native_enrollment_cannot_create_delegation_depth_from_the_product_ceiling() {
    let mut fixture = Fixture::new();
    fixture.parent_control = grant(
        &fixture.root,
        &fixture.parent,
        PARTICIPANT_SERVICE,
        CONTROL_TOOLS,
        None,
        0,
    );
    fixture.pins.control_grant = grant_id(fixture.parent_control.statement()).unwrap();
    fixture.child_control = grant(
        &fixture.parent,
        &fixture.child,
        PARTICIPANT_SERVICE,
        CONTROL_TOOLS,
        Some(fixture.pins.control_grant),
        0,
    );
    fixture.enrollment.control_grant = *grant_id(fixture.child_control.statement())
        .unwrap()
        .as_bytes();
    let resource = fixture.resource_proof("record-a");
    assert!(matches!(
        fixture.verify(&fixture.enrollment, &fixture.enrollment, &resource),
        Err(ParticipantEnrollmentError::Native(_))
    ));
}

#[test]
fn enrollment_commitment_refuses_integer_rounding_and_oversized_names() {
    let fixture = Fixture::new();
    let mut enrollment = fixture.enrollment;
    enrollment.child_instance_generation = MAX_JSON_INTEGER + 1;
    assert_eq!(
        enrollment.commitment(),
        Err(ParticipantEnrollmentError::Invalid)
    );
    enrollment.child_instance_generation = 1;
    enrollment.enrollment_id = "x".repeat(65);
    assert_eq!(
        enrollment.commitment(),
        Err(ParticipantEnrollmentError::Invalid)
    );
}

impl Fixture {
    fn enroll_tree(&self, tree: &mut EnrollmentTree) -> Result<[u8; 32], EnrollmentTreeError> {
        let parent = self.parent_proof(&self.enrollment);
        let child = self.child_proof(&self.enrollment);
        let resource = self.resource_proof("record-a");
        let resources = [EnrollmentResourceWitness {
            scope_id: "project-a-read",
            invocation: invocation(&resource),
        }];
        tree.enroll(
            &self.context,
            self.pins.enrollment_commitment,
            NOW,
            &ParticipantEnrollmentProofs {
                parent: invocation(&parent),
                child: invocation(&child),
                resources: &resources,
            },
        )
    }
}

#[test]
fn enrollment_tree_derives_exact_native_resource_ancestry() {
    let fixture = Fixture::new();
    let mut tree = EnrollmentTree::new(fixture.pins.clone()).unwrap();
    let commitment = fixture.enroll_tree(&mut tree).unwrap();
    let pins = tree.parent_pins(commitment, NOW).unwrap();
    assert_eq!(pins.principal, fixture.child.principal);
    assert_eq!(
        pins.instance_generation,
        fixture.enrollment.child_instance_generation
    );
    assert_eq!(
        pins.control_grant.as_bytes(),
        &fixture.enrollment.control_grant
    );
    assert_eq!(pins.ceilings, fixture.enrollment.ceilings);
    assert_eq!(pins.remaining_depth, 0);
    assert_eq!(
        pins.scopes[0].resource,
        EnrollmentResourceBinding::Exact {
            handle: "record-a".into()
        }
    );
    assert_eq!(
        tree.resource_grant_path(commitment, "project-a-read", NOW)
            .unwrap(),
        vec![
            grant_id(fixture.parent_resource.statement()).unwrap(),
            grant_id(fixture.child_resource.statement()).unwrap()
        ]
    );
    assert_eq!(
        tree.resource_grant_path(commitment, "other-scope", NOW),
        Err(EnrollmentTreeError::Binding)
    );
    assert_eq!(tree.participant_count(), 2);
}

#[test]
fn enrollment_tree_rechecks_revocation_after_a_valid_native_snapshot() {
    let fixture = Fixture::new();
    let resource = fixture.resource_proof("record-a");
    assert!(
        fixture
            .verify(&fixture.enrollment, &fixture.enrollment, &resource)
            .is_ok()
    );
    let mut tree = EnrollmentTree::new(fixture.pins.clone()).unwrap();
    tree.revoke(fixture.pins.enrollment_commitment).unwrap();
    let before = tree.clone();
    assert_eq!(
        fixture.enroll_tree(&mut tree),
        Err(EnrollmentTreeError::Inactive)
    );
    assert_eq!(tree, before);
    assert_eq!(tree.participant_count(), 1);
}

#[test]
fn enrollment_tree_revocation_retains_ids_principals_and_descendant_denials() {
    let mut fixture = Fixture::new();
    let mut tree = EnrollmentTree::new(fixture.pins.clone()).unwrap();
    let commitment = fixture.enroll_tree(&mut tree).unwrap();
    tree.revoke(commitment).unwrap();
    tree.revoke(commitment).unwrap();
    let before = tree.clone();
    assert_eq!(
        fixture.enroll_tree(&mut tree),
        Err(EnrollmentTreeError::Replay)
    );
    fixture.enrollment.enrollment_id = "fresh-id-same-revoked-principal".into();
    assert_eq!(
        fixture.enroll_tree(&mut tree),
        Err(EnrollmentTreeError::Replay)
    );
    assert_eq!(tree, before);
    assert!(matches!(
        tree.parent_pins(commitment, NOW),
        Err(EnrollmentTreeError::Inactive)
    ));
    assert_eq!(
        tree.resource_grant_path(commitment, "project-a-read", NOW),
        Err(EnrollmentTreeError::Inactive)
    );
    assert_eq!(tree.participant_count(), 2);
}

#[test]
fn enrollment_tree_bounds_include_root_and_revoked_records() {
    let fixture = Fixture::new();
    let mut pins = fixture.pins.clone();
    for index in 0..15_u8 {
        pins.permitted_channels.insert(
            format!("channel-{index}"),
            EnrollmentChannelPins {
                principal: Signer::new(0x50 + index).principal,
                instance_generation: 1,
            },
        );
    }
    let mut tree = EnrollmentTree::new(pins).unwrap();
    for index in 0..15_u8 {
        let mut child = Fixture::with_child(0x50 + index);
        child.enrollment.enrollment_id = format!("member-{index}");
        child.enrollment.delivery_channel = format!("channel-{index}");
        let commitment = child.enroll_tree(&mut tree).unwrap();
        tree.revoke(commitment).unwrap();
    }
    assert_eq!(tree.participant_count(), 16);
    let before = tree.clone();
    assert_eq!(
        fixture.enroll_tree(&mut tree),
        Err(EnrollmentTreeError::Full)
    );
    assert_eq!(tree, before);
}

#[test]
fn enrollment_tree_refusals_are_atomic_and_root_pins_are_bounded() {
    let mut fixture = Fixture::new();
    let mut tree = EnrollmentTree::new(fixture.pins.clone()).unwrap();
    let before = tree.clone();
    fixture.enrollment.partition_generation += 1;
    assert!(matches!(
        fixture.enroll_tree(&mut tree),
        Err(EnrollmentTreeError::Verification(_))
    ));
    assert_eq!(tree, before);
    assert_eq!(tree.revoke([0x99; 32]), Err(EnrollmentTreeError::Binding));
    assert_eq!(tree, before);
    for mutation in 0..5 {
        let mut pins = fixture.pins.clone();
        match mutation {
            0 => pins.scopes.clear(),
            1 => pins.permitted_channels.clear(),
            2 => pins.remaining_depth = 16,
            3 => pins.partition_generation = MAX_JSON_INTEGER + 1,
            _ => pins.ceilings.provider_reads = 65,
        }
        assert_eq!(EnrollmentTree::new(pins), Err(EnrollmentTreeError::Binding));
    }
    assert!(matches!(
        tree.parent_pins(fixture.pins.enrollment_commitment, fixture.pins.expires_at),
        Err(EnrollmentTreeError::Inactive)
    ));
}

#[test]
fn enrollment_tree_restores_revocations_and_rejects_changed_installation() {
    let fixture = Fixture::new();
    let mut tree = EnrollmentTree::new(fixture.pins.clone()).unwrap();
    let child = fixture.enroll_tree(&mut tree).unwrap();
    tree.revoke(child).unwrap();
    let bytes = tree.encode().unwrap();
    let restored = EnrollmentTree::decode(&bytes, &fixture.pins).unwrap();
    assert_eq!(tree, restored);
    assert!(matches!(
        restored.parent_pins(child, NOW),
        Err(EnrollmentTreeError::Inactive)
    ));
    for mutation in 0..5 {
        let mut installed = fixture.pins.clone();
        match mutation {
            0 => installed.partition_generation += 1,
            1 => installed.engagement_commitment[0] ^= 1,
            2 => {
                installed.scopes[0].resource = EnrollmentResourceBinding::Exact {
                    handle: "another-record".into(),
                }
            }
            3 => installed.scopes[0].parent_grant = GrantId::new([0x99; 32]),
            _ => {
                installed.permitted_channels.insert(
                    "another-channel".into(),
                    EnrollmentChannelPins {
                        principal: fixture.child.principal.clone(),
                        instance_generation: 1,
                    },
                );
            }
        }
        assert_eq!(
            EnrollmentTree::decode(&bytes, &installed),
            Err(EnrollmentTreeError::Corrupt)
        );
    }
    tree.revoke(fixture.pins.enrollment_commitment).unwrap();
    let revoked_root = tree.encode().unwrap();
    assert_eq!(
        EnrollmentTree::decode(&revoked_root, &fixture.pins).unwrap(),
        tree
    );
    let mut revoked_installation = fixture.pins.clone();
    revoked_installation.active = false;
    assert_eq!(
        EnrollmentTree::decode(&bytes, &revoked_installation),
        Err(EnrollmentTreeError::Corrupt)
    );
}

#[test]
fn enrollment_tree_decoder_refuses_malformed_widened_and_noncanonical_state() {
    let fixture = Fixture::new();
    let mut tree = EnrollmentTree::new(fixture.pins.clone()).unwrap();
    fixture.enroll_tree(&mut tree).unwrap();
    let bytes = tree.encode().unwrap();
    for mutation in 0..8 {
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        let child_id = &fixture.enrollment.enrollment_id;
        match mutation {
            0 => value["schema"] = json!("auths.engagement-enrollment-tree/0"),
            1 => value["children"][child_id]["descriptor"]["ceilings"]["writes"] = json!(2),
            2 => {
                value["children"][child_id]["descriptor"]["parent_enrollment"] = json!(vec![9; 32]);
            }
            3 => value["children"][child_id]["commitment"] = json!(vec![8; 32]),
            4 => value["children"][child_id]["descriptor"]["enrollment_id"] = json!("other-id"),
            5 => value["unknown"] = json!(true),
            6 => {
                value["children"][child_id]["descriptor"]["scopes"][0]["scope_id"] =
                    json!("another-scope");
            }
            _ => {
                value["children"][child_id]["descriptor"]["child_principal"] =
                    json!(fixture.parent.principal.as_str());
            }
        }
        // Recompute the commitment for structural mutations to prove the
        // decoder checks narrowing and topology, not merely content hashing.
        if matches!(mutation, 1 | 2 | 4 | 6 | 7) {
            let descriptor: ParticipantEnrollment =
                serde_json::from_value(value["children"][child_id]["descriptor"].clone()).unwrap();
            value["children"][child_id]["commitment"] = json!(descriptor.commitment().unwrap());
        }
        let changed = serde_json_canonicalizer::to_vec(&value).unwrap();
        assert_eq!(
            EnrollmentTree::decode(&changed, &fixture.pins),
            Err(EnrollmentTreeError::Corrupt),
            "mutation {mutation}"
        );
    }
    let mut padded = bytes.clone();
    padded.push(b' ');
    assert_eq!(
        EnrollmentTree::decode(&padded, &fixture.pins),
        Err(EnrollmentTreeError::Corrupt)
    );
    assert_eq!(
        EnrollmentTree::decode(&vec![b' '; 196_609], &fixture.pins),
        Err(EnrollmentTreeError::Corrupt)
    );
}

#[test]
fn enrollment_tree_native_grandchild_keeps_full_scope_path_and_parent_revocation() {
    let mut fixture = Fixture::with_depth(0x44, 2);
    fixture.pins.permitted_channels.insert(
        "grandchild-channel".into(),
        EnrollmentChannelPins {
            principal: Signer::new(0x55).principal,
            instance_generation: 1,
        },
    );
    let mut tree = EnrollmentTree::new(fixture.pins.clone()).unwrap();
    let parent_id = fixture.enroll_tree(&mut tree).unwrap();
    let parent_pins = tree.parent_pins(parent_id, NOW).unwrap();
    let grandchild = Signer::new(0x55);
    let control = grant(
        &fixture.child,
        &grandchild,
        PARTICIPANT_SERVICE,
        CONTROL_TOOLS,
        Some(grant_id(fixture.child_control.statement()).unwrap()),
        0,
    );
    let resource = grant_for_audiences(
        &fixture.child,
        &grandchild,
        RESOURCE_SERVICE,
        &[RESOURCE_TOOL],
        Some(grant_id(fixture.child_resource.statement()).unwrap()),
        0,
        vec![resource_audience(&[1; 32], 2, &"ab".repeat(32)).unwrap()],
    );
    let mut descriptor = child_descriptor(&grandchild, &control, &resource, &parent_pins);
    descriptor.enrollment_id = "grandchild".into();
    descriptor.delivery_channel = "grandchild-channel".into();
    let parent_signed = chained(
        &[&fixture.root, &fixture.parent, &fixture.child],
        &[&fixture.parent_control, &fixture.child_control],
        PARTICIPANT_SERVICE,
        ENROLL_PARTICIPANT_TOOL,
        json!({"enrollment": descriptor}).as_object().unwrap(),
    );
    let signers = [&fixture.root, &fixture.parent, &fixture.child, &grandchild];
    let child_signed = chained(
        &signers,
        &[&fixture.parent_control, &fixture.child_control, &control],
        PARTICIPANT_SERVICE,
        ACCEPT_PARTICIPANT_TOOL,
        json!({"enrollment_commitment": descriptor.commitment().unwrap()})
            .as_object()
            .unwrap(),
    );
    let resource_signed = chained(
        &signers,
        &[&fixture.parent_resource, &fixture.child_resource, &resource],
        RESOURCE_SERVICE,
        RESOURCE_TOOL,
        json!({"record_id": "record-a"}).as_object().unwrap(),
    );
    let resources = [EnrollmentResourceWitness {
        scope_id: "project-a-read",
        invocation: invocation(&resource_signed),
    }];
    let proofs = ParticipantEnrollmentProofs {
        parent: invocation(&parent_signed),
        child: invocation(&child_signed),
        resources: &resources,
    };
    let grandchild_id = tree
        .enroll(&fixture.context, parent_id, NOW, &proofs)
        .unwrap();
    assert_eq!(
        tree.resource_grant_path(grandchild_id, "project-a-read", NOW)
            .unwrap(),
        vec![
            grant_id(fixture.parent_resource.statement()).unwrap(),
            grant_id(fixture.child_resource.statement()).unwrap(),
            grant_id(resource.statement()).unwrap()
        ]
    );
    tree.revoke(parent_id).unwrap();
    let restored = EnrollmentTree::decode(&tree.encode().unwrap(), &fixture.pins).unwrap();
    assert_eq!(
        restored.resource_grant_path(grandchild_id, "project-a-read", NOW),
        Err(EnrollmentTreeError::Inactive)
    );
    assert_eq!(restored.participant_count(), 3);
}

#[test]
fn native_enrollment_registered_channel_must_match_child_identity_and_instance() {
    let mut fixture = Fixture::new();
    let resource = fixture.resource_proof("record-a");
    let original = fixture.pins.permitted_channels["agent-b-channel"].clone();
    fixture
        .pins
        .permitted_channels
        .get_mut("agent-b-channel")
        .unwrap()
        .principal = fixture.parent.principal.clone();
    assert_eq!(
        fixture
            .verify(&fixture.enrollment, &fixture.enrollment, &resource)
            .unwrap_err(),
        ParticipantEnrollmentError::ParentBinding
    );
    fixture
        .pins
        .permitted_channels
        .insert("agent-b-channel".into(), original);
    fixture
        .pins
        .permitted_channels
        .get_mut("agent-b-channel")
        .unwrap()
        .instance_generation += 1;
    assert_eq!(
        fixture
            .verify(&fixture.enrollment, &fixture.enrollment, &resource)
            .unwrap_err(),
        ParticipantEnrollmentError::ParentBinding
    );
}

impl Fixture {
    fn committed_root(&self) -> ParentEnrollmentPins {
        let mut pins = self.pins.clone();
        pins.enrollment_commitment = root_enrollment_commitment(&pins).unwrap();
        pins
    }

    fn root_activation(&self, pins: &ParentEnrollmentPins) -> Submission {
        chained(
            &[&self.root, &self.parent],
            &[&self.parent_control],
            PARTICIPANT_SERVICE,
            ACTIVATE_ROOT_TOOL,
            json!({"root_enrollment_commitment": pins.enrollment_commitment})
                .as_object()
                .unwrap(),
        )
    }

    fn root_resource(&self, handle: &str, grant: &SignedGrant) -> Submission {
        chained(
            &[&self.root, &self.parent],
            &[grant],
            RESOURCE_SERVICE,
            RESOURCE_TOOL,
            json!({"record_id": handle}).as_object().unwrap(),
        )
    }

    fn bootstrap_with(
        &self,
        pins: &ParentEnrollmentPins,
        activation: &Submission,
        resource: &Submission,
        now: u64,
    ) -> Result<EnrollmentTree, EnrollmentTreeError> {
        let resources = [EnrollmentResourceWitness {
            scope_id: "project-a-read",
            invocation: invocation(resource),
        }];
        EnrollmentTree::bootstrap(
            &self.context,
            pins,
            now,
            &RootEnrollmentProofs {
                activation: invocation(activation),
                resources: &resources,
            },
        )
    }
}

#[test]
fn root_bootstrap_requires_native_holder_and_resource_grants_before_child_enrollment() {
    let mut fixture = Fixture::new();
    fixture.pins = fixture.committed_root();
    fixture.enrollment.parent_enrollment = fixture.pins.enrollment_commitment;
    let activation = fixture.root_activation(&fixture.pins);
    let resource = fixture.root_resource("record-a", &fixture.parent_resource);
    let mut tree = fixture
        .bootstrap_with(&fixture.pins, &activation, &resource, NOW)
        .unwrap();
    assert_eq!(tree.participant_count(), 1);
    let child = fixture.enroll_tree(&mut tree).unwrap();
    assert_eq!(
        tree.resource_grant_path(child, "project-a-read", NOW)
            .unwrap(),
        vec![
            grant_id(fixture.parent_resource.statement()).unwrap(),
            grant_id(fixture.child_resource.statement()).unwrap()
        ]
    );
    assert_eq!(
        EnrollmentTree::decode(&tree.encode().unwrap(), &fixture.pins).unwrap(),
        tree
    );
}

#[test]
fn root_bootstrap_commitment_covers_every_immutable_installation_dimension() {
    let fixture = Fixture::new();
    let pins = fixture.committed_root();
    let activation = fixture.root_activation(&pins);
    let resource = fixture.root_resource("record-a", &fixture.parent_resource);
    for mutation in 0..21 {
        let mut changed = pins.clone();
        match mutation {
            0 => changed.engagement_commitment[0] ^= 1,
            1 => changed.partition_generation += 1,
            2 => changed.instance_generation += 1,
            3 => changed.principal = fixture.child.principal.clone(),
            4 => changed.control_grant = GrantId::new([0x99; 32]),
            5 => changed.not_before += 1,
            6 => changed.expires_at -= 1,
            7 => changed.remaining_depth = 0,
            8 => changed.ceilings.disclosure_bytes -= 1,
            9 => changed.scopes[0].parent_grant = GrantId::new([0x99; 32]),
            10 => {
                changed.scopes[0].resource = EnrollmentResourceBinding::Exact {
                    handle: "record-b".into(),
                }
            }
            11 => changed.scopes[0].resource_argument = "other_id".into(),
            12 => changed.scopes[0].tool = "another_tool".into(),
            13 => {
                changed
                    .permitted_channels
                    .get_mut("agent-b-channel")
                    .unwrap()
                    .instance_generation += 1;
            }
            14 => changed.ceilings.provider_reads -= 1,
            15 => changed.ceilings.disclosures -= 1,
            16 => changed.ceilings.writes -= 1,
            17 => changed.scopes[0].scope_id = "other-scope".into(),
            18 => changed.scopes[0].service = "other-service".into(),
            19 => {
                changed
                    .permitted_channels
                    .get_mut("agent-b-channel")
                    .unwrap()
                    .principal = fixture.parent.principal.clone();
            }
            _ => {
                let channel = changed
                    .permitted_channels
                    .remove("agent-b-channel")
                    .unwrap();
                changed
                    .permitted_channels
                    .insert("other-channel".into(), channel);
            }
        }
        changed.enrollment_commitment = root_enrollment_commitment(&changed).unwrap();
        assert_ne!(
            changed.enrollment_commitment, pins.enrollment_commitment,
            "mutation {mutation}"
        );
        assert_eq!(
            fixture.bootstrap_with(&changed, &activation, &resource, NOW),
            Err(EnrollmentTreeError::Verification(
                ParticipantEnrollmentError::Acceptance
            )),
            "mutation {mutation}"
        );
    }
    let mut state_only = pins.clone();
    state_only.active = false;
    state_only.enrollment_commitment = [0x99; 32];
    assert_eq!(
        root_enrollment_commitment(&state_only).unwrap(),
        pins.enrollment_commitment
    );
}

#[test]
fn root_bootstrap_refuses_unpinned_resource_authority_and_wrong_resource_handle() {
    let fixture = Fixture::new();
    let pins = fixture.committed_root();
    let activation = fixture.root_activation(&pins);
    let wrong_handle = fixture.root_resource("record-b", &fixture.parent_resource);
    assert_eq!(
        fixture.bootstrap_with(&pins, &activation, &wrong_handle, NOW),
        Err(EnrollmentTreeError::Verification(
            ParticipantEnrollmentError::ResourceAuthority
        ))
    );
    let alternate = grant_for_audiences(
        &fixture.root,
        &fixture.parent,
        RESOURCE_SERVICE,
        &[RESOURCE_TOOL],
        None,
        0,
        vec![resource_audience(&[1; 32], 2, &"ab".repeat(32)).unwrap()],
    );
    let alternate_resource = fixture.root_resource("record-a", &alternate);
    assert_eq!(
        fixture.bootstrap_with(&pins, &activation, &alternate_resource, NOW),
        Err(EnrollmentTreeError::Verification(
            ParticipantEnrollmentError::ResourceAuthority
        ))
    );
    // Pinning a different valid grant still cannot invent native delegation depth.
    let mut depth = pins.clone();
    depth.scopes[0].parent_grant = grant_id(alternate.statement()).unwrap();
    depth.enrollment_commitment = root_enrollment_commitment(&depth).unwrap();
    let activation = fixture.root_activation(&depth);
    assert_eq!(
        fixture.bootstrap_with(&depth, &activation, &alternate_resource, NOW),
        Err(EnrollmentTreeError::Verification(
            ParticipantEnrollmentError::ResourceAuthority
        ))
    );
}

#[test]
fn root_bootstrap_refuses_missing_oversized_expired_or_revoked_inputs() {
    let fixture = Fixture::new();
    let pins = fixture.committed_root();
    let activation = fixture.root_activation(&pins);
    let resource = fixture.root_resource("record-a", &fixture.parent_resource);
    let no_resources = RootEnrollmentProofs {
        activation: invocation(&activation),
        resources: &[],
    };
    assert_eq!(
        EnrollmentTree::bootstrap(&fixture.context, &pins, NOW, &no_resources),
        Err(EnrollmentTreeError::Verification(
            ParticipantEnrollmentError::Invalid
        ))
    );
    let oversized = Submission {
        proof: vec![0; MAX_PROOF_BYTES + 1],
        action: vec![0],
        commitment: [0; 32],
    };
    assert_eq!(
        fixture.bootstrap_with(&pins, &oversized, &resource, NOW),
        Err(EnrollmentTreeError::Verification(
            ParticipantEnrollmentError::Invalid
        ))
    );
    for now in [pins.not_before - 1, pins.expires_at] {
        assert_eq!(
            fixture.bootstrap_with(&pins, &activation, &resource, now),
            Err(EnrollmentTreeError::Verification(
                ParticipantEnrollmentError::ParentBinding
            ))
        );
    }
    let mut revoked = pins.clone();
    revoked.active = false;
    assert_eq!(
        fixture.bootstrap_with(&revoked, &activation, &resource, NOW),
        Err(EnrollmentTreeError::Verification(
            ParticipantEnrollmentError::ParentBinding
        ))
    );
}

#[test]
fn root_bootstrap_never_substitutes_another_valid_control_grant_or_holder() {
    let fixture = Fixture::new();
    let pins = fixture.committed_root();
    let resource = fixture.root_resource("record-a", &fixture.parent_resource);
    let alternate = grant(
        &fixture.root,
        &fixture.parent,
        PARTICIPANT_SERVICE,
        &[ACTIVATE_ROOT_TOOL],
        None,
        1,
    );
    let activation = chained(
        &[&fixture.root, &fixture.parent],
        &[&alternate],
        PARTICIPANT_SERVICE,
        ACTIVATE_ROOT_TOOL,
        json!({"root_enrollment_commitment": pins.enrollment_commitment})
            .as_object()
            .unwrap(),
    );
    assert_eq!(
        fixture.bootstrap_with(&pins, &activation, &resource, NOW),
        Err(EnrollmentTreeError::Verification(
            ParticipantEnrollmentError::ControlAuthority
        ))
    );
    let activation = chained(
        &[&fixture.root, &fixture.parent, &fixture.child],
        &[&fixture.parent_control, &fixture.child_control],
        PARTICIPANT_SERVICE,
        ACTIVATE_ROOT_TOOL,
        json!({"root_enrollment_commitment": pins.enrollment_commitment})
            .as_object()
            .unwrap(),
    );
    assert_eq!(
        fixture.bootstrap_with(&pins, &activation, &resource, NOW),
        Err(EnrollmentTreeError::Verification(
            ParticipantEnrollmentError::ControlAuthority
        ))
    );
}

#[test]
fn enrollment_resource_pins_cannot_alias_control_namespaces() {
    let fixture = Fixture::new();
    for service in [crate::control_namespace::TASK_SERVICE, PARTICIPANT_SERVICE] {
        let mut pins = fixture.pins.clone();
        pins.scopes[0].service = service.into();
        pins.scopes[0].tool = ENROLL_PARTICIPANT_TOOL.into();
        pins.scopes[0].parent_grant = pins.control_grant;
        assert_eq!(
            root_enrollment_commitment(&pins),
            Err(ParticipantEnrollmentError::Invalid)
        );
    }
}

#[test]
fn root_bootstrap_refuses_resource_grants_reusable_outside_the_engagement() {
    let fixture = Fixture::new();
    let audience = resource_audience(&[1; 32], 2, &"ab".repeat(32)).unwrap();
    let multi = grant_for_audiences(
        &fixture.root,
        &fixture.parent,
        RESOURCE_SERVICE,
        &[RESOURCE_TOOL],
        None,
        1,
        vec![
            audience.clone(),
            Audience::parse(&format!("mcp://{RESOURCE_SERVICE}")).unwrap(),
        ],
    );
    let mut pins = fixture.committed_root();
    pins.scopes[0].parent_grant = grant_id(multi.statement()).unwrap();
    pins.enrollment_commitment = root_enrollment_commitment(&pins).unwrap();
    let activation = fixture.root_activation(&pins);
    let resource = submission_for_audience(
        &fixture.root,
        &fixture.parent,
        &multi,
        json!({"record_id": "record-a"}).as_object().unwrap(),
        &[],
        RESOURCE_SERVICE,
        RESOURCE_TOOL,
        NOW,
        audience,
    );
    assert_eq!(
        fixture.bootstrap_with(&pins, &activation, &resource, NOW),
        Err(EnrollmentTreeError::Verification(
            ParticipantEnrollmentError::ResourceAuthority
        ))
    );
}

#[test]
fn resource_audience_is_canonical_and_separates_every_authority_dimension() {
    let valid = resource_audience(&[1; 32], 2, &"ab".repeat(32)).unwrap();
    assert_ne!(
        valid,
        resource_audience(&[2; 32], 2, &"ab".repeat(32)).unwrap()
    );
    assert_ne!(
        valid,
        resource_audience(&[1; 32], 3, &"ab".repeat(32)).unwrap()
    );
    assert_ne!(
        valid,
        resource_audience(&[1; 32], 2, &"cd".repeat(32)).unwrap()
    );
    for generation in [0, MAX_JSON_INTEGER + 1, u64::MAX] {
        assert!(resource_audience(&[1; 32], generation, &"ab".repeat(32)).is_err());
    }
    for digest in [
        "AB".repeat(32),
        "ab".repeat(31),
        "ab".repeat(33),
        "g".repeat(64),
    ] {
        assert!(resource_audience(&[1; 32], 2, &digest).is_err());
    }
}

#[test]
fn deferred_child_witness_is_authority_not_a_resource_binding() {
    use auths_profile_api::ActionProfile as _;
    let fixture = Fixture::new();
    let mut pins = fixture.committed_root();
    pins.scopes[0].resource = EnrollmentResourceBinding::CreatedChild {
        create_operation_id: "create-one".into(),
        create_recipe_digest: "cd".repeat(32),
        parent_scope_id: "ef".repeat(32),
    };
    pins.enrollment_commitment = root_enrollment_commitment(&pins).unwrap();
    let activation = fixture.root_activation(&pins);
    let resource = fixture.root_resource("witness-only", &fixture.parent_resource);
    let tree = fixture
        .bootstrap_with(&pins, &activation, &resource, NOW)
        .unwrap();
    assert_eq!(tree.root().scopes[0].resource, pins.scopes[0].resource);
    assert!(matches!(
        tree.root().scopes[0].resource,
        EnrollmentResourceBinding::CreatedChild { .. }
    ));

    // This native grant authorizes the sample, but proves nothing about an
    // unknown future handle. It must not become deferred enrollment authority.
    let call = McpToolCall::new(
        RESOURCE_SERVICE,
        RESOURCE_TOOL,
        json!({"record_id": "witness-only"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .unwrap();
    let canonical = auths_profile_mcp::McpProfile
        .canonicalize(&call.canonical_bytes().unwrap())
        .unwrap();
    let original = fixture.parent_resource.statement();
    let statement = GrantStatement::new(
        original.issuer().clone(),
        original.subject().clone(),
        original.profile().clone(),
        original.permissions().clone(),
        original.validity(),
        original.audiences().clone(),
        ActionConstraint::ExactBodyDigest(auths_codec::body_digest(canonical.body())),
        original.budget_ceiling().cloned(),
        original.remaining_depth(),
        original.parent(),
        original.status_policy().clone(),
        original.assurance_floor().clone(),
        original.extensions().clone(),
    );
    let descriptor = fixture.root.descriptor();
    let signature = fixture
        .root
        .sign(&grant_signing_preimage(&statement, &descriptor).unwrap());
    let exact = SignedGrant::new(statement, SignatureEnvelope::new(descriptor, signature));
    pins.scopes[0].parent_grant = grant_id(exact.statement()).unwrap();
    pins.enrollment_commitment = root_enrollment_commitment(&pins).unwrap();
    let activation = fixture.root_activation(&pins);
    let resource = fixture.root_resource("witness-only", &exact);
    assert_eq!(
        fixture.bootstrap_with(&pins, &activation, &resource, NOW),
        Err(EnrollmentTreeError::Verification(
            ParticipantEnrollmentError::ResourceAuthority
        ))
    );
}
