use super::*;
use crate::GatewayObserver;
use crate::harness::{self, Signer};
use crate::observed_tests::Submission;
use auths_codec::{grant_id, grant_signing_preimage};
use auths_model::{
    ActionConstraint, AssurancePolicyId, AudienceSet, BundleHeader, CompositionRequirement,
    ControlBinding, CriticalExtensions, GrantStatement, PermissionSet, ProofBundle,
    SignatureEnvelope, StatementRef, StatusPolicy,
};
use auths_profile_mcp::McpToolCall;
use serde_json::{Map, json};

#[path = "configuration_tests.rs"]
mod configuration_tests;

#[path = "audit_tests.rs"]
mod audit_tests;

#[cfg(all(unix, feature = "loopback-provider", feature = "testkit-harness"))]
#[path = "cross_recipe_fixture.rs"]
mod cross_recipe_fixture;
#[cfg(all(unix, feature = "loopback-provider", feature = "testkit-harness"))]
pub(crate) use cross_recipe_fixture::cross_recipe_fixture;

const NOW: u64 = 1_790_000_000;
const RESOURCE_SERVICE: &str = "engagement-records";
const RESOURCE_TOOL: &str = "read_record";
const CONTROL_TOOLS: &[&str] = &[
    ACTIVATE_ROOT_TOOL,
    ENROLL_PARTICIPANT_TOOL,
    ACCEPT_PARTICIPANT_TOOL,
    REVOKE_PARTICIPANT_TOOL,
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
                (PARTICIPANT_SERVICE, REVOKE_PARTICIPANT_TOOL),
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
        admission_namespace: "engagement-authority".into(),
        admission_partition: "shared-partition".into(),
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
                channel_binding: [0x76; 32],
                principal: child.principal.clone(),
                instance_generation: 1,
            },
        )]),
        scopes: vec![EnrollmentScopePins {
            connection_binding: [0x75; 32],
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
                channel_binding: [0x76; 32],
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
                        channel_binding: [0x76; 32],
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
            channel_binding: [0x76; 32],
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

    fn commit_root(&mut self) {
        self.pins = self.committed_root();
        self.enrollment.parent_enrollment = self.pins.enrollment_commitment;
    }

    fn withdraw_as_parent(&self, participant: [u8; 32]) -> Submission {
        chained(
            &[&self.root, &self.parent],
            &[&self.parent_control],
            PARTICIPANT_SERVICE,
            REVOKE_PARTICIPANT_TOOL,
            json!({"root_enrollment": self.pins.enrollment_commitment,
                "participant": participant})
            .as_object()
            .unwrap(),
        )
    }

    fn withdraw_as_child(&self, participant: [u8; 32]) -> Submission {
        chained(
            &[&self.root, &self.parent, &self.child],
            &[&self.parent_control, &self.child_control],
            PARTICIPANT_SERVICE,
            REVOKE_PARTICIPANT_TOOL,
            json!({"root_enrollment": self.pins.enrollment_commitment,
                "participant": participant})
            .as_object()
            .unwrap(),
        )
    }

    fn bootstrap_configuration(
        &self,
        controller: &crate::EngagementConfiguration,
    ) -> Result<crate::EngagementConfigurationSnapshot, crate::EngagementConfigurationError> {
        let activation = self.root_activation(&self.pins);
        let resource = self.root_resource("record-a", &self.parent_resource);
        let resources = [EnrollmentResourceWitness {
            scope_id: "project-a-read",
            invocation: invocation(&resource),
        }];
        controller.bootstrap(&RootEnrollmentProofs {
            activation: invocation(&activation),
            resources: &resources,
        })
    }

    fn enroll_configuration(
        &self,
        controller: &crate::EngagementConfiguration,
    ) -> Result<crate::EngagementConfigurationSnapshot, crate::EngagementConfigurationError> {
        let parent = self.parent_proof(&self.enrollment);
        let child = self.child_proof(&self.enrollment);
        let resource = self.resource_proof("record-a");
        let resources = [EnrollmentResourceWitness {
            scope_id: "project-a-read",
            invocation: invocation(&resource),
        }];
        controller.enroll(
            self.pins.enrollment_commitment,
            &ParticipantEnrollmentProofs {
                parent: invocation(&parent),
                child: invocation(&child),
                resources: &resources,
            },
        )
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
    for mutation in 0..25 {
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
            21 => changed.admission_namespace = "another-authority".into(),
            22 => changed.admission_partition = "another-partition".into(),
            23 => changed.scopes[0].connection_binding[0] ^= 1,
            24 => {
                changed
                    .permitted_channels
                    .get_mut("agent-b-channel")
                    .unwrap()
                    .channel_binding[0] ^= 1
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
    assert_eq!(
        tree.verify_operation_scope(
            &fixture.context,
            "project-a-read",
            NOW,
            &invocation(&resource)
        ),
        Err(EnrollmentTreeError::Binding)
    );

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

// Test-only native authoring, independent of any gateway execution/projection.
// These fixed public fixture keys establish no deployment identity assurance.
#[allow(
    clippy::too_many_arguments,
    reason = "native fixture states every signed input"
)]
fn submission_for_audience(
    root: &Signer,
    actor: &Signer,
    grant: &SignedGrant,
    arguments: &Map<String, Value>,
    observations: &[Vec<u8>],
    service: &str,
    tool: &str,
    now: u64,
    audience: Audience,
) -> Submission {
    use auths_codec::{
        action_id, action_signing_preimage, body_digest, encode_bundle, encode_canonical_action,
        plan_id,
    };
    use auths_model::{
        ActionEnvelope, AuthorizationPlan, CanonicalAction, Challenge, ChannelBindingId, ProofRef,
        SignedAction,
    };
    assert!(observations.is_empty());
    let call = McpToolCall::new(service, tool, arguments.clone()).unwrap();
    let canonical: CanonicalAction = McpProfile
        .canonicalize(&call.canonical_bytes().unwrap())
        .unwrap();
    let proof_ref = ProofRef::new([0x0b; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let envelope = ActionEnvelope::new(
        canonical.profile().clone(),
        canonical.media_type().clone(),
        body_digest(canonical.body()),
        canonical.permission().clone(),
        None,
        audience,
        Challenge::new([0; 32]),
        harness::window(now - 3_600, now + 3_600).unwrap(),
        actor.principal.clone(),
        Some(grant_id(grant.statement()).unwrap()),
        plan_id(&plan).unwrap(),
        ChannelBindingId::parse("none-v1").unwrap(),
        proof_ref,
        Vec::new(),
        CriticalExtensions::empty(),
    );
    let descriptor = actor.descriptor();
    let signature = actor.sign(&action_signing_preimage(&envelope, &descriptor).unwrap());
    let action = SignedAction::new(envelope, SignatureEnvelope::new(descriptor, signature));
    let bindings = vec![
        ControlBinding::new(
            StatementRef::Grant(grant_id(grant.statement()).unwrap()),
            vec![root.evidence().id()],
        )
        .unwrap(),
        ControlBinding::new(
            StatementRef::Action(action_id(action.envelope()).unwrap()),
            vec![actor.evidence().id()],
        )
        .unwrap(),
    ];
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        vec![grant.clone()],
        vec![action],
        plan,
        vec![root.evidence(), actor.evidence()],
        bindings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .unwrap();
    let action = encode_canonical_action(&canonical).unwrap();
    let commitment = *auths_codec::domain_commitment("auths.canonical-action.v1", &action)
        .unwrap()
        .as_bytes();
    Submission {
        proof: encode_bundle(&bundle).unwrap(),
        action,
        commitment,
    }
}

#[test]
fn native_operation_requires_the_exact_enrolled_scope_grant_suffix() {
    let fixture = Fixture::new();
    let mut tree = EnrollmentTree::new(fixture.pins.clone()).unwrap();
    fixture.enroll_tree(&mut tree).unwrap();
    let signed = fixture.resource_proof("record-a");
    let identity = tree
        .verify_operation_scope(
            &fixture.context,
            "project-a-read",
            NOW,
            &invocation(&signed),
        )
        .unwrap();
    assert_eq!(identity.principal(), fixture.child.principal.as_str());
    assert_eq!(
        identity,
        tree.retained_identity(fixture.child.principal.as_str())
            .unwrap()
    );

    // A freshly signed, natively authorized alternative from the same parent
    // to the same holder is not the enrolled immutable resource authority.
    let replacement = grant_for_audiences_at(
        &fixture.parent,
        &fixture.child,
        RESOURCE_SERVICE,
        &[RESOURCE_TOOL],
        Some(grant_id(fixture.parent_resource.statement()).unwrap()),
        0,
        vec![resource_audience(&[1; 32], 2, &"ab".repeat(32)).unwrap()],
        NOW + 1,
    );
    let substituted = chained_at(
        &[&fixture.root, &fixture.parent, &fixture.child],
        &[&fixture.parent_resource, &replacement],
        RESOURCE_SERVICE,
        RESOURCE_TOOL,
        json!({"record_id": "record-a"}).as_object().unwrap(),
        NOW + 1,
    );
    assert_eq!(
        tree.verify_operation_scope(
            &fixture.context,
            "project-a-read",
            NOW + 1,
            &invocation(&substituted)
        ),
        Err(EnrollmentTreeError::Binding)
    );
}

#[test]
fn native_operation_refuses_other_scope_resource_and_revoked_ancestry() {
    let fixture = Fixture::new();
    let mut tree = EnrollmentTree::new(fixture.pins.clone()).unwrap();
    fixture.enroll_tree(&mut tree).unwrap();
    let signed = fixture.resource_proof("record-a");
    assert_eq!(
        tree.verify_operation_scope(&fixture.context, "other-scope", NOW, &invocation(&signed)),
        Err(EnrollmentTreeError::Binding)
    );
    let wrong = fixture.resource_proof("record-b");
    assert!(
        tree.verify_operation_scope(&fixture.context, "project-a-read", NOW, &invocation(&wrong))
            .is_err()
    );
    let retained = tree
        .retained_identity(fixture.child.principal.as_str())
        .unwrap();
    tree.revoke(fixture.pins.enrollment_commitment).unwrap();
    assert_eq!(
        tree.verify_operation_scope(
            &fixture.context,
            "project-a-read",
            NOW,
            &invocation(&signed)
        ),
        Err(EnrollmentTreeError::Inactive)
    );
    assert_eq!(
        tree.retained_identity(fixture.child.principal.as_str())
            .unwrap(),
        retained
    );
}

#[test]
fn native_operation_refuses_cross_engagement_recipe_and_epoch() {
    let fixture = Fixture::new();
    let mut tree = EnrollmentTree::new(fixture.pins.clone()).unwrap();
    fixture.enroll_tree(&mut tree).unwrap();
    for audience in [
        resource_audience(&[2; 32], 2, &"ab".repeat(32)).unwrap(),
        resource_audience(&[1; 32], 3, &"ab".repeat(32)).unwrap(),
        resource_audience(&[1; 32], 2, &"cd".repeat(32)).unwrap(),
    ] {
        let root_grant = grant_for_audiences(
            &fixture.root,
            &fixture.parent,
            RESOURCE_SERVICE,
            &[RESOURCE_TOOL],
            None,
            1,
            vec![audience.clone()],
        );
        let child_grant = grant_for_audiences(
            &fixture.parent,
            &fixture.child,
            RESOURCE_SERVICE,
            &[RESOURCE_TOOL],
            Some(grant_id(root_grant.statement()).unwrap()),
            0,
            vec![audience],
        );
        let signed = chained(
            &[&fixture.root, &fixture.parent, &fixture.child],
            &[&root_grant, &child_grant],
            RESOURCE_SERVICE,
            RESOURCE_TOOL,
            json!({"record_id": "record-a"}).as_object().unwrap(),
        );
        assert!(
            tree.verify_operation_scope(
                &fixture.context,
                "project-a-read",
                NOW,
                &invocation(&signed)
            )
            .is_err()
        );
    }
}

#[test]
fn enrollment_private_debug_and_bounded_operation_refusals() {
    let fixture = Fixture::new();
    let mut tree = EnrollmentTree::new(fixture.pins.clone()).unwrap();
    fixture.enroll_tree(&mut tree).unwrap();
    let identity = tree
        .retained_identity(fixture.child.principal.as_str())
        .unwrap();
    for debug in [
        format!("{tree:?}"),
        format!("{identity:?}"),
        format!("{:?}", fixture.pins),
        format!("{:?}", fixture.enrollment),
    ] {
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("record-a"));
        assert!(!debug.contains(fixture.child.principal.as_str()));
        assert!(!debug.contains("agent-b-channel"));
    }
    let oversized = EnrollmentInvocation {
        proof: &[1],
        action: &vec![0; MAX_ACTION_BYTES + 1],
    };
    assert!(
        tree.verify_operation_scope(&fixture.context, "project-a-read", NOW, &oversized)
            .is_err()
    );
    let signed = fixture.resource_proof("record-a");
    assert_eq!(
        tree.verify_operation_scope(
            &fixture.context,
            "project-a-read",
            fixture.enrollment.expires_at,
            &invocation(&signed)
        ),
        Err(EnrollmentTreeError::Inactive)
    );
}

proptest::proptest! {
    #[test]
    fn enrollment_narrowing_rejects_generated_widening(
        dimension in 0usize..8,
        excess in 1u64..1000,
    ) {
        let fixture = Fixture::new();
        let mut descriptor = fixture.enrollment.clone();
        match dimension {
            0 => descriptor.ceilings.provider_reads = fixture.pins.ceilings.provider_reads + u32::try_from(excess).unwrap(),
            1 => descriptor.ceilings.disclosures = fixture.pins.ceilings.disclosures + u32::try_from(excess).unwrap(),
            2 => descriptor.ceilings.disclosure_bytes = fixture.pins.ceilings.disclosure_bytes + excess,
            3 => descriptor.ceilings.writes = fixture.pins.ceilings.writes + u32::try_from(excess).unwrap(),
            4 => descriptor.remaining_depth = fixture.pins.remaining_depth + u16::try_from(excess).unwrap(),
            5 => descriptor.not_before = fixture.pins.not_before - excess,
            6 => descriptor.expires_at = fixture.pins.expires_at + excess,
            7 => descriptor.child_instance_generation += excess,
            _ => unreachable!(),
        }
        proptest::prop_assert!(descriptor.validate(&fixture.pins, NOW).is_err());
    }

    #[test]
    fn enrollment_tree_arbitrary_bytes_fail_without_changing_retained_state(
        bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..4096),
    ) {
        let fixture = Fixture::new();
        let tree = EnrollmentTree::new(fixture.pins.clone()).unwrap();
        let before = tree.encode().unwrap();
        proptest::prop_assert!(EnrollmentTree::decode(&bytes, &fixture.pins).is_err());
        proptest::prop_assert_eq!(tree.encode().unwrap(), before);
    }
}

/// Product corpus generated by the native verifier with public fixture keys.
/// A valid enrollment is still a proposal, never a provider/delivery permit.
#[test]
fn native_participant_enrollment_fixture_is_current() {
    let mut fixture = Fixture::new();
    fixture.commit_root();
    let parent = fixture.parent_proof(&fixture.enrollment);
    let child = fixture.child_proof(&fixture.enrollment);
    let resource = fixture.resource_proof("record-a");
    let verified = fixture
        .verify(&fixture.enrollment, &fixture.enrollment, &resource)
        .unwrap();
    let activation = fixture.root_activation(&fixture.pins);
    let root_resource = fixture.root_resource("record-a", &fixture.parent_resource);
    let mut tree = fixture
        .bootstrap_with(&fixture.pins, &activation, &root_resource, NOW)
        .unwrap();
    fixture.enroll_tree(&mut tree).unwrap();
    let native_inputs = |signed: &Submission| {
        json!({"proof_cbor_hex": hex::encode(&signed.proof),
            "action_cbor_hex": hex::encode(&signed.action)})
    };
    let mut wrong_instance = fixture.enrollment.clone();
    wrong_instance.child_instance_generation += 1;
    let wrong_parent = fixture.parent_proof(&wrong_instance);
    let wrong_child = fixture.child_proof(&wrong_instance);
    assert_eq!(
        fixture
            .verify(&wrong_instance, &wrong_instance, &resource)
            .unwrap_err(),
        ParticipantEnrollmentError::ParentBinding
    );
    let wrong_resource = fixture.resource_proof("record-b");
    assert_eq!(
        fixture
            .verify(&fixture.enrollment, &fixture.enrollment, &wrong_resource)
            .unwrap_err(),
        ParticipantEnrollmentError::ResourceAuthority
    );
    let identity = tree
        .verify_operation_scope(
            &fixture.context,
            "project-a-read",
            NOW,
            &invocation(&resource),
        )
        .unwrap();
    let value = json!({
        "schema": "auths.participant-enrollment-vectors/2",
        "claim_boundary": "native root, enrollment and scope verification only; no durable admission or entry",
        "evaluation_time": NOW,
        "context_cbor_hex": hex::encode(auths_codec::encode_verifier_context(&fixture.context).unwrap()),
        "parent_pins": fixture.pins,
        "enrollment": fixture.enrollment,
        "commitment_hex": hex::encode(verified.commitment()),
        "root_activation": native_inputs(&activation),
        "root_resource_invocation": native_inputs(&root_resource),
        "parent_invocation": native_inputs(&parent),
        "child_invocation": native_inputs(&child),
        "resource_invocation": native_inputs(&resource),
        "expected_identity": identity,
        "cases": [
            {"id": "parent-child-and-resource", "parent_invocation": native_inputs(&parent),
                "child_invocation": native_inputs(&child), "resource_invocation": native_inputs(&resource),
                "result": "verified-proposal"},
            {"id": "other-instance", "enrollment": wrong_instance,
                "parent_invocation": native_inputs(&wrong_parent), "child_invocation": native_inputs(&wrong_child),
                "resource_invocation": native_inputs(&resource), "result": "parent-binding"},
            {"id": "other-resource", "parent_invocation": native_inputs(&parent),
                "child_invocation": native_inputs(&child), "resource_invocation": native_inputs(&wrong_resource),
                "result": "resource-authority"}
        ]
    });
    let bytes = serde_json_canonicalizer::to_vec(&value).unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/engagement/enrollment.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    } else {
        assert_eq!(
            std::fs::read(path).unwrap(),
            bytes,
            "regenerate the canonical native enrollment corpus with AUTHS_UPDATE_FIXTURES=1"
        );
    }
}

/// Owned native enrollment inputs shared by scope and durable accounting tests.
pub(crate) struct EffectScopeFixture {
    pub(crate) root: ParentEnrollmentPins,
    pub(crate) tree: EnrollmentTree,
    pub(crate) context: TrustedContext,
    pub(crate) action: Submission,
    activation: Submission,
    root_resources: Vec<Submission>,
    children: Vec<([u8; 32], Submission, Submission, Vec<Submission>)>,
    withdrawal: Submission,
}

impl EffectScopeFixture {
    pub(crate) fn root_evidence(&self) -> crate::EngagementControlEvidence {
        let resources = self.control_resources(&self.root_resources);
        crate::EngagementControlEvidence::root(&RootEnrollmentProofs {
            activation: invocation(&self.activation),
            resources: &resources,
        })
        .unwrap()
    }
    fn control_resources<'a>(
        &'a self,
        proofs: &'a [Submission],
    ) -> Vec<EnrollmentResourceWitness<'a>> {
        self.root
            .scopes
            .iter()
            .zip(proofs)
            .map(|(scope, proof)| EnrollmentResourceWitness {
                scope_id: &scope.scope_id,
                invocation: invocation(proof),
            })
            .collect()
    }
    pub(crate) fn enrollment_evidence(&self, index: usize) -> crate::EngagementControlEvidence {
        let (parent_id, parent, child, proofs) = &self.children[index];
        let resources = self.control_resources(proofs);
        crate::EngagementControlEvidence::enroll(
            *parent_id,
            &ParticipantEnrollmentProofs {
                parent: invocation(parent),
                child: invocation(child),
                resources: &resources,
            },
        )
        .unwrap()
    }
    pub(crate) fn withdrawal_evidence(&self, actor: u8) -> crate::EngagementControlEvidence {
        let principal = Signer::new(actor);
        let target = self
            .tree
            .retained_principal_pins(principal.principal.as_str())
            .unwrap()
            .enrollment_commitment;
        let mut fixture = Fixture::with_depth(0x44, self.root.remaining_depth);
        fixture.pins = self.root.clone();
        let withdrawal = fixture.withdraw_as_parent(target);
        crate::EngagementControlEvidence::revoke(invocation(&withdrawal)).unwrap()
    }
    pub(crate) fn withdraw_participant(
        &self,
        controller: &crate::EngagementConfiguration,
        target: [u8; 32],
    ) {
        let mut fixture = Fixture::with_depth(0x44, self.root.remaining_depth);
        fixture.pins = self.root.clone();
        let withdrawal = fixture.withdraw_as_parent(target);
        controller.revoke(&invocation(&withdrawal)).unwrap();
    }
    pub(crate) fn withdraw_root(&self, controller: &crate::EngagementConfiguration) {
        controller.revoke(&invocation(&self.withdrawal)).unwrap();
    }
    pub(crate) fn signed_call(&self, call: &McpToolCall, actor: u8) -> Submission {
        let issuer = Signer::new(0x11);
        let actor_signer = Signer::new(actor);
        // Build the same native resource suffix retained by enrollment. Unknown
        // actors deliberately get a direct proposal for negative compiler cases.
        let path = self
            .tree
            .active_principal_path(actor_signer.principal.as_str(), NOW)
            .ok();
        let seeds: Vec<u8> = if path.as_ref().is_some_and(|path| path.len() == 3) {
            vec![0x22, 0x44, actor]
        } else {
            vec![0x22, actor]
        };
        let signers: Vec<_> = seeds.iter().map(|seed| Signer::new(*seed)).collect();
        let tools: Vec<_> = self
            .root
            .scopes
            .iter()
            .map(|scope| scope.tool.as_str())
            .collect();
        let audience = resource_audience(
            &self.root.engagement_commitment,
            self.root.partition_generation,
            &self.root.scopes[0].recipe_digest,
        )
        .unwrap();
        let mut grants = Vec::new();
        for (index, signer) in signers.iter().enumerate() {
            let parent = if index == 0 {
                &issuer
            } else {
                &signers[index - 1]
            };
            let previous = grants
                .last()
                .map(|grant: &SignedGrant| grant_id(grant.statement()).unwrap());
            grants.push(grant_for_audiences(
                parent,
                signer,
                call.service(),
                &tools,
                previous,
                self.root.remaining_depth - u16::try_from(index).unwrap(),
                vec![audience.clone()],
            ));
        }
        assert_eq!(
            grant_id(grants[0].statement()).unwrap(),
            self.root.scopes[0].parent_grant
        );
        let signer_refs: Vec<_> = std::iter::once(&issuer).chain(signers.iter()).collect();
        let grant_refs: Vec<_> = grants.iter().collect();
        chained(
            &signer_refs,
            &grant_refs,
            call.service(),
            call.name(),
            call.arguments(),
        )
    }
    pub(crate) fn persist(&self, controller: &crate::EngagementConfiguration) {
        let resources: Vec<_> = self
            .root
            .scopes
            .iter()
            .zip(&self.root_resources)
            .map(|(scope, proof)| EnrollmentResourceWitness {
                scope_id: &scope.scope_id,
                invocation: invocation(proof),
            })
            .collect();
        controller
            .bootstrap(&RootEnrollmentProofs {
                activation: invocation(&self.activation),
                resources: &resources,
            })
            .unwrap();
        for (parent_id, parent, child, proofs) in &self.children {
            let resources: Vec<_> = self
                .root
                .scopes
                .iter()
                .zip(proofs)
                .map(|(scope, proof)| EnrollmentResourceWitness {
                    scope_id: &scope.scope_id,
                    invocation: invocation(proof),
                })
                .collect();
            controller
                .enroll(
                    *parent_id,
                    &ParticipantEnrollmentProofs {
                        parent: invocation(parent),
                        child: invocation(child),
                        resources: &resources,
                    },
                )
                .unwrap();
        }
        assert!(controller.snapshot().unwrap().tree() == &self.tree);
    }
}

/// Real native root and two separately accepted siblings, with one shared root
/// ceiling. These are proof inputs only; persistence uses the maintained owner.
#[allow(
    clippy::too_many_lines,
    reason = "one complete native root/sibling/resource fixture is signed together"
)]
pub(crate) fn effect_scope_fixture_for_actor(
    recipe: &crate::CompiledRecipe,
    connection: &auths_connections::ConnectionRecord,
    arguments: &Map<String, Value>,
    actor_seed: u8,
) -> EffectScopeFixture {
    effect_scope_fixture_in_engagement(recipe, connection, arguments, actor_seed, [1; 32])
}

pub(crate) fn effect_scope_fixture_in_engagement(
    recipe: &crate::CompiledRecipe,
    connection: &auths_connections::ConnectionRecord,
    arguments: &Map<String, Value>,
    actor_seed: u8,
    engagement: [u8; 32],
) -> EffectScopeFixture {
    effect_scope_fixture_with_channel(recipe, connection, arguments, actor_seed, engagement, None)
}

pub(crate) fn effect_scope_hierarchy_fixture(
    recipe: &crate::CompiledRecipe,
    connection: &auths_connections::ConnectionRecord,
    arguments: &Map<String, Value>,
) -> EffectScopeFixture {
    effect_scope_fixture_with_topology(recipe, connection, arguments, 0x55, [1; 32], None, true)
}

pub(crate) fn effect_scope_fixture_with_channel(
    recipe: &crate::CompiledRecipe,
    connection: &auths_connections::ConnectionRecord,
    arguments: &Map<String, Value>,
    actor_seed: u8,
    engagement: [u8; 32],
    sibling_channel: Option<[u8; 32]>,
) -> EffectScopeFixture {
    effect_scope_fixture_with_topology(
        recipe,
        connection,
        arguments,
        actor_seed,
        engagement,
        sibling_channel,
        false,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "one native root and full control/resource suffix for the selected test topology"
)]
fn effect_scope_fixture_with_topology(
    recipe: &crate::CompiledRecipe,
    connection: &auths_connections::ConnectionRecord,
    arguments: &Map<String, Value>,
    actor_seed: u8,
    engagement: [u8; 32],
    sibling_channel: Option<[u8; 32]>,
    hierarchy: bool,
) -> EffectScopeFixture {
    assert!([0x44, 0x55].contains(&actor_seed));
    let depth = if hierarchy { 2 } else { 1 };
    let mut fixture = Fixture::with_depth(0x44, depth);
    fixture.pins.engagement_commitment = engagement;
    let sibling = Signer::new(0x55);
    let audience = resource_audience(
        &fixture.pins.engagement_commitment,
        fixture.pins.partition_generation,
        &recipe.digest_hex(),
    )
    .unwrap();
    let service = recipe.service();
    let review = recipe.review();
    let tool = review.tool();
    let content = crate::effect::ContentReadTarget::new(
        recipe,
        connection,
        serde_json::json!({"record_id":arguments["record_id"]})
            .as_object()
            .unwrap()
            .clone(),
    )
    .ok();
    let mut tools = vec![tool];
    if content.is_some() {
        tools.extend([
            crate::effect::CONTENT_READ_TOOL,
            crate::effect::DISCLOSURE_TOOL,
            crate::effect::RECOVERY_READ_TOOL,
        ]);
    }
    fixture.parent_resource = grant_for_audiences(
        &fixture.root,
        &fixture.parent,
        service,
        &tools,
        None,
        depth,
        vec![audience.clone()],
    );
    fixture.child_resource = grant_for_audiences(
        &fixture.parent,
        &fixture.child,
        service,
        &tools,
        Some(grant_id(fixture.parent_resource.statement()).unwrap()),
        depth - 1,
        vec![audience.clone()],
    );
    let sibling_control = grant(
        if hierarchy {
            &fixture.child
        } else {
            &fixture.parent
        },
        &sibling,
        PARTICIPANT_SERVICE,
        CONTROL_TOOLS,
        Some(
            grant_id(if hierarchy {
                fixture.child_control.statement()
            } else {
                fixture.parent_control.statement()
            })
            .unwrap(),
        ),
        0,
    );
    let sibling_resource = grant_for_audiences(
        if hierarchy {
            &fixture.child
        } else {
            &fixture.parent
        },
        &sibling,
        service,
        &tools,
        Some(
            grant_id(if hierarchy {
                fixture.child_resource.statement()
            } else {
                fixture.parent_resource.statement()
            })
            .unwrap(),
        ),
        0,
        vec![audience.clone()],
    );
    let observer = GatewayObserver::from_test_seed(0x33);
    let mut profiles = vec![
        (PARTICIPANT_SERVICE, ACTIVATE_ROOT_TOOL),
        (PARTICIPANT_SERVICE, ENROLL_PARTICIPANT_TOOL),
        (PARTICIPANT_SERVICE, ACCEPT_PARTICIPANT_TOOL),
        (PARTICIPANT_SERVICE, REVOKE_PARTICIPANT_TOOL),
    ];
    profiles.extend(tools.iter().map(|tool| (service, *tool)));
    fixture.context = harness::context_for_profiles_and_audiences(
        &[&fixture.root],
        observer.principal(),
        None,
        NOW,
        depth + 1,
        CompositionRequirement::new(None, 1, 1, 1).unwrap(),
        &[auths_raw_key::RAW_KEY_V1],
        &profiles,
        &[audience],
    )
    .unwrap();
    fixture.pins.scopes[0].recipe_digest = recipe.digest_hex();
    fixture.pins.scopes[0].service = service.to_owned();
    fixture.pins.scopes[0].tool = tool.to_owned();
    fixture.pins.scopes[0].connection_binding = crate::effect::commitment(
        "auths.effect-installation/1",
        &connection.to_canonical_cbor().unwrap(),
    )
    .unwrap();
    fixture.pins.scopes[0].parent_grant = grant_id(fixture.parent_resource.statement()).unwrap();
    fixture.pins.scopes[0].resource = EnrollmentResourceBinding::Exact {
        handle: arguments["record_id"].as_str().unwrap().to_owned(),
    };
    fixture.pins.permitted_channels.insert(
        "sibling-channel".to_owned(),
        EnrollmentChannelPins {
            channel_binding: [0x77; 32],
            principal: sibling.principal.clone(),
            instance_generation: 1,
        },
    );
    if content.is_some() {
        let base = fixture.pins.scopes[0].clone();
        for (suffix, tool) in [
            ("content", crate::effect::CONTENT_READ_TOOL),
            ("disclosure", crate::effect::DISCLOSURE_TOOL),
            ("recovery", crate::effect::RECOVERY_READ_TOOL),
        ] {
            let mut scope = base.clone();
            scope.scope_id = format!("project-a-read-{suffix}");
            scope.tool = tool.to_owned();
            fixture.pins.scopes.push(scope);
        }
        fixture
            .pins
            .permitted_channels
            .get_mut("sibling-channel")
            .unwrap()
            .channel_binding = sibling_channel.unwrap_or_else(|| {
            crate::effect::UnixDisclosurePolicy::new(1000, 1001, [0x78; 32])
                .commitment()
                .unwrap()
        });
    }
    fixture.enrollment.scopes[0].grant_id = *grant_id(fixture.child_resource.statement())
        .unwrap()
        .as_bytes();
    fixture.commit_root();
    let activation = fixture.root_activation(&fixture.pins);
    let witness = |actor: &Signer,
                   child_grant: Option<&SignedGrant>,
                   scope: &EnrollmentScopePins| {
        let args = if scope.tool == crate::effect::CONTENT_READ_TOOL {
            content
                .as_ref()
                .unwrap()
                .authorization_call(
                    recipe,
                    &crate::LogicalOperationId::parse("native-enrollment-content-witness").unwrap(),
                )
                .unwrap()
                .arguments()
                .clone()
        } else if scope.tool == tool {
            arguments.clone()
        } else {
            serde_json::json!({"record_id":arguments["record_id"]})
                .as_object()
                .unwrap()
                .clone()
        };
        match child_grant {
            None => chained(
                &[&fixture.root, actor],
                &[&fixture.parent_resource],
                service,
                &scope.tool,
                &args,
            ),
            Some(grant) if hierarchy && actor.principal == sibling.principal => chained(
                &[&fixture.root, &fixture.parent, &fixture.child, actor],
                &[&fixture.parent_resource, &fixture.child_resource, grant],
                service,
                &scope.tool,
                &args,
            ),
            Some(grant) => chained(
                &[&fixture.root, &fixture.parent, actor],
                &[&fixture.parent_resource, grant],
                service,
                &scope.tool,
                &args,
            ),
        }
    };
    let root_resources: Vec<_> = fixture
        .pins
        .scopes
        .iter()
        .map(|scope| witness(&fixture.parent, None, scope))
        .collect();
    let resource_refs: Vec<_> = fixture
        .pins
        .scopes
        .iter()
        .zip(&root_resources)
        .map(|(scope, proof)| EnrollmentResourceWitness {
            scope_id: &scope.scope_id,
            invocation: invocation(proof),
        })
        .collect();
    let mut tree = EnrollmentTree::bootstrap(
        &fixture.context,
        &fixture.pins,
        NOW,
        &RootEnrollmentProofs {
            activation: invocation(&activation),
            resources: &resource_refs,
        },
    )
    .unwrap();
    let mut children = Vec::new();
    for (child_signer, control, resource, is_sibling) in [
        (
            &fixture.child,
            &fixture.child_control,
            &fixture.child_resource,
            false,
        ),
        (&sibling, &sibling_control, &sibling_resource, true),
    ] {
        let parent_pins = if hierarchy && is_sibling {
            tree.retained_principal_pins(fixture.child.principal.as_str())
                .unwrap()
        } else {
            fixture.pins.clone()
        };
        let mut descriptor = child_descriptor(child_signer, control, resource, &parent_pins);
        if hierarchy && !is_sibling {
            descriptor.remaining_depth = 1;
        }
        descriptor.scopes = fixture
            .pins
            .scopes
            .iter()
            .map(|scope| ParticipantScopeGrant {
                scope_id: scope.scope_id.clone(),
                grant_id: *grant_id(resource.statement()).unwrap().as_bytes(),
            })
            .collect();
        if is_sibling {
            descriptor.enrollment_id = "sibling".to_owned();
            descriptor.delivery_channel = "sibling-channel".to_owned();
        }
        let parent = if hierarchy && is_sibling {
            chained(
                &[&fixture.root, &fixture.parent, &fixture.child],
                &[&fixture.parent_control, &fixture.child_control],
                PARTICIPANT_SERVICE,
                ENROLL_PARTICIPANT_TOOL,
                json!({"enrollment":descriptor}).as_object().unwrap(),
            )
        } else {
            fixture.parent_proof(&descriptor)
        };
        let child_signers: Vec<_> = if hierarchy && is_sibling {
            vec![&fixture.root, &fixture.parent, &fixture.child, child_signer]
        } else {
            vec![&fixture.root, &fixture.parent, child_signer]
        };
        let child_controls: Vec<_> = if hierarchy && is_sibling {
            vec![&fixture.parent_control, &fixture.child_control, control]
        } else {
            vec![&fixture.parent_control, control]
        };
        let child = chained(
            &child_signers,
            &child_controls,
            PARTICIPANT_SERVICE,
            ACCEPT_PARTICIPANT_TOOL,
            serde_json::json!({"enrollment_commitment":descriptor.commitment().unwrap()})
                .as_object()
                .unwrap(),
        );
        let proofs: Vec<_> = fixture
            .pins
            .scopes
            .iter()
            .map(|scope| witness(child_signer, Some(resource), scope))
            .collect();
        let resources: Vec<_> = fixture
            .pins
            .scopes
            .iter()
            .zip(&proofs)
            .map(|(scope, proof)| EnrollmentResourceWitness {
                scope_id: &scope.scope_id,
                invocation: invocation(proof),
            })
            .collect();
        tree.enroll(
            &fixture.context,
            parent_pins.enrollment_commitment,
            NOW,
            &ParticipantEnrollmentProofs {
                parent: invocation(&parent),
                child: invocation(&child),
                resources: &resources,
            },
        )
        .unwrap();
        children.push((parent_pins.enrollment_commitment, parent, child, proofs));
    }
    let action = if hierarchy && actor_seed == 0x55 {
        chained(
            &[&fixture.root, &fixture.parent, &fixture.child, &sibling],
            &[
                &fixture.parent_resource,
                &fixture.child_resource,
                &sibling_resource,
            ],
            service,
            tool,
            arguments,
        )
    } else {
        chained(
            &[
                &fixture.root,
                &fixture.parent,
                if actor_seed == 0x44 {
                    &fixture.child
                } else {
                    &sibling
                },
            ],
            &[
                &fixture.parent_resource,
                if actor_seed == 0x44 {
                    &fixture.child_resource
                } else {
                    &sibling_resource
                },
            ],
            service,
            tool,
            arguments,
        )
    };
    let withdrawal = fixture.withdraw_as_parent(fixture.pins.enrollment_commitment);
    EffectScopeFixture {
        root: fixture.pins,
        tree,
        context: fixture.context,
        action,
        activation,
        root_resources,
        children,
        withdrawal,
    }
}

pub(crate) fn effect_scope_fixture(
    recipe: &crate::CompiledRecipe,
    connection: &auths_connections::ConnectionRecord,
    arguments: &Map<String, Value>,
) -> EffectScopeFixture {
    effect_scope_fixture_for_actor(recipe, connection, arguments, 0x44)
}
