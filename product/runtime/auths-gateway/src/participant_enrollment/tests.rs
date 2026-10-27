use super::*;
use crate::GatewayObserver;
use crate::harness::{self, Signer};
use crate::observed_tests::{Submission, submission_for};
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
const CONTROL_TOOLS: &[&str] = &[ENROLL_PARTICIPANT_TOOL, ACCEPT_PARTICIPANT_TOOL];

fn grant(
    issuer: &Signer,
    subject: &Signer,
    service: &str,
    tools: &[&str],
    parent: Option<GrantId>,
    depth: u16,
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
        harness::window(NOW - 100, NOW + 1000).unwrap(),
        AudienceSet::new(vec![Audience::parse(&format!("mcp://{service}")).unwrap()]).unwrap(),
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

fn chained(
    signers: &[&Signer],
    grants: &[&SignedGrant],
    service: &str,
    tool: &str,
    arguments: &Map<String, Value>,
) -> Submission {
    let mut signed = submission_for(
        signers[signers.len() - 2],
        signers[signers.len() - 1],
        grants.last().unwrap(),
        arguments,
        &[],
        service,
        tool,
        NOW,
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

fn invocation(signed: &Submission) -> EnrollmentInvocation<'_> {
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
        let root = Signer::new(0x11);
        let parent = Signer::new(0x22);
        let child = Signer::new(0x44);
        let observer = GatewayObserver::from_test_seed(0x33);
        let context = harness::context_for_profiles(
            &[&root],
            observer.principal(),
            None,
            NOW,
            2,
            CompositionRequirement::new(None, 1, 1, 1).unwrap(),
            &[auths_raw_key::RAW_KEY_V1],
            &[
                (PARTICIPANT_SERVICE, ENROLL_PARTICIPANT_TOOL),
                (PARTICIPANT_SERVICE, ACCEPT_PARTICIPANT_TOOL),
                (RESOURCE_SERVICE, RESOURCE_TOOL),
            ],
        )
        .unwrap();
        let parent_control = grant(&root, &parent, PARTICIPANT_SERVICE, CONTROL_TOOLS, None, 1);
        let child_control = grant(
            &parent,
            &child,
            PARTICIPANT_SERVICE,
            CONTROL_TOOLS,
            Some(grant_id(parent_control.statement()).unwrap()),
            0,
        );
        let parent_resource = grant(&root, &parent, RESOURCE_SERVICE, &[RESOURCE_TOOL], None, 1);
        let child_resource = grant(
            &parent,
            &child,
            RESOURCE_SERVICE,
            &[RESOURCE_TOOL],
            Some(grant_id(parent_resource.statement()).unwrap()),
            0,
        );
        let pins = parent_pins(&parent, &parent_control, &parent_resource);
        let enrollment = child_descriptor(&child, &child_control, &child_resource, &pins);
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
        permitted_channels: BTreeSet::from(["agent-b-channel".to_owned()]),
        scopes: vec![EnrollmentScopePins {
            scope_id: "project-a-read".to_owned(),
            parent_grant: grant_id(parent_resource.statement()).unwrap(),
            service: RESOURCE_SERVICE.to_owned(),
            tool: RESOURCE_TOOL.to_owned(),
            resource_argument: "record_id".to_owned(),
            resource_handle: "record-a".to_owned(),
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
fn native_enrollment_binds_child_acceptance_to_every_descriptor_field() {
    let fixture = Fixture::new();
    let resource = fixture.resource_proof("record-a");
    let mut changed = fixture.enrollment.clone();
    changed.child_instance_generation += 1;
    assert_eq!(
        fixture
            .verify(&changed, &fixture.enrollment, &resource)
            .unwrap_err(),
        ParticipantEnrollmentError::Acceptance
    );
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
    let direct = grant(
        &fixture.root,
        &fixture.child,
        RESOURCE_SERVICE,
        &[RESOURCE_TOOL],
        None,
        0,
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
