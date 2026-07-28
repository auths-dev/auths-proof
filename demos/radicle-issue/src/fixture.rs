use std::sync::Arc;

use auths_author::{GrantRequest, plan_child_grant, prepare_action, prepare_grant};
use auths_codec::{action_id, body_digest, encode_bundle, evidence_id, grant_id, plan_id};
use auths_model::{
    AcceptedRegistries, ActionConstraint, ActionEnvelope, AssuranceClaimId, AssurancePolicy,
    AssurancePolicyId, AssuranceQuantifier, AssuranceRequirement, AudienceSet, AuthorizationPlan,
    BudgetAlgebraId, BudgetCeiling, BundleHeader, Challenge, ChannelBindingId,
    CompositionRequirement, ControlBinding, CriticalExtensions, EvidenceId, EvidenceObject,
    EvidenceTypeId, GrantStatement, GrantStatusSnapshot, MediaType, ParticipantRole, PermissionSet,
    PrincipalId, PrincipalMethodId, PrincipalStatusSnapshot, ProfilePolicyId, ProofBundle,
    ProofRef, ResourceId, ResourceMatcherId, SignatureBytes, SignatureDescriptor, SignatureSuiteId,
    StatementRef, StatusPolicy, StatusSnapshotId, Timestamp, TrustAnchor, TrustAnchorId,
    ValidityWindow, VerificationMethod, VerifierContext, VerifierLimits,
};
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_profile_api::ActionProfile as _;
use auths_radicle::{OpenPatchActionV1, RadiclePatchProfile};
use auths_raw_key::{RAW_KEY_MEDIA_TYPE, RAW_KEY_V1, RawKeyDescriptor, RawKeyMethod, RawKeyType};
use auths_runtime::AuthsKernel;
use auths_sdk::{RequestContext, Verifier};
use auths_signature::{ED25519_V1, Ed25519Suite};
use ed25519_dalek::{Signer as _, SigningKey};

const HUMAN_SEED: [u8; 32] = [0x51; 32];
const WORKFLOW_SEED: [u8; 32] = [0x53; 32];
const AGENT_SEED: [u8; 32] = [0x52; 32];
const ASSURANCE_POLICY: &str = "raw-key-baseline";
const RESOURCE_MATCHER: &str = "uri-namespace-v1";
const PROFILE_POLICY: &str = "exact-v1";

pub struct AuthorizationFixture {
    pub verifier: Verifier,
    pub proof: Vec<u8>,
    pub request: RequestContext,
    pub human_principal: String,
    pub workflow_principal: String,
    pub agent_principal: String,
}

/// Builds one deterministic two-party Auths delegation fixture.
///
/// # Panics
///
/// Panics only if repository-owned identifiers, keys, or exact profile bytes
/// violate the protocol model. Tests and service startup exercise this path.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "the fixture mirrors every Auths signed object and trust input explicitly"
)]
pub fn authorization_fixture(
    action: &OpenPatchActionV1,
    now: u64,
    challenge: [u8; 32],
) -> AuthorizationFixture {
    authorization_fixture_with_seeds(
        action,
        now,
        challenge,
        HUMAN_SEED,
        WORKFLOW_SEED,
        AGENT_SEED,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the fixture mirrors every Auths signed object and trust input explicitly"
)]
pub(crate) fn authorization_fixture_with_seeds(
    action: &OpenPatchActionV1,
    now: u64,
    challenge: [u8; 32],
    human_seed: [u8; 32],
    workflow_seed: [u8; 32],
    agent_seed: [u8; 32],
) -> AuthorizationFixture {
    let canonical = RadiclePatchProfile
        .canonicalize(&action.canonical_bytes().unwrap())
        .unwrap();
    let human = Identity::new(human_seed);
    let workflow = Identity::new(workflow_seed);
    let agent = Identity::new(agent_seed);
    let proof_ref = ProofRef::new([0x61; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let plan_identifier = plan_id(&plan).unwrap();
    let validity =
        ValidityWindow::new(Timestamp::new(now - 60), Timestamp::new(now + 300)).unwrap();
    let audience = auths_model::Audience::parse(action.executor_audience().as_str()).unwrap();
    let assurance_id = AssurancePolicyId::parse(ASSURANCE_POLICY).unwrap();
    let permissions = PermissionSet::new(vec![canonical.permission().clone()]).unwrap();
    let audiences = AudienceSet::new(vec![audience.clone()]).unwrap();
    let budget = canonical.requested_budget().cloned();
    let root_grant_statement = GrantStatement::new(
        human.principal.clone(),
        workflow.principal.clone(),
        canonical.profile().clone(),
        permissions.clone(),
        validity,
        audiences.clone(),
        ActionConstraint::AnyBody,
        budget.clone(),
        1,
        None,
        StatusPolicy::ExpiryOnly,
        assurance_id.clone(),
        CriticalExtensions::empty(),
    );
    let root_grant_request = prepare_grant(root_grant_statement, human.descriptor()).unwrap();
    let root_grant_signature = human.sign(root_grant_request.signing_preimage());
    let root_grant = root_grant_request.complete(root_grant_signature);
    let child_plan = plan_child_grant(
        root_grant.statement(),
        GrantRequest::new(
            agent.principal.clone(),
            canonical.profile().clone(),
            permissions,
            validity,
            audiences,
            ActionConstraint::ExactBodyDigest(body_digest(canonical.body())),
            budget,
            0,
            StatusPolicy::ExpiryOnly,
            assurance_id.clone(),
            CriticalExtensions::empty(),
        ),
    )
    .unwrap();
    let child_grant_request =
        prepare_grant(child_plan.into_statement(), workflow.descriptor()).unwrap();
    let child_grant_signature = workflow.sign(child_grant_request.signing_preimage());
    let child_grant = child_grant_request.complete(child_grant_signature);
    let terminal_grant = grant_id(child_grant.statement()).unwrap();
    let envelope = ActionEnvelope::new(
        canonical.profile().clone(),
        canonical.media_type().clone(),
        body_digest(canonical.body()),
        canonical.permission().clone(),
        canonical.requested_budget().cloned(),
        audience.clone(),
        Challenge::new(challenge),
        validity,
        agent.principal.clone(),
        Some(terminal_grant),
        plan_identifier,
        ChannelBindingId::parse("none-v1").unwrap(),
        proof_ref,
        Vec::new(),
        CriticalExtensions::empty(),
    );
    let action_request = prepare_action(envelope, agent.descriptor()).unwrap();
    let action_signature = agent.sign(action_request.signing_preimage());
    let signed_action = action_request.complete(action_signature);
    let human_evidence = human.evidence();
    let workflow_evidence = workflow.evidence();
    let agent_evidence = agent.evidence();
    let bindings = vec![
        ControlBinding::new(
            StatementRef::Grant(grant_id(root_grant.statement()).unwrap()),
            vec![human_evidence.id()],
        )
        .unwrap(),
        ControlBinding::new(
            StatementRef::Grant(terminal_grant),
            vec![workflow_evidence.id()],
        )
        .unwrap(),
        ControlBinding::new(
            StatementRef::Action(action_id(signed_action.envelope()).unwrap()),
            vec![agent_evidence.id()],
        )
        .unwrap(),
    ];
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        vec![root_grant, child_grant],
        vec![signed_action],
        plan,
        vec![human_evidence, workflow_evidence, agent_evidence],
        bindings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .unwrap();
    let assurance = AssurancePolicy::new(
        assurance_id.clone(),
        vec![
            AssuranceRequirement::new(
                ParticipantRole::Root,
                AssuranceQuantifier::Every,
                AssuranceClaimId::parse("self-certifying-identifier").unwrap(),
                None,
            ),
            AssuranceRequirement::new(
                ParticipantRole::Actor,
                AssuranceQuantifier::Every,
                AssuranceClaimId::parse("self-certifying-identifier").unwrap(),
                None,
            ),
        ],
    )
    .unwrap();
    let namespace = format!("radicle://{}", action.rid());
    let anchor = TrustAnchor::new(
        TrustAnchorId::parse(human.principal.as_str()).unwrap(),
        human.principal.clone(),
        vec![PrincipalMethodId::parse(RAW_KEY_V1).unwrap()],
        vec![canonical.profile().clone()],
        PermissionSet::new(vec![canonical.permission().clone()]).unwrap(),
        vec![ResourceId::parse(&namespace).unwrap()],
        AudienceSet::new(vec![audience.clone()]).unwrap(),
        validity,
        Some(BudgetCeiling::new(
            BudgetAlgebraId::parse("numeric-ceiling-v1").unwrap(),
            1,
        )),
        2,
        assurance_id,
        StatusPolicy::ExpiryOnly,
    )
    .unwrap();
    let configuration = verifier_configuration();
    let registries = AcceptedRegistries::new(
        auths_registries::TARGET_V1_REGISTRY_MANIFEST,
        vec![PrincipalMethodId::parse(RAW_KEY_V1).unwrap()],
        vec![SignatureSuiteId::parse(ED25519_V1).unwrap()],
        vec![EvidenceTypeId::parse(RAW_KEY_V1).unwrap()],
        Vec::new(),
        Vec::new(),
        vec![
            AssuranceClaimId::parse("offline-verifiable").unwrap(),
            AssuranceClaimId::parse("self-certifying-identifier").unwrap(),
        ],
        Vec::new(),
        vec![ResourceMatcherId::parse(RESOURCE_MATCHER).unwrap()],
        vec![BudgetAlgebraId::parse("numeric-ceiling-v1").unwrap()],
        Vec::new(),
        vec![canonical.profile().clone()],
        vec![ProfilePolicyId::parse(PROFILE_POLICY).unwrap()],
    )
    .unwrap();
    let context = VerifierContext::new(
        configuration,
        CompositionRequirement::exact(plan_identifier),
        vec![anchor],
        registries,
        audience,
        Challenge::new(challenge),
        Timestamp::new(now),
        assurance,
        PrincipalStatusSnapshot::new(
            StatusSnapshotId::new([0x63; 32]),
            Timestamp::new(now - 60),
            Timestamp::new(now + 300),
            Vec::new(),
            Vec::new(),
        )
        .unwrap(),
        GrantStatusSnapshot::new(
            StatusSnapshotId::new([0x64; 32]),
            Timestamp::new(now - 60),
            Timestamp::new(now + 300),
            Vec::new(),
            Vec::new(),
        )
        .unwrap(),
        ResourceMatcherId::parse(RESOURCE_MATCHER).unwrap(),
        ProfilePolicyId::parse(PROFILE_POLICY).unwrap(),
        ChannelBindingId::parse("none-v1").unwrap(),
        VerifierLimits::default(),
    )
    .unwrap();
    let methods: Vec<Box<dyn PrincipalMethod + Send + Sync>> =
        vec![Box::new(RawKeyMethod::new().unwrap())];
    let suites: Vec<Box<dyn SignatureSuite + Send + Sync>> =
        vec![Box::new(Ed25519Suite::new().unwrap())];
    let kernel = AuthsKernel::new(context, methods, suites).unwrap();
    AuthorizationFixture {
        verifier: Verifier::new(Arc::new(kernel)),
        proof: encode_bundle(&bundle).unwrap(),
        request: RequestContext::new(action.executor_audience().as_str(), challenge, now).unwrap(),
        human_principal: human.principal.to_string(),
        workflow_principal: workflow.principal.to_string(),
        agent_principal: agent.principal.to_string(),
    }
}

fn verifier_configuration() -> auths_model::VerifierConfigurationId {
    let method = RawKeyMethod::new().unwrap();
    let suite = Ed25519Suite::new().unwrap();
    auths_registries::ImmutableRegistries::new(
        &[&method as &dyn PrincipalMethod],
        &[&suite as &dyn SignatureSuite],
    )
    .unwrap()
    .configuration_id()
}

struct Identity {
    signing: SigningKey,
    raw: RawKeyDescriptor,
    principal: PrincipalId,
}

impl Identity {
    fn new(seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let raw = RawKeyDescriptor::new(
            RawKeyType::Ed25519,
            signing.verifying_key().to_bytes().to_vec(),
        )
        .unwrap();
        let principal = raw.principal().unwrap();
        Self {
            signing,
            raw,
            principal,
        }
    }

    fn descriptor(&self) -> SignatureDescriptor {
        SignatureDescriptor::new(
            PrincipalMethodId::parse(RAW_KEY_V1).unwrap(),
            VerificationMethod::parse(self.principal.as_str()).unwrap(),
            SignatureSuiteId::parse(ED25519_V1).unwrap(),
        )
    }

    fn sign(&self, preimage: &[u8]) -> SignatureBytes {
        SignatureBytes::new(self.signing.sign(preimage).to_bytes().to_vec()).unwrap()
    }

    fn evidence(&self) -> EvidenceObject {
        let unaddressed = EvidenceObject::new(
            EvidenceId::new([0; 32]),
            EvidenceTypeId::parse(RAW_KEY_V1).unwrap(),
            MediaType::parse(RAW_KEY_MEDIA_TYPE).unwrap(),
            self.raw.encode(),
        )
        .unwrap();
        EvidenceObject::new(
            evidence_id(&unaddressed).unwrap(),
            unaddressed.evidence_type().clone(),
            unaddressed.media_type().clone(),
            unaddressed.bytes().to_vec(),
        )
        .unwrap()
    }
}
