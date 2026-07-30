//! Repository-owned Auths issuer fixture for short-lived demo grants.

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
use auths_profile_api::ActionProfile;
use auths_raw_key::{RAW_KEY_MEDIA_TYPE, RAW_KEY_V1, RawKeyDescriptor, RawKeyMethod, RawKeyType};
use auths_runtime::AuthsKernel;
use auths_sdk::{RequestContext, Verifier};
use auths_signature::{ED25519_V1, Ed25519Suite};
use ed25519_dalek::{Signer as _, SigningKey};

const HUMAN_SEED: [u8; 32] = [0xa1; 32];
const WORKFLOW_SEED: [u8; 32] = [0xa2; 32];
const AGENT_SEED: [u8; 32] = [0xa3; 32];
const ASSURANCE_POLICY: &str = "raw-key-baseline";
const RESOURCE_MATCHER: &str = "uri-namespace-v1";
const PROFILE_POLICY: &str = "exact-v1";

pub struct AuthorizationFixture {
    pub verifier: Verifier,
    pub proof: Vec<u8>,
    pub request: RequestContext,
    pub human_principal: String,
    pub agent_principal: String,
}

/// Issues one exact, short-lived Auths action proof for any records profile.
///
/// This demo issuer is deliberately separate from request verification. The
/// returned verifier has an immutable context and does not call back to the
/// issuer.
///
/// # Panics
///
/// Panics only if the repository-owned fixture constants or the already
/// canonicalized action violate an Auths constructor invariant. CI exercises
/// these fixed inputs for both records profiles.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "every signed object and trust input remains explicit"
)]
pub fn authorization_fixture<P: ActionProfile>(
    profile: &P,
    canonical_action_bytes: &[u8],
    executor_audience: &str,
    namespace: &str,
    now: u64,
    challenge: [u8; 32],
) -> AuthorizationFixture {
    let canonical = profile.canonicalize(canonical_action_bytes).unwrap();
    let human = Identity::new(HUMAN_SEED);
    let workflow = Identity::new(WORKFLOW_SEED);
    let agent = Identity::new(AGENT_SEED);
    let proof_ref = ProofRef::new([0xa4; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let plan_identifier = plan_id(&plan).unwrap();
    let validity =
        ValidityWindow::new(Timestamp::new(now - 60), Timestamp::new(now + 300)).unwrap();
    let audience = auths_model::Audience::parse(executor_audience).unwrap();
    let assurance_id = AssurancePolicyId::parse(ASSURANCE_POLICY).unwrap();
    let permissions = PermissionSet::new(vec![canonical.permission().clone()]).unwrap();
    let audiences = AudienceSet::new(vec![audience.clone()]).unwrap();
    let budget = canonical.requested_budget().cloned();

    let root_statement = GrantStatement::new(
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
    let root_request = prepare_grant(root_statement, human.descriptor()).unwrap();
    let root_signature = human.sign(root_request.signing_preimage());
    let root_grant = root_request.complete(root_signature);
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
    let child_request = prepare_grant(child_plan.into_statement(), workflow.descriptor()).unwrap();
    let child_signature = workflow.sign(child_request.signing_preimage());
    let child_grant = child_request.complete(child_signature);
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
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        vec![root_grant.clone(), child_grant],
        vec![signed_action.clone()],
        plan,
        vec![
            human_evidence.clone(),
            workflow_evidence.clone(),
            agent_evidence.clone(),
        ],
        vec![
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
        ],
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
    let anchor = TrustAnchor::new(
        TrustAnchorId::parse(human.principal.as_str()).unwrap(),
        human.principal.clone(),
        vec![PrincipalMethodId::parse(RAW_KEY_V1).unwrap()],
        vec![canonical.profile().clone()],
        PermissionSet::new(vec![canonical.permission().clone()]).unwrap(),
        vec![ResourceId::parse(&format!("records://{namespace}")).unwrap()],
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
        verifier_configuration(),
        CompositionRequirement::exact(plan_identifier),
        vec![anchor],
        registries,
        audience,
        Challenge::new(challenge),
        Timestamp::new(now),
        assurance,
        PrincipalStatusSnapshot::new(
            StatusSnapshotId::new([0xa5; 32]),
            Timestamp::new(now - 60),
            Timestamp::new(now + 300),
            Vec::new(),
            Vec::new(),
        )
        .unwrap(),
        GrantStatusSnapshot::new(
            StatusSnapshotId::new([0xa6; 32]),
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
        request: RequestContext::new(executor_audience, challenge, now).unwrap(),
        human_principal: human.principal.to_string(),
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
