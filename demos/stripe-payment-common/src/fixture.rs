use std::sync::Arc;

use auths_author::{GrantRequest, plan_child_grant, prepare_action, prepare_grant};
use auths_codec::{action_id, body_digest, encode_bundle, evidence_id, grant_id, plan_id};
use auths_model::{
    AcceptedRegistries, ActionConstraint, ActionEnvelope, AssuranceClaimId, AssurancePolicy,
    AssurancePolicyId, AssuranceQuantifier, AssuranceRequirement, AudienceSet, AuthorizationPlan,
    BundleHeader, Challenge, ChannelBindingId, CompositionRequirement, ControlBinding,
    CriticalExtensions, EvidenceId, EvidenceObject, EvidenceTypeId, GrantStatement,
    GrantStatusSnapshot, MediaType, ParticipantRole, PermissionSet, PrincipalId, PrincipalMethodId,
    PrincipalStatusSnapshot, ProfilePolicyId, ProofBundle, ProofRef, ResourceId, ResourceMatcherId,
    SignatureBytes, SignatureDescriptor, SignatureSuiteId, StatementRef, StatusPolicy,
    StatusSnapshotId, Timestamp, TrustAnchor, TrustAnchorId, TrustedContext, ValidityWindow,
    VerificationMethod, VerifierLimits,
};
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_raw_key::{RAW_KEY_MEDIA_TYPE, RAW_KEY_V1, RawKeyDescriptor, RawKeyMethod, RawKeyType};
use auths_runtime::AuthsKernel;
use auths_sdk::{RequestContext, Verifier};
use auths_signature::{ED25519_V1, Ed25519Suite};
use ed25519_dalek::{Signer as _, SigningKey};

const HUMAN_SEED: [u8; 32] = [0x91; 32];
const WORKFLOW_SEED: [u8; 32] = [0x92; 32];
const AGENT_SEED: [u8; 32] = [0x93; 32];
const ASSURANCE_POLICY: &str = "raw-key-baseline";
const RESOURCE_MATCHER: &str = "uri-namespace-v1";
const PROFILE_POLICY: &str = "exact-v1";

/// One deterministic, exact-action Auths proof fixture.
pub struct AuthorizationFixture {
    /// Configured native verifier.
    pub verifier: Verifier,
    /// Encoded exact proof bundle.
    pub proof: Vec<u8>,
    /// Exact request context.
    pub request: RequestContext,
    /// Human/root identifier.
    pub human_principal: String,
    /// Workflow identifier.
    pub workflow_principal: String,
    /// Agent/actor identifier.
    pub agent_principal: String,
}

/// Builds a deterministic exact-action delegation using the action's own
/// profile, permission, body, audience, and requested budget.
///
/// The fixture is generic over canonical Auths mechanics only. It does not
/// interpret collection or authorization semantics.
///
/// # Panics
///
/// Panics only if repository-owned static fixture constants violate their
/// canonical Auths schemas.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "the fixture mirrors every signed Auths object explicitly"
)]
pub fn authorization_fixture(
    canonical: &auths_model::CanonicalAction,
    executor_audience: &str,
    trust_resource_namespace: &str,
    now: u64,
    challenge: [u8; 32],
) -> AuthorizationFixture {
    let human = Identity::new(HUMAN_SEED);
    let workflow = Identity::new(WORKFLOW_SEED);
    let agent = Identity::new(AGENT_SEED);
    let proof_ref = ProofRef::new([0x94; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let plan_identifier = plan_id(&plan).expect("static plan is canonical");
    let validity = ValidityWindow::new(Timestamp::new(now - 60), Timestamp::new(now + 300))
        .expect("static validity is ordered");
    let audience =
        auths_model::Audience::parse(executor_audience).expect("action already validated audience");
    let assurance_id =
        AssurancePolicyId::parse(ASSURANCE_POLICY).expect("static assurance identifier");
    let permissions =
        PermissionSet::new(vec![canonical.permission().clone()]).expect("one permission");
    let audiences = AudienceSet::new(vec![audience.clone()]).expect("one audience");
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
    let root_request =
        prepare_grant(root_statement, human.descriptor()).expect("static root grant is valid");
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
            budget.clone(),
            0,
            StatusPolicy::ExpiryOnly,
            assurance_id.clone(),
            CriticalExtensions::empty(),
        ),
    )
    .expect("child grant attenuates root");
    let child_request = prepare_grant(child_plan.into_statement(), workflow.descriptor())
        .expect("static child grant is valid");
    let child_signature = workflow.sign(child_request.signing_preimage());
    let child_grant = child_request.complete(child_signature);
    let terminal_grant = grant_id(child_grant.statement()).expect("canonical child grant");
    let envelope = ActionEnvelope::new(
        canonical.profile().clone(),
        canonical.media_type().clone(),
        body_digest(canonical.body()),
        canonical.permission().clone(),
        budget.clone(),
        audience.clone(),
        Challenge::new(challenge),
        validity,
        agent.principal.clone(),
        Some(terminal_grant),
        plan_identifier,
        ChannelBindingId::parse("none-v1").expect("static channel binding"),
        proof_ref,
        Vec::new(),
        CriticalExtensions::empty(),
    );
    let action_request =
        prepare_action(envelope, agent.descriptor()).expect("canonical action request");
    let action_signature = agent.sign(action_request.signing_preimage());
    let signed_action = action_request.complete(action_signature);
    let human_evidence = human.evidence();
    let workflow_evidence = workflow.evidence();
    let agent_evidence = agent.evidence();
    let bindings = vec![
        ControlBinding::new(
            StatementRef::Grant(grant_id(root_grant.statement()).expect("canonical root grant")),
            vec![human_evidence.id()],
        )
        .expect("one root binding"),
        ControlBinding::new(
            StatementRef::Grant(terminal_grant),
            vec![workflow_evidence.id()],
        )
        .expect("one workflow binding"),
        ControlBinding::new(
            StatementRef::Action(action_id(signed_action.envelope()).expect("canonical action")),
            vec![agent_evidence.id()],
        )
        .expect("one agent binding"),
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
    .expect("static proof bundle is valid");
    let assurance = AssurancePolicy::new(
        assurance_id.clone(),
        vec![
            AssuranceRequirement::new(
                ParticipantRole::Root,
                AssuranceQuantifier::Every,
                AssuranceClaimId::parse("self-certifying-identifier")
                    .expect("static assurance claim"),
                None,
            ),
            AssuranceRequirement::new(
                ParticipantRole::Actor,
                AssuranceQuantifier::Every,
                AssuranceClaimId::parse("self-certifying-identifier")
                    .expect("static assurance claim"),
                None,
            ),
        ],
    )
    .expect("static assurance policy");
    let anchor = TrustAnchor::new(
        TrustAnchorId::parse(human.principal.as_str()).expect("principal is an anchor id"),
        human.principal.clone(),
        vec![PrincipalMethodId::parse(RAW_KEY_V1).expect("static principal method")],
        vec![canonical.profile().clone()],
        PermissionSet::new(vec![canonical.permission().clone()]).expect("one permission"),
        vec![ResourceId::parse(trust_resource_namespace).expect("validated resource namespace")],
        AudienceSet::new(vec![audience.clone()]).expect("one audience"),
        validity,
        budget,
        2,
        assurance_id,
        StatusPolicy::ExpiryOnly,
    )
    .expect("static trust anchor");
    let registries = AcceptedRegistries::new(
        auths_registries::TARGET_V1_REGISTRY_MANIFEST,
        vec![PrincipalMethodId::parse(RAW_KEY_V1).expect("static method")],
        vec![SignatureSuiteId::parse(ED25519_V1).expect("static suite")],
        vec![EvidenceTypeId::parse(RAW_KEY_V1).expect("static evidence")],
        Vec::new(),
        Vec::new(),
        vec![
            AssuranceClaimId::parse("offline-verifiable").expect("static claim"),
            AssuranceClaimId::parse("self-certifying-identifier").expect("static claim"),
        ],
        Vec::new(),
        vec![ResourceMatcherId::parse(RESOURCE_MATCHER).expect("static matcher")],
        vec![
            auths_model::BudgetAlgebraId::parse("numeric-ceiling-v1")
                .expect("static budget algebra"),
        ],
        Vec::new(),
        vec![canonical.profile().clone()],
        vec![ProfilePolicyId::parse(PROFILE_POLICY).expect("static profile policy")],
    )
    .expect("static accepted registries");
    let context = TrustedContext::new(
        verifier_configuration(),
        CompositionRequirement::exact(plan_identifier),
        vec![anchor],
        registries,
        audience,
        Challenge::new(challenge),
        Timestamp::new(now),
        assurance,
        PrincipalStatusSnapshot::new(
            StatusSnapshotId::new([0x95; 32]),
            Timestamp::new(now - 60),
            Timestamp::new(now + 300),
            Vec::new(),
            Vec::new(),
        )
        .expect("static principal snapshot"),
        GrantStatusSnapshot::new(
            StatusSnapshotId::new([0x96; 32]),
            Timestamp::new(now - 60),
            Timestamp::new(now + 300),
            Vec::new(),
            Vec::new(),
        )
        .expect("static grant snapshot"),
        ResourceMatcherId::parse(RESOURCE_MATCHER).expect("static matcher"),
        ProfilePolicyId::parse(PROFILE_POLICY).expect("static policy"),
        ChannelBindingId::parse("none-v1").expect("static channel binding"),
        VerifierLimits::default(),
    )
    .expect("static verifier context");
    let methods: Vec<Box<dyn PrincipalMethod + Send + Sync>> =
        vec![Box::new(RawKeyMethod::new().expect("raw-key method"))];
    let suites: Vec<Box<dyn SignatureSuite + Send + Sync>> =
        vec![Box::new(Ed25519Suite::new().expect("ed25519 suite"))];
    let kernel = AuthsKernel::new(context, methods, suites).expect("static verifier kernel");
    AuthorizationFixture {
        verifier: Verifier::new(Arc::new(kernel)),
        proof: encode_bundle(&bundle).expect("canonical proof encoding"),
        request: RequestContext::new(executor_audience, challenge, now)
            .expect("validated request context"),
        human_principal: human.principal.to_string(),
        workflow_principal: workflow.principal.to_string(),
        agent_principal: agent.principal.to_string(),
    }
}

fn verifier_configuration() -> auths_model::VerifierConfigurationId {
    let method = RawKeyMethod::new().expect("raw-key method");
    let suite = Ed25519Suite::new().expect("ed25519 suite");
    auths_registries::ImmutableRegistries::new(
        &[&method as &dyn PrincipalMethod],
        &[&suite as &dyn SignatureSuite],
    )
    .expect("static registries")
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
        .expect("static raw key");
        let principal = raw.principal().expect("self-certifying principal");
        Self {
            signing,
            raw,
            principal,
        }
    }

    fn descriptor(&self) -> SignatureDescriptor {
        SignatureDescriptor::new(
            PrincipalMethodId::parse(RAW_KEY_V1).expect("static method"),
            VerificationMethod::parse(self.principal.as_str()).expect("principal method"),
            SignatureSuiteId::parse(ED25519_V1).expect("static suite"),
        )
    }

    fn sign(&self, preimage: &[u8]) -> SignatureBytes {
        SignatureBytes::new(self.signing.sign(preimage).to_bytes().to_vec())
            .expect("ed25519 signature length")
    }

    fn evidence(&self) -> EvidenceObject {
        let unaddressed = EvidenceObject::new(
            EvidenceId::new([0; 32]),
            EvidenceTypeId::parse(RAW_KEY_V1).expect("static evidence type"),
            MediaType::parse(RAW_KEY_MEDIA_TYPE).expect("static media type"),
            self.raw.encode(),
        )
        .expect("raw-key evidence");
        EvidenceObject::new(
            evidence_id(&unaddressed).expect("canonical evidence"),
            unaddressed.evidence_type().clone(),
            unaddressed.media_type().clone(),
            unaddressed.bytes().to_vec(),
        )
        .expect("addressed evidence")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_model::{
        BudgetAlgebraId, BudgetCeiling, CanonicalAction, CapabilityId, Permission, ProfileId,
        ProfileRef,
    };

    #[test]
    fn authorization_fixture_uses_the_real_auths_kernel() {
        let canonical = CanonicalAction::new(
            ProfileRef::new(ProfileId::parse("auths.stripe.fixture-test").unwrap(), 1).unwrap(),
            MediaType::parse("application/vnd.auths.stripe.fixture-test+json;version=1").unwrap(),
            br#"{"amount_minor":1}"#.to_vec(),
            Permission::new(
                CapabilityId::parse("stripe.fixture/test").unwrap(),
                ResourceId::parse("stripe-test://acct_fixture/orders/order-1").unwrap(),
            ),
            Some(BudgetCeiling::new(
                BudgetAlgebraId::parse("numeric-ceiling-v1").unwrap(),
                1,
            )),
        )
        .unwrap();
        let fixture = authorization_fixture(
            &canonical,
            "https://stripe-fixture.auths.dev",
            "stripe-test://acct_fixture/",
            1_800_000_000,
            [0x41; 32],
        );
        assert!(!fixture.proof.is_empty());
        assert_eq!(
            fixture.request.audience().as_str(),
            "https://stripe-fixture.auths.dev"
        );
    }
}
