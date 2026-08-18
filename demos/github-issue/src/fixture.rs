use std::sync::Arc;

use auths_author::{GrantRequest, plan_child_grant, prepare_action, prepare_grant};
use auths_codec::{action_id, body_digest, encode_bundle, evidence_id, grant_id, plan_id};
use auths_github::{
    ExactGitHubAction, GitHubIssueProfile,
    canonical::sha256,
    ports::{ExactActionAuthorizer, ProofAuthorization, ProofError},
};
use auths_model::{
    AcceptedRegistries, ActionConstraint, ActionEnvelope, AssuranceClaimId, AssurancePolicy,
    AssurancePolicyId, AssuranceQuantifier, AssuranceRequirement, AudienceSet, AuthorizationPlan,
    BudgetAlgebraId, BudgetCeiling, BundleHeader, CapabilityId, Challenge, ChannelBindingId,
    CompositionRequirement, ControlBinding, CriticalExtensions, EvidenceId, EvidenceObject,
    EvidenceTypeId, GrantStatement, GrantStatusSnapshot, MediaType, ParticipantRole, Permission,
    PermissionSet, PrincipalId, PrincipalMethodId, PrincipalStatusSnapshot, ProfilePolicyId,
    ProofBundle, ProofRef, ResourceId, ResourceMatcherId, SignatureBytes, SignatureDescriptor,
    SignatureSuiteId, StatementRef, StatusPolicy, StatusSnapshotId, Timestamp, TrustAnchor,
    TrustAnchorId, TrustedContext, ValidityWindow, VerificationMethod, VerifierLimits,
};
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_profile_api::ActionProfile as _;
use auths_raw_key::{RAW_KEY_MEDIA_TYPE, RAW_KEY_V1, RawKeyDescriptor, RawKeyMethod, RawKeyType};
use auths_runtime::AuthsKernel;
use auths_sdk::{RequestContext, Verifier, VerifyResult};
use auths_signature::{ED25519_V1, Ed25519Suite};
use ed25519_dalek::{Signer as _, SigningKey};

const ASSURANCE_POLICY: &str = "raw-key-baseline";
const RESOURCE_MATCHER: &str = "uri-namespace-v1";
const PROFILE_POLICY: &str = "exact-v1";

/// Executor-owned workflow authority. Seeds never leave the native service.
pub struct EphemeralAuthsAuthorizer {
    human: [u8; 32],
    workflow: [u8; 32],
    agent: [u8; 32],
}

impl EphemeralAuthsAuthorizer {
    /// Creates one per-session authority.
    #[must_use]
    pub const fn new(human_seed: [u8; 32], workflow_seed: [u8; 32], agent_seed: [u8; 32]) -> Self {
        Self {
            human: human_seed,
            workflow: workflow_seed,
            agent: agent_seed,
        }
    }

    /// Returns the concrete principal receiving the session authority.
    ///
    /// # Errors
    ///
    /// Returns an adapter failure if the generated Ed25519 key cannot form a
    /// raw-key principal.
    pub fn agent_principal(&self) -> Result<PrincipalId, ProofError> {
        Ok(Identity::new(self.agent)?.principal)
    }
}

impl ExactActionAuthorizer for EphemeralAuthsAuthorizer {
    fn authorize(
        &self,
        action: &ExactGitHubAction,
        now: u64,
    ) -> Result<ProofAuthorization, ProofError> {
        let action_digest = action.digest().map_err(|_| ProofError::Adapter)?;
        let challenge: [u8; 32] = hex::decode(action_digest.as_str())
            .map_err(|_| ProofError::Adapter)?
            .try_into()
            .map_err(|_| ProofError::Adapter)?;
        let fixture = authorization_fixture(
            action,
            now,
            challenge,
            self.human,
            self.workflow,
            self.agent,
        )?;
        let canonical = GitHubIssueProfile
            .canonicalize(&action.canonical_bytes().map_err(|_| ProofError::Adapter)?)
            .map_err(|_| ProofError::Adapter)?;
        match fixture
            .verifier
            .verify(
                &fixture.proof,
                &canonical,
                &fixture.request,
                &GitHubIssueProfile,
            )
            .map_err(|_| ProofError::Adapter)?
        {
            VerifyResult::Authorized(authorized) => Ok(ProofAuthorization {
                context_digest: auths_github::DigestHex::from_digest_bytes(
                    *authorized.verified().context_digest().as_bytes(),
                ),
                proof_digest: sha256(&fixture.proof),
                authorized: *authorized,
            }),
            VerifyResult::Denied(_) => Err(ProofError::Denied),
            VerifyResult::Indeterminate(_) => Err(ProofError::Indeterminate),
        }
    }
}

struct AuthorizationFixture {
    verifier: Verifier,
    proof: Vec<u8>,
    request: RequestContext,
}

#[allow(
    clippy::too_many_lines,
    reason = "the fixture mirrors every signed Auths object and trust input"
)]
fn authorization_fixture(
    action: &ExactGitHubAction,
    now: u64,
    challenge: [u8; 32],
    human_seed: [u8; 32],
    workflow_seed: [u8; 32],
    agent_seed: [u8; 32],
) -> Result<AuthorizationFixture, ProofError> {
    let canonical = GitHubIssueProfile
        .canonicalize(&action.canonical_bytes().map_err(|_| ProofError::Adapter)?)
        .map_err(|_| ProofError::Adapter)?;
    let human = Identity::new(human_seed)?;
    let workflow = Identity::new(workflow_seed)?;
    let agent = Identity::new(agent_seed)?;
    let proof_ref = ProofRef::new([0x61; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let plan_identifier = plan_id(&plan).map_err(|_| ProofError::Adapter)?;
    let validity = ValidityWindow::new(
        Timestamp::new(now.saturating_sub(60)),
        Timestamp::new(now + 300),
    )
    .map_err(|_| ProofError::Adapter)?;
    let audience = auths_model::Audience::parse(action.executor_audience().as_str())
        .map_err(|_| ProofError::Adapter)?;
    let assurance_id =
        AssurancePolicyId::parse(ASSURANCE_POLICY).map_err(|_| ProofError::Adapter)?;
    let permissions = both_permissions(canonical.permission())?;
    let audiences = AudienceSet::new(vec![audience.clone()]).map_err(|_| ProofError::Adapter)?;
    let root_budget = Some(BudgetCeiling::new(
        BudgetAlgebraId::parse("numeric-ceiling-v1").map_err(|_| ProofError::Adapter)?,
        2,
    ));
    let root_grant_statement = GrantStatement::new(
        human.principal.clone(),
        workflow.principal.clone(),
        canonical.profile().clone(),
        permissions.clone(),
        validity,
        audiences.clone(),
        ActionConstraint::AnyBody,
        root_budget.clone(),
        1,
        None,
        StatusPolicy::ExpiryOnly,
        assurance_id.clone(),
        CriticalExtensions::empty(),
    );
    let root_grant_request = prepare_grant(root_grant_statement, human.descriptor()?)
        .map_err(|_| ProofError::Adapter)?;
    let root_grant_signature = human.sign(root_grant_request.signing_preimage())?;
    let root_grant = root_grant_request.complete(root_grant_signature);
    let child_plan = plan_child_grant(
        root_grant.statement(),
        GrantRequest::new(
            agent.principal.clone(),
            canonical.profile().clone(),
            PermissionSet::new(vec![canonical.permission().clone()])
                .map_err(|_| ProofError::Adapter)?,
            validity,
            audiences,
            ActionConstraint::ExactBodyDigest(body_digest(canonical.body())),
            canonical.requested_budget().cloned(),
            0,
            StatusPolicy::ExpiryOnly,
            assurance_id.clone(),
            CriticalExtensions::empty(),
        ),
    )
    .map_err(|_| ProofError::Adapter)?;
    let child_grant_request = prepare_grant(child_plan.into_statement(), workflow.descriptor()?)
        .map_err(|_| ProofError::Adapter)?;
    let child_grant_signature = workflow.sign(child_grant_request.signing_preimage())?;
    let child_grant = child_grant_request.complete(child_grant_signature);
    let terminal_grant = grant_id(child_grant.statement()).map_err(|_| ProofError::Adapter)?;
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
        ChannelBindingId::parse("none-v1").map_err(|_| ProofError::Adapter)?,
        proof_ref,
        Vec::new(),
        CriticalExtensions::empty(),
    );
    let action_request =
        prepare_action(envelope, agent.descriptor()?).map_err(|_| ProofError::Adapter)?;
    let action_signature = agent.sign(action_request.signing_preimage())?;
    let signed_action = action_request.complete(action_signature);
    let human_evidence = human.evidence()?;
    let workflow_evidence = workflow.evidence()?;
    let agent_evidence = agent.evidence()?;
    let bindings = vec![
        ControlBinding::new(
            StatementRef::Grant(grant_id(root_grant.statement()).map_err(|_| ProofError::Adapter)?),
            vec![human_evidence.id()],
        )
        .map_err(|_| ProofError::Adapter)?,
        ControlBinding::new(
            StatementRef::Grant(terminal_grant),
            vec![workflow_evidence.id()],
        )
        .map_err(|_| ProofError::Adapter)?,
        ControlBinding::new(
            StatementRef::Action(
                action_id(signed_action.envelope()).map_err(|_| ProofError::Adapter)?,
            ),
            vec![agent_evidence.id()],
        )
        .map_err(|_| ProofError::Adapter)?,
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
    .map_err(|_| ProofError::Adapter)?;
    let assurance = AssurancePolicy::new(
        assurance_id.clone(),
        vec![
            AssuranceRequirement::new(
                ParticipantRole::Root,
                AssuranceQuantifier::Every,
                AssuranceClaimId::parse("self-certifying-identifier")
                    .map_err(|_| ProofError::Adapter)?,
                None,
            ),
            AssuranceRequirement::new(
                ParticipantRole::Actor,
                AssuranceQuantifier::Every,
                AssuranceClaimId::parse("self-certifying-identifier")
                    .map_err(|_| ProofError::Adapter)?,
                None,
            ),
        ],
    )
    .map_err(|_| ProofError::Adapter)?;
    let namespace = format!(
        "github://repositories/{}",
        action.repository().repository_id()
    );
    let anchor = TrustAnchor::new(
        TrustAnchorId::parse(human.principal.as_str()).map_err(|_| ProofError::Adapter)?,
        human.principal.clone(),
        vec![PrincipalMethodId::parse(RAW_KEY_V1).map_err(|_| ProofError::Adapter)?],
        vec![canonical.profile().clone()],
        permissions,
        vec![ResourceId::parse(&namespace).map_err(|_| ProofError::Adapter)?],
        AudienceSet::new(vec![audience.clone()]).map_err(|_| ProofError::Adapter)?,
        validity,
        root_budget,
        2,
        assurance_id,
        StatusPolicy::ExpiryOnly,
    )
    .map_err(|_| ProofError::Adapter)?;
    let configuration = verifier_configuration()?;
    let registries = AcceptedRegistries::new(
        auths_registries::TARGET_V1_REGISTRY_MANIFEST,
        vec![PrincipalMethodId::parse(RAW_KEY_V1).map_err(|_| ProofError::Adapter)?],
        vec![SignatureSuiteId::parse(ED25519_V1).map_err(|_| ProofError::Adapter)?],
        vec![EvidenceTypeId::parse(RAW_KEY_V1).map_err(|_| ProofError::Adapter)?],
        Vec::new(),
        Vec::new(),
        vec![
            AssuranceClaimId::parse("offline-verifiable").map_err(|_| ProofError::Adapter)?,
            AssuranceClaimId::parse("self-certifying-identifier")
                .map_err(|_| ProofError::Adapter)?,
        ],
        Vec::new(),
        vec![ResourceMatcherId::parse(RESOURCE_MATCHER).map_err(|_| ProofError::Adapter)?],
        vec![BudgetAlgebraId::parse("numeric-ceiling-v1").map_err(|_| ProofError::Adapter)?],
        Vec::new(),
        vec![canonical.profile().clone()],
        vec![ProfilePolicyId::parse(PROFILE_POLICY).map_err(|_| ProofError::Adapter)?],
    )
    .map_err(|_| ProofError::Adapter)?;
    let context = TrustedContext::new(
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
            Timestamp::new(now.saturating_sub(60)),
            Timestamp::new(now + 300),
            Vec::new(),
            Vec::new(),
        )
        .map_err(|_| ProofError::Adapter)?,
        GrantStatusSnapshot::new(
            StatusSnapshotId::new([0x64; 32]),
            Timestamp::new(now.saturating_sub(60)),
            Timestamp::new(now + 300),
            Vec::new(),
            Vec::new(),
        )
        .map_err(|_| ProofError::Adapter)?,
        ResourceMatcherId::parse(RESOURCE_MATCHER).map_err(|_| ProofError::Adapter)?,
        ProfilePolicyId::parse(PROFILE_POLICY).map_err(|_| ProofError::Adapter)?,
        ChannelBindingId::parse("none-v1").map_err(|_| ProofError::Adapter)?,
        VerifierLimits::default(),
    )
    .map_err(|_| ProofError::Adapter)?;
    let methods: Vec<Box<dyn PrincipalMethod + Send + Sync>> = vec![Box::new(
        RawKeyMethod::new().map_err(|_| ProofError::Adapter)?,
    )];
    let suites: Vec<Box<dyn SignatureSuite + Send + Sync>> = vec![Box::new(
        Ed25519Suite::new().map_err(|_| ProofError::Adapter)?,
    )];
    let kernel = AuthsKernel::new(context, methods, suites).map_err(|_| ProofError::Adapter)?;
    Ok(AuthorizationFixture {
        verifier: Verifier::new(Arc::new(kernel)),
        proof: encode_bundle(&bundle).map_err(|_| ProofError::Adapter)?,
        request: RequestContext::new(action.executor_audience().as_str(), challenge, now)
            .map_err(|_| ProofError::Adapter)?,
    })
}

fn both_permissions(permission: &Permission) -> Result<PermissionSet, ProofError> {
    let other_capability =
        if permission.capability().as_str() == auths_github::types::BRANCH_CAPABILITY {
            auths_github::types::PULL_REQUEST_CAPABILITY
        } else {
            auths_github::types::BRANCH_CAPABILITY
        };
    PermissionSet::new(vec![
        permission.clone(),
        Permission::new(
            CapabilityId::parse(other_capability).map_err(|_| ProofError::Adapter)?,
            permission.resource().clone(),
        ),
    ])
    .map_err(|_| ProofError::Adapter)
}

fn verifier_configuration() -> Result<auths_model::VerifierConfigurationId, ProofError> {
    let method = RawKeyMethod::new().map_err(|_| ProofError::Adapter)?;
    let suite = Ed25519Suite::new().map_err(|_| ProofError::Adapter)?;
    auths_registries::ImmutableRegistries::new(
        &[&method as &dyn PrincipalMethod],
        &[&suite as &dyn SignatureSuite],
    )
    .map(|registries| registries.configuration_id())
    .map_err(|_| ProofError::Adapter)
}

struct Identity {
    signing: SigningKey,
    raw: RawKeyDescriptor,
    principal: PrincipalId,
}

impl Identity {
    fn new(seed: [u8; 32]) -> Result<Self, ProofError> {
        let signing = SigningKey::from_bytes(&seed);
        let raw = RawKeyDescriptor::new(
            RawKeyType::Ed25519,
            signing.verifying_key().to_bytes().to_vec(),
        )
        .map_err(|_| ProofError::Adapter)?;
        let principal = raw.principal().map_err(|_| ProofError::Adapter)?;
        Ok(Self {
            signing,
            raw,
            principal,
        })
    }

    fn descriptor(&self) -> Result<SignatureDescriptor, ProofError> {
        Ok(SignatureDescriptor::new(
            PrincipalMethodId::parse(RAW_KEY_V1).map_err(|_| ProofError::Adapter)?,
            VerificationMethod::parse(self.principal.as_str()).map_err(|_| ProofError::Adapter)?,
            SignatureSuiteId::parse(ED25519_V1).map_err(|_| ProofError::Adapter)?,
        ))
    }

    fn sign(&self, preimage: &[u8]) -> Result<SignatureBytes, ProofError> {
        SignatureBytes::new(self.signing.sign(preimage).to_bytes().to_vec())
            .map_err(|_| ProofError::Adapter)
    }

    fn evidence(&self) -> Result<EvidenceObject, ProofError> {
        let unaddressed = EvidenceObject::new(
            EvidenceId::new([0; 32]),
            EvidenceTypeId::parse(RAW_KEY_V1).map_err(|_| ProofError::Adapter)?,
            MediaType::parse(RAW_KEY_MEDIA_TYPE).map_err(|_| ProofError::Adapter)?,
            self.raw.encode(),
        )
        .map_err(|_| ProofError::Adapter)?;
        EvidenceObject::new(
            evidence_id(&unaddressed).map_err(|_| ProofError::Adapter)?,
            unaddressed.evidence_type().clone(),
            unaddressed.media_type().clone(),
            unaddressed.bytes().to_vec(),
        )
        .map_err(|_| ProofError::Adapter)
    }
}
