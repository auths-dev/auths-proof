use super::*;
use auths_codec::{
    action_signing_preimage, approval_signing_preimage, encode_bundle, evidence_id, plan_id,
};
use auths_model::{
    EvidenceTypeId, MediaType, PrincipalMethodId, SignatureBytes, SignatureDescriptor,
    SignatureEnvelope, SignatureSuiteId, Timestamp, ValidityWindow, VerificationMethod,
};
use auths_profile_api::ActionProfile as _;
use auths_profile_mcp::{McpProfile, McpToolCall};
use auths_raw_key::{RAW_KEY_MEDIA_TYPE, RAW_KEY_V1, RawKeyDescriptor, RawKeyType};
use ed25519_dalek::{Signer as _, SigningKey};

struct Member {
    key: SigningKey,
    raw: RawKeyDescriptor,
    principal: PrincipalId,
}

impl Member {
    fn new(seed: u8) -> Self {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let raw =
            RawKeyDescriptor::new(RawKeyType::Ed25519, key.verifying_key().to_bytes().to_vec())
                .expect("raw key");
        let principal = raw.principal().expect("principal");
        Self {
            key,
            raw,
            principal,
        }
    }

    fn actor(&self) -> QuorumActor {
        QuorumActor::new(self.principal.clone(), None).expect("actor")
    }

    fn descriptor(&self) -> SignatureDescriptor {
        SignatureDescriptor::new(
            PrincipalMethodId::parse(RAW_KEY_V1).expect("method"),
            VerificationMethod::parse(self.principal.as_str()).expect("verification method"),
            SignatureSuiteId::parse(auths_signature::ED25519_V1).expect("suite"),
        )
    }

    fn evidence(&self) -> EvidenceObject {
        let object = |id| {
            EvidenceObject::new(
                id,
                EvidenceTypeId::parse(RAW_KEY_V1).expect("type"),
                MediaType::parse(RAW_KEY_MEDIA_TYPE).expect("media"),
                self.raw.encode(),
            )
            .expect("evidence")
        };
        object(evidence_id(&object(EvidenceId::new([0; 32]))).expect("evidence ID"))
    }

    fn sign_action(&self, envelope: &ActionEnvelope) -> QuorumAction {
        let descriptor = self.descriptor();
        let preimage = action_signing_preimage(envelope, &descriptor).expect("preimage");
        let signature =
            SignatureBytes::new(self.key.sign(&preimage).to_bytes().to_vec()).expect("signature");
        QuorumAction::new(
            SignedAction::new(
                envelope.clone(),
                SignatureEnvelope::new(descriptor, signature),
            ),
            Vec::new(),
            vec![self.evidence()],
        )
        .expect("action")
    }

    fn approve(&self, quorum: &QuorumProposal) -> SignedApproval {
        let statement = quorum.statement(&self.principal).expect("listed").clone();
        self.approve_statement(statement, quorum.canonical().profile())
    }

    fn approve_statement(
        &self,
        statement: ApprovalStatement,
        profile: &auths_model::ProfileRef,
    ) -> SignedApproval {
        let descriptor = self.descriptor();
        let preimage =
            approval_signing_preimage(&statement, &descriptor, profile).expect("preimage");
        let signature =
            SignatureBytes::new(self.key.sign(&preimage).to_bytes().to_vec()).expect("signature");
        SignedApproval::new(
            statement,
            SignatureEnvelope::new(descriptor, signature),
            vec![self.evidence()],
        )
        .expect("approval")
    }
}

fn refund() -> (CanonicalAction, Audience) {
    let arguments = serde_json::json!({"amount_minor": 4200, "charge": "ch_quorum_0001"});
    let call = McpToolCall::new(
        "payments",
        "refund_v1",
        arguments.as_object().expect("object").clone(),
    )
    .expect("call");
    let canonical = McpProfile
        .canonicalize(&call.canonical_bytes().expect("bytes"))
        .expect("canonical");
    (canonical, call.audience().expect("audience"))
}

fn proposal(
    required: u16,
    actor: &Member,
    members: &[&Member],
) -> Result<QuorumProposal, QuorumError> {
    let (canonical, audience) = refund();
    let approvers: Vec<_> = members
        .iter()
        .map(|member| member.principal.clone())
        .collect();
    QuorumProposal::new(
        canonical,
        &audience,
        [7; 32],
        1_000,
        None,
        required,
        &approvers,
        &actor.actor(),
    )
}

#[test]
fn impossible_thresholds_duplicates_and_self_approval_are_refused() {
    let (actor, a, b) = (Member::new(10), Member::new(1), Member::new(2));
    assert_eq!(
        proposal(0, &actor, &[&a, &b]).err(),
        Some(QuorumError::InvalidQuorum)
    );
    assert_eq!(
        proposal(3, &actor, &[&a, &b]).err(),
        Some(QuorumError::InvalidQuorum)
    );
    assert_eq!(
        proposal(1, &actor, &[]).err(),
        Some(QuorumError::InvalidQuorum)
    );
    assert_eq!(
        proposal(2, &actor, &[&a, &a]).err(),
        Some(QuorumError::DuplicateApprover)
    );
    assert_eq!(
        proposal(1, &actor, &[&a, &actor]).err(),
        Some(QuorumError::SelfApproval),
        "the actor's own approval would never count"
    );
    let many: Vec<_> = (1..=17).map(Member::new).collect();
    let refs: Vec<_> = many.iter().collect();
    assert_eq!(
        proposal(2, &actor, &refs).err(),
        Some(QuorumError::InvalidQuorum)
    );
}

#[test]
fn every_statement_binds_the_action_and_the_requirement() {
    let (actor, a, b, c) = (
        Member::new(10),
        Member::new(1),
        Member::new(2),
        Member::new(3),
    );
    let quorum = proposal(2, &actor, &[&a, &b, &c]).expect("proposal");
    let requirement = quorum.requirement();
    assert_eq!(requirement.threshold(), 2);
    assert_eq!(requirement.approvers().len(), 3);
    assert_eq!(
        quorum.requirement_id(),
        approval_requirement_id(requirement).expect("requirement ID")
    );
    assert!(matches!(
        quorum.plan().as_ref(),
        auths_model::AuthorizationPlanRef::Proof(_)
    ));
    let envelope = quorum.envelope();
    assert_eq!(envelope.actor(), &actor.principal);
    assert_eq!(
        envelope.authorization_plan(),
        plan_id(quorum.plan()).expect("plan ID")
    );
    assert_eq!(quorum.statements().len(), 3);
    for statement in quorum.statements() {
        assert_eq!(statement.requirement(), quorum.requirement_id());
        assert_eq!(statement.body_digest(), envelope.canonical_body_digest());
        assert_eq!(statement.media_type(), envelope.body_media_type());
        assert_eq!(statement.permission(), envelope.permission());
        assert_eq!(statement.requested_budget(), envelope.requested_budget());
        assert_eq!(statement.audience(), envelope.audience());
        assert_eq!(statement.challenge(), envelope.challenge());
        assert_eq!(statement.validity(), envelope.validity());
        assert_eq!(statement.attributes(), None);
    }
    let again = proposal(2, &actor, &[&c, &a, &b]).expect("reordered proposal");
    assert_eq!(
        again.requirement(),
        quorum.requirement(),
        "the requirement is canonical in approver order"
    );
    assert_eq!(again.statements(), quorum.statements());
}

#[test]
fn any_threshold_of_distinct_listed_approvers_assembles() {
    let (actor, a, b, c, x) = (
        Member::new(10),
        Member::new(1),
        Member::new(2),
        Member::new(3),
        Member::new(9),
    );
    let quorum = proposal(2, &actor, &[&a, &b, &c]).expect("proposal");
    let action = actor.sign_action(quorum.envelope());

    assert_eq!(
        quorum.assemble(&action, &[a.approve(&quorum)]).err(),
        Some(QuorumError::Incomplete {
            approved: 1,
            required: 2
        })
    );
    assert_eq!(
        quorum
            .assemble(&action, &[a.approve(&quorum), a.approve(&quorum)])
            .err(),
        Some(QuorumError::DuplicateApproval)
    );
    let other = proposal(2, &actor, &[&a, &b, &x]).expect("other proposal");
    assert_eq!(
        quorum
            .assemble(&action, &[a.approve(&quorum), x.approve(&other)])
            .err(),
        Some(QuorumError::UnknownApproval),
        "an approver the proposal does not list"
    );
    assert_eq!(
        quorum
            .assemble(&action, &[a.approve(&quorum), b.approve(&other)])
            .err(),
        Some(QuorumError::UnknownApproval),
        "a listed approver's approval for another requirement"
    );
    let (canonical, audience) = refund();
    let later = QuorumProposal::new(
        canonical,
        &audience,
        [7; 32],
        1_000,
        Some(3_600),
        2,
        &[
            a.principal.clone(),
            b.principal.clone(),
            c.principal.clone(),
        ],
        &actor.actor(),
    )
    .expect("proposal with another window");
    let stray = actor.sign_action(later.envelope());
    assert_eq!(
        quorum
            .assemble(&stray, &[a.approve(&quorum), b.approve(&quorum)])
            .err(),
        Some(QuorumError::ActionMismatch)
    );

    for pair in [[&a, &b], [&a, &c], [&b, &c]] {
        let bundle = quorum
            .assemble(&action, &pair.map(|member| member.approve(&quorum)))
            .expect("any two of three");
        assert_eq!(bundle.actions().len(), 1);
        assert_eq!(bundle.approvals().len(), 2);
    }
    let forward = quorum
        .assemble(
            &action,
            &[a.approve(&quorum), b.approve(&quorum), c.approve(&quorum)],
        )
        .expect("bundle");
    let reversed = quorum
        .assemble(
            &action,
            &[c.approve(&quorum), b.approve(&quorum), a.approve(&quorum)],
        )
        .expect("bundle");
    assert_eq!(
        forward.approvals().len(),
        3,
        "every matching approval is carried"
    );
    assert_eq!(
        encode_bundle(&forward).expect("bytes"),
        encode_bundle(&reversed).expect("bytes"),
        "assembly is independent of approval arrival order"
    );
}

#[test]
fn validity_defaults_to_a_day_and_is_bounded_to_a_week() {
    let (canonical, audience) = refund();
    let (actor, a) = (Member::new(10), Member::new(1));
    let window = |seconds| {
        QuorumProposal::new(
            canonical.clone(),
            &audience,
            [7; 32],
            1_000,
            seconds,
            1,
            std::slice::from_ref(&a.principal),
            &actor.actor(),
        )
        .map(|quorum| quorum.envelope().validity())
    };
    let expected =
        |until| ValidityWindow::new(Timestamp::new(1_000), Timestamp::new(until)).expect("window");
    assert_eq!(DEFAULT_QUORUM_VALIDITY_SECONDS, 86_400);
    assert_eq!(MAX_QUORUM_VALIDITY_SECONDS, 604_800);
    assert_eq!(window(None), Ok(expected(1_000 + 86_400)));
    assert_eq!(window(Some(3_600)), Ok(expected(1_000 + 3_600)));
    assert_eq!(window(Some(604_800)), Ok(expected(1_000 + 604_800)));
    assert_eq!(window(Some(0)).err(), Some(QuorumError::ActionValidity));
    assert_eq!(
        window(Some(604_801)).err(),
        Some(QuorumError::ActionValidity)
    );
}

#[test]
fn validity_is_cut_to_the_actor_grant_expiry() {
    use auths_model::{
        ActionConstraint, AssurancePolicyId, AudienceSet, CriticalExtensions, PermissionSet,
        StatusPolicy,
    };
    let (canonical, audience) = refund();
    let (root, actor, a) = (Member::new(1), Member::new(2), Member::new(3));
    let statement = auths_model::GrantStatement::new(
        root.principal.clone(),
        actor.principal.clone(),
        canonical.profile().clone(),
        PermissionSet::new(vec![canonical.permission().clone()]).expect("permissions"),
        ValidityWindow::new(Timestamp::new(0), Timestamp::new(1_010)).expect("window"),
        AudienceSet::new(vec![audience.clone()]).expect("audiences"),
        ActionConstraint::AnyBody,
        None,
        0,
        None,
        StatusPolicy::ExpiryOnly,
        AssurancePolicyId::parse("quorum-test").expect("assurance"),
        CriticalExtensions::empty(),
    );
    let descriptor = root.descriptor();
    let preimage = auths_codec::grant_signing_preimage(&statement, &descriptor).expect("preimage");
    let signature =
        SignatureBytes::new(root.key.sign(&preimage).to_bytes().to_vec()).expect("signature");
    let grant = SignedGrant::new(statement, SignatureEnvelope::new(descriptor, signature));
    let quorum = QuorumProposal::new(
        canonical,
        &audience,
        [7; 32],
        1_000,
        Some(86_400),
        1,
        std::slice::from_ref(&a.principal),
        &QuorumActor::new(actor.principal.clone(), Some(&grant)).expect("actor"),
    )
    .expect("proposal");
    let expected =
        ValidityWindow::new(Timestamp::new(1_000), Timestamp::new(1_010)).expect("window");
    assert_eq!(quorum.envelope().validity(), expected);
    assert!(
        quorum
            .statements()
            .iter()
            .all(|statement| statement.validity() == expected)
    );
    assert_eq!(
        quorum.envelope().terminal_grant(),
        Some(grant_id(grant.statement()).expect("grant ID"))
    );
}
