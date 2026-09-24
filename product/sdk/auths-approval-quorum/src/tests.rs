use super::*;
use auths_codec::{action_signing_preimage, encode_bundle, evidence_id};
use auths_model::{
    EvidenceTypeId, MediaType, PrincipalMethodId, SignatureBytes, SignatureDescriptor,
    SignatureEnvelope, SignatureSuiteId, VerificationMethod,
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

    fn approver(&self) -> QuorumApprover {
        QuorumApprover::new(self.principal.clone(), None).expect("approver")
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

    fn approve(&self, envelope: &ActionEnvelope) -> QuorumApproval {
        let descriptor = SignatureDescriptor::new(
            PrincipalMethodId::parse(RAW_KEY_V1).expect("method"),
            VerificationMethod::parse(self.principal.as_str()).expect("verification method"),
            SignatureSuiteId::parse(auths_signature::ED25519_V1).expect("suite"),
        );
        let preimage = action_signing_preimage(envelope, &descriptor).expect("preimage");
        let signature =
            SignatureBytes::new(self.key.sign(&preimage).to_bytes().to_vec()).expect("signature");
        QuorumApproval::new(
            SignedAction::new(
                envelope.clone(),
                SignatureEnvelope::new(descriptor, signature),
            ),
            Vec::new(),
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

fn proposal(required: u16, members: &[&Member]) -> Result<QuorumProposal, QuorumError> {
    let (canonical, audience) = refund();
    let approvers: Vec<_> = members.iter().map(|member| member.approver()).collect();
    QuorumProposal::new(
        canonical, &audience, [7; 32], 1_000, None, required, &approvers,
    )
}

#[test]
fn impossible_thresholds_and_duplicate_approvers_are_refused() {
    let (a, b) = (Member::new(1), Member::new(2));
    assert_eq!(
        proposal(0, &[&a, &b]).err(),
        Some(QuorumError::InvalidQuorum)
    );
    assert_eq!(
        proposal(3, &[&a, &b]).err(),
        Some(QuorumError::InvalidQuorum)
    );
    assert_eq!(proposal(1, &[]).err(), Some(QuorumError::InvalidQuorum));
    assert_eq!(
        proposal(2, &[&a, &a]).err(),
        Some(QuorumError::DuplicateApprover)
    );
    let many: Vec<_> = (1..=17).map(Member::new).collect();
    let refs: Vec<_> = many.iter().collect();
    assert_eq!(proposal(2, &refs).err(), Some(QuorumError::InvalidQuorum));
}

#[test]
fn every_envelope_shares_the_action_and_the_threshold_plan() {
    let (a, b, c) = (Member::new(1), Member::new(2), Member::new(3));
    let quorum = proposal(2, &[&a, &b, &c]).expect("proposal");
    let plan = plan_id(quorum.plan()).expect("plan ID");
    let shape = quorum
        .plan()
        .validate(&VerifierLimits::default_deployment())
        .expect("shape");
    assert_eq!(shape.leaves().len(), 3);
    assert!(matches!(
        quorum.plan().as_ref(),
        auths_model::AuthorizationPlanRef::KOfN { k: 2, members } if members.len() == 3
    ));
    let first = &quorum.envelopes()[0];
    let mut references = BTreeSet::new();
    for (envelope, member) in quorum.envelopes().iter().zip([&a, &b, &c]) {
        assert_eq!(envelope.authorization_plan(), plan);
        assert_eq!(envelope.actor(), &member.principal);
        assert_eq!(
            envelope.canonical_body_digest(),
            first.canonical_body_digest()
        );
        assert_eq!(envelope.challenge(), first.challenge());
        assert_eq!(envelope.validity(), first.validity());
        assert!(shape.leaves().contains(&envelope.proof_ref()));
        references.insert(envelope.proof_ref());
    }
    assert_eq!(references.len(), 3);
    let again = proposal(2, &[&c, &a, &b]).expect("reordered proposal");
    assert_eq!(
        again.plan(),
        quorum.plan(),
        "plan is canonical in member order"
    );
}

#[test]
fn assembly_needs_one_exact_approval_per_listed_approver() {
    let (a, b, c, x) = (
        Member::new(1),
        Member::new(2),
        Member::new(3),
        Member::new(9),
    );
    let quorum = proposal(2, &[&a, &b, &c]).expect("proposal");
    let [ea, eb, ec] = [0, 1, 2].map(|index| quorum.envelopes()[index].clone());

    assert_eq!(
        quorum.assemble(&[a.approve(&ea), b.approve(&eb)]).err(),
        Some(QuorumError::Incomplete {
            signed: 2,
            approvers: 3
        })
    );
    assert_eq!(
        quorum
            .assemble(&[a.approve(&ea), a.approve(&ea), b.approve(&eb)])
            .err(),
        Some(QuorumError::DuplicateApproval)
    );
    let other = proposal(2, &[&a, &b, &x]).expect("other proposal");
    assert_eq!(
        quorum
            .assemble(&[
                a.approve(&ea),
                b.approve(&eb),
                x.approve(&other.envelopes()[2])
            ])
            .err(),
        Some(QuorumError::UnknownApproval)
    );

    let forward = quorum
        .assemble(&[a.approve(&ea), b.approve(&eb), c.approve(&ec)])
        .expect("bundle");
    let reversed = quorum
        .assemble(&[c.approve(&ec), b.approve(&eb), a.approve(&ea)])
        .expect("bundle");
    assert_eq!(forward.actions().len(), 3);
    assert_eq!(forward.bindings().len(), 3);
    assert_eq!(
        encode_bundle(&forward).expect("bytes"),
        encode_bundle(&reversed).expect("bytes"),
        "assembly is independent of approval arrival order"
    );
}

#[test]
fn quorum_requirement_counts_distinct_actors() {
    let requirement = quorum_requirement(2, 1).expect("requirement");
    assert_eq!(requirement.expected_plan(), None);
    assert_eq!(requirement.minimum_authorized_branches(), 2);
    assert_eq!(requirement.minimum_distinct_actors(), 2);
    assert_eq!(requirement.minimum_distinct_roots(), 1);
    assert!(quorum_requirement(0, 1).is_err());
    assert!(quorum_requirement(2, 3).is_err());
}

#[test]
fn validity_follows_the_single_signer_rule() {
    let (canonical, audience) = refund();
    let a = Member::new(1);
    let window = |seconds| {
        QuorumProposal::new(
            canonical.clone(),
            &audience,
            [7; 32],
            1_000,
            seconds,
            1,
            &[a.approver()],
        )
        .map(|quorum| quorum.envelopes()[0].validity())
    };
    let expected =
        |until| ValidityWindow::new(Timestamp::new(1_000), Timestamp::new(until)).expect("window");
    assert_eq!(
        window(None),
        Ok(expected(1_000 + DEFAULT_ACTION_VALIDITY_SECONDS))
    );
    assert_eq!(
        window(Some(MAX_ACTION_VALIDITY_SECONDS)),
        Ok(expected(1_000 + MAX_ACTION_VALIDITY_SECONDS))
    );
    assert_eq!(window(Some(0)).err(), Some(QuorumError::ActionValidity));
    assert_eq!(
        window(Some(MAX_ACTION_VALIDITY_SECONDS + 1)).err(),
        Some(QuorumError::ActionValidity)
    );
}

#[test]
fn validity_is_cut_to_the_earliest_approver_grant_expiry() {
    use auths_model::{
        ActionConstraint, AssurancePolicyId, AudienceSet, CriticalExtensions, PermissionSet,
        StatusPolicy,
    };
    let (canonical, audience) = refund();
    let (root, a, b) = (Member::new(1), Member::new(2), Member::new(3));
    let grant = |subject: &Member, expires_at| {
        let statement = auths_model::GrantStatement::new(
            root.principal.clone(),
            subject.principal.clone(),
            canonical.profile().clone(),
            PermissionSet::new(vec![canonical.permission().clone()]).expect("permissions"),
            ValidityWindow::new(Timestamp::new(0), Timestamp::new(expires_at)).expect("window"),
            AudienceSet::new(vec![audience.clone()]).expect("audiences"),
            ActionConstraint::AnyBody,
            None,
            0,
            None,
            StatusPolicy::ExpiryOnly,
            AssurancePolicyId::parse("quorum-test").expect("assurance"),
            CriticalExtensions::empty(),
        );
        let descriptor = SignatureDescriptor::new(
            PrincipalMethodId::parse(RAW_KEY_V1).expect("method"),
            VerificationMethod::parse(root.principal.as_str()).expect("verification method"),
            SignatureSuiteId::parse(auths_signature::ED25519_V1).expect("suite"),
        );
        let preimage =
            auths_codec::grant_signing_preimage(&statement, &descriptor).expect("preimage");
        let signature =
            SignatureBytes::new(root.key.sign(&preimage).to_bytes().to_vec()).expect("signature");
        SignedGrant::new(statement, SignatureEnvelope::new(descriptor, signature))
    };
    let (early, late) = (grant(&a, 1_010), grant(&b, 5_000));
    let approvers = [
        QuorumApprover::new(a.principal.clone(), Some(&early)).expect("approver"),
        QuorumApprover::new(b.principal.clone(), Some(&late)).expect("approver"),
    ];
    let quorum = QuorumProposal::new(
        canonical,
        &audience,
        [7; 32],
        1_000,
        Some(300),
        2,
        &approvers,
    )
    .expect("proposal");
    let expected =
        ValidityWindow::new(Timestamp::new(1_000), Timestamp::new(1_010)).expect("window");
    assert!(
        quorum
            .envelopes()
            .iter()
            .all(|envelope| envelope.validity() == expected)
    );
    assert_eq!(
        quorum.envelopes()[0].terminal_grant(),
        Some(grant_id(early.statement()).expect("grant ID"))
    );
}
