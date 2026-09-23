use super::*;
use auths_codec::{action_signing_preimage, encode_bundle, evidence_id};
use auths_model::{
    EvidenceTypeId, MediaType, PrincipalMethodId, SignatureBytes, SignatureDescriptor,
    SignatureEnvelope, SignatureSuiteId, Timestamp, VerificationMethod,
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
        canonical,
        &audience,
        [7; 32],
        ValidityWindow::new(Timestamp::new(1_000), Timestamp::new(2_000)).expect("window"),
        required,
        &approvers,
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
