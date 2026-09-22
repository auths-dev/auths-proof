//! Sign-then-verify against the kernel, with a test-only `did:key` signer.
//!
//! The verifier under test receives its principal methods as a parameter. The
//! multi-method case shows that enabling another method is configuration, and
//! that the enabled set is bound by the trusted context.

use crate::action::{GitSignatureAction, RepositoryId, SIGN_COMMIT, SIGN_TAG};
use crate::envelope::GitSignatureEnvelope;
use crate::object::{ObjectKind, UnsignedPayload};
use crate::program::VerifyStatus;
use crate::sign::{Delegation, DelegationLink, GitProofSigner, SignError, sign_payload};
use crate::verify::{GitTrust, GitVerification, verify_object, verify_signature};
use auths_author::prepare_grant;
use auths_did_key::{DID_KEY_MEDIA_TYPE, DID_KEY_V1, DidKeyEvidence, DidKeyMethod};
use auths_model::{
    AcceptedRegistries, ActionConstraint, AssuranceClaimId, AssurancePolicy, AssurancePolicyId,
    Audience, AudienceSet, CapabilityId, Challenge, ChannelBindingId, CompositionRequirement,
    CriticalExtensions, EvidenceObject, EvidenceTypeId, GrantStatement, GrantStatusSnapshot,
    MediaType, Permission, PermissionSet, PrincipalId, PrincipalMethodId, PrincipalStatusSnapshot,
    ProfilePolicyId, ResourceId, ResourceMatcherId, SignatureBytes, SignatureDescriptor,
    SignatureSuiteId, SignedGrant, StatusPolicy, StatusSnapshotId, Timestamp, TrustAnchor,
    TrustAnchorId, TrustedContext, ValidityWindow, VerifierLimits,
};
use auths_multikey::{Multikey, MultikeyType};
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_raw_key::RawKeyMethod;
use auths_registries::ImmutableRegistries;
use auths_signature::{ED25519_V1, Ed25519Suite};
use ed25519_dalek::{Signer as _, SigningKey};

const REPOSITORY: &str = "github.com/acme/app";
const NOW: u64 = 1_790_000_000;
const COMMIT: &[u8] = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor Agent <a@example.invalid> 1790000000 +0000\ncommitter Agent <a@example.invalid> 1790000000 +0000\n\nsigned by an agent\n";
const TAG: &[u8] = b"object 1111111111111111111111111111111111111111\ntype commit\ntag v1.0.0\ntagger Agent <a@example.invalid> 1790000000 +0000\n\nrelease\n";
const ASSURANCE: &str = "git-signing-test-v1";

struct DidKeySigner {
    key: SigningKey,
    evidence: DidKeyEvidence,
}

impl DidKeySigner {
    fn new(seed: u8) -> Self {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let multikey = Multikey::from_public_key(
            MultikeyType::Ed25519,
            key.verifying_key().to_bytes().to_vec(),
        )
        .expect("multikey");
        Self {
            key,
            evidence: DidKeyEvidence::new(multikey),
        }
    }
}

impl GitProofSigner for DidKeySigner {
    fn principal(&self) -> PrincipalId {
        self.evidence.principal().expect("principal")
    }

    fn descriptor(&self) -> SignatureDescriptor {
        SignatureDescriptor::new(
            PrincipalMethodId::parse(DID_KEY_V1).expect("method"),
            self.evidence
                .verification_method()
                .expect("verification method"),
            SignatureSuiteId::parse(ED25519_V1).expect("suite"),
        )
    }

    fn control_evidence(&self) -> Vec<EvidenceObject> {
        vec![self.single_evidence()]
    }

    fn sign(&self, preimage: &[u8]) -> Result<SignatureBytes, SignError> {
        SignatureBytes::new(self.key.sign(preimage).to_bytes().to_vec())
            .map_err(|_| SignError::Signer)
    }
}

impl DidKeySigner {
    fn single_evidence(&self) -> EvidenceObject {
        auths_author::address_evidence(
            EvidenceTypeId::parse(DID_KEY_V1).expect("evidence type"),
            MediaType::parse(DID_KEY_MEDIA_TYPE).expect("media type"),
            self.evidence.encode().expect("evidence"),
        )
        .expect("addressed evidence")
    }
}

fn repository() -> RepositoryId {
    RepositoryId::parse(REPOSITORY).expect("repository")
}

fn audience() -> Audience {
    Audience::parse(&repository().audience()).expect("audience")
}

fn permission(capability: &str, collection: &str) -> Permission {
    Permission::new(
        CapabilityId::parse(capability).expect("capability"),
        ResourceId::parse(&format!("git://{REPOSITORY}/{collection}")).expect("resource"),
    )
}

fn window(from: u64, until: u64) -> ValidityWindow {
    ValidityWindow::new(Timestamp::new(from), Timestamp::new(until)).expect("window")
}

fn profile() -> auths_model::ProfileRef {
    GitSignatureAction::for_payload(
        &repository(),
        &UnsignedPayload::parse(COMMIT.to_vec()).expect("payload"),
    )
    .expect("action")
    .canonical_action()
    .expect("canonical")
    .profile()
    .clone()
}

/// A root-to-agent grant with the given permissions and validity.
fn delegate(
    root: &DidKeySigner,
    agent: &DidKeySigner,
    permissions: Vec<Permission>,
    validity: ValidityWindow,
) -> Delegation {
    let statement = GrantStatement::new(
        root.principal(),
        agent.principal(),
        profile(),
        PermissionSet::new(permissions).expect("permissions"),
        validity,
        AudienceSet::new(vec![audience()]).expect("audiences"),
        ActionConstraint::AnyBody,
        None,
        0,
        None,
        StatusPolicy::ExpiryOnly,
        AssurancePolicyId::parse(ASSURANCE).expect("assurance"),
        CriticalExtensions::empty(),
    );
    let request = prepare_grant(statement, root.descriptor()).expect("grant request");
    let signature = root
        .sign(request.signing_preimage())
        .expect("grant signature");
    let grant: SignedGrant = request.complete(signature);
    Delegation::new(vec![DelegationLink::new(grant, root.single_evidence())]).expect("chain")
}

fn full_delegation(root: &DidKeySigner, agent: &DidKeySigner) -> Delegation {
    delegate(
        root,
        agent,
        vec![
            permission(SIGN_COMMIT, "commits"),
            permission(SIGN_TAG, "tags"),
        ],
        window(NOW - 3_600, NOW + 86_400),
    )
}

/// Trust pinned to `root`, accepting exactly the methods in `methods`.
fn trust(root: &DidKeySigner, methods: &[&dyn PrincipalMethod]) -> GitTrust {
    let suite = Ed25519Suite::new().expect("suite");
    let configuration = ImmutableRegistries::new(methods, &[&suite as &dyn SignatureSuite])
        .expect("registries")
        .configuration_id();
    let method_ids: Vec<PrincipalMethodId> =
        methods.iter().map(|method| method.id().clone()).collect();
    let evidence_types: Vec<EvidenceTypeId> = method_ids
        .iter()
        .map(|id| EvidenceTypeId::parse(id.as_str()).expect("evidence type"))
        .collect();
    let assurance_id = AssurancePolicyId::parse(ASSURANCE).expect("assurance");
    let anchor = TrustAnchor::new(
        TrustAnchorId::parse(root.principal().as_str()).expect("anchor id"),
        root.principal(),
        vec![PrincipalMethodId::parse(DID_KEY_V1).expect("method")],
        vec![profile()],
        PermissionSet::new(vec![
            permission(SIGN_COMMIT, "commits"),
            permission(SIGN_TAG, "tags"),
        ])
        .expect("permissions"),
        vec![ResourceId::parse(&format!("git://{REPOSITORY}/")).expect("namespace")],
        AudienceSet::new(vec![audience()]).expect("audiences"),
        window(NOW - 86_400, NOW + 365 * 86_400),
        None,
        1,
        assurance_id.clone(),
        StatusPolicy::ExpiryOnly,
    )
    .expect("anchor");
    let registries = AcceptedRegistries::new(
        auths_registries::TARGET_V1_REGISTRY_MANIFEST,
        method_ids,
        vec![SignatureSuiteId::parse(ED25519_V1).expect("suite id")],
        evidence_types,
        Vec::new(),
        Vec::new(),
        vec![
            AssuranceClaimId::parse("offline-verifiable").expect("claim"),
            AssuranceClaimId::parse("self-certifying-identifier").expect("claim"),
        ],
        Vec::new(),
        vec![ResourceMatcherId::parse("uri-namespace-v1").expect("matcher")],
        Vec::new(),
        Vec::new(),
        vec![profile()],
        vec![ProfilePolicyId::parse("exact-v1").expect("policy")],
    )
    .expect("accepted registries");
    let context = TrustedContext::new(
        configuration,
        CompositionRequirement::new(None, 1, 1, 1).expect("composition"),
        vec![anchor],
        registries,
        audience(),
        Challenge::new([0; 32]),
        Timestamp::new(NOW),
        AssurancePolicy::new(assurance_id, Vec::new()).expect("assurance policy"),
        PrincipalStatusSnapshot::new(
            StatusSnapshotId::new([0x63; 32]),
            Timestamp::new(NOW - 86_400),
            Timestamp::new(NOW + 365 * 86_400),
            Vec::new(),
            Vec::new(),
        )
        .expect("principal status"),
        GrantStatusSnapshot::new(
            StatusSnapshotId::new([0x64; 32]),
            Timestamp::new(NOW - 86_400),
            Timestamp::new(NOW + 365 * 86_400),
            Vec::new(),
            Vec::new(),
        )
        .expect("grant status"),
        ResourceMatcherId::parse("uri-namespace-v1").expect("matcher"),
        ProfilePolicyId::parse("exact-v1").expect("policy"),
        ChannelBindingId::parse("none-v1").expect("channel"),
        VerifierLimits::default(),
    )
    .expect("context");
    let encoded = auths_codec::encode_verifier_context(&context).expect("encode trust");
    GitTrust::decode(&encoded).expect("trust round-trips through its canonical bytes")
}

struct World {
    root: DidKeySigner,
    agent: DidKeySigner,
    did_key: DidKeyMethod,
    suite: Ed25519Suite,
}

impl World {
    fn new() -> Self {
        Self {
            root: DidKeySigner::new(0x11),
            agent: DidKeySigner::new(0x22),
            did_key: DidKeyMethod::new().expect("did:key"),
            suite: Ed25519Suite::new().expect("suite"),
        }
    }

    /// Runs `check` with registries that enable exactly `did:key`.
    fn with_registries<R>(&self, check: impl FnOnce(&ImmutableRegistries<'_>) -> R) -> R {
        let methods = [&self.did_key as &dyn PrincipalMethod];
        let suites = [&self.suite as &dyn SignatureSuite];
        check(&ImmutableRegistries::new(&methods, &suites).expect("registries"))
    }

    fn trust(&self) -> GitTrust {
        trust(&self.root, &[&self.did_key as &dyn PrincipalMethod])
    }

    fn sign(&self, payload: &[u8], delegation: &Delegation) -> (UnsignedPayload, Vec<u8>) {
        let payload = UnsignedPayload::parse(payload.to_vec()).expect("payload");
        let envelope = sign_payload(&payload, &repository(), &self.agent, delegation, NOW - 60)
            .expect("signature");
        (payload, envelope.to_armored().into_bytes())
    }

    fn verify(&self, payload: &UnsignedPayload, signature: &[u8], at: u64) -> GitVerification {
        self.verify_with(&self.trust(), payload, signature, at)
    }

    fn verify_with(
        &self,
        trust: &GitTrust,
        payload: &UnsignedPayload,
        signature: &[u8],
        at: u64,
    ) -> GitVerification {
        self.with_registries(|registries| {
            verify_signature(payload, signature, trust, registries, Timestamp::new(at))
        })
    }

    fn verify_raw(&self, raw: &[u8]) -> GitVerification {
        let trust = self.trust();
        self.with_registries(|registries| {
            verify_object(raw, &trust, registries, Timestamp::new(NOW))
        })
    }
}

#[test]
fn delegated_agent_signatures_verify_for_commits_and_tags() {
    let world = World::new();
    let delegation = full_delegation(&world.root, &world.agent);
    for (object, kind, tag) in [
        (COMMIT, ObjectKind::Commit, None),
        (TAG, ObjectKind::Tag, Some("v1.0.0")),
    ] {
        let (payload, signature) = world.sign(object, &delegation);
        let GitVerification::Verified(verified) = world.verify(&payload, &signature, NOW) else {
            panic!(
                "{kind:?} did not verify: {:?}",
                world.verify(&payload, &signature, NOW)
            );
        };
        assert_eq!(verified.kind(), kind);
        assert_eq!(verified.signer(), &world.agent.principal());
        assert_eq!(verified.chain(), &[world.root.principal()]);
        assert_eq!(verified.tag_name(), tag);
        assert!(matches!(
            GitVerification::Verified(verified).status(),
            VerifyStatus::Good(_)
        ));
    }
}

#[test]
fn verification_derives_the_request_from_the_object() {
    let world = World::new();
    let delegation = full_delegation(&world.root, &world.agent);
    let (_, commit_signature) = world.sign(COMMIT, &delegation);
    let (tag_payload, tag_signature) = world.sign(TAG, &delegation);

    let mut altered = COMMIT.to_vec();
    altered.push(b'!');
    let altered = UnsignedPayload::parse(altered).expect("payload");
    let commit_payload = UnsignedPayload::parse(COMMIT.to_vec()).expect("payload");
    let cases = [
        (&altered, &commit_signature, "git.payload-digest-mismatch"),
        (&tag_payload, &commit_signature, "git.kind-mismatch"),
        (&commit_payload, &tag_signature, "git.kind-mismatch"),
    ];
    for (payload, signature, code) in cases {
        assert_eq!(
            world.verify(payload, signature, NOW),
            GitVerification::Denied(code)
        );
    }

    let other = GitTrust::new(
        auths_codec::decode_verifier_context(
            &auths_codec::encode_verifier_context(
                &world
                    .trust()
                    .context_for_tests()
                    .for_request(
                        Audience::parse("git://github.com/acme/other").expect("audience"),
                        Challenge::new([0; 32]),
                        Timestamp::new(NOW),
                    )
                    .expect("context"),
            )
            .expect("encode"),
        )
        .expect("decode"),
    )
    .expect("trust");
    assert_eq!(
        world.verify_with(&other, &commit_payload, &commit_signature, NOW),
        GitVerification::Denied("git.repository-mismatch")
    );
}

#[test]
fn authority_limits_are_enforced_by_the_kernel() {
    let world = World::new();
    let commit_only = delegate(
        &world.root,
        &world.agent,
        vec![permission(SIGN_COMMIT, "commits")],
        window(NOW - 3_600, NOW + 3_600),
    );
    let (payload, signature) = world.sign(TAG, &commit_only);
    assert!(
        !matches!(
            world.verify(&payload, &signature, NOW),
            GitVerification::Verified(_)
        ),
        "a commit-only grant must not authorize a tag"
    );

    let (payload, signature) = world.sign(COMMIT, &commit_only);
    assert!(matches!(
        world.verify(&payload, &signature, NOW),
        GitVerification::Verified(_)
    ));
    assert!(
        !matches!(
            world.verify(&payload, &signature, NOW + 7_200),
            GitVerification::Verified(_)
        ),
        "an expired grant must not verify at gate time"
    );

    let stranger = DidKeySigner::new(0x33);
    let foreign = full_delegation(&stranger, &world.agent);
    let (payload, signature) = world.sign(COMMIT, &foreign);
    assert!(
        !matches!(
            world.verify(&payload, &signature, NOW),
            GitVerification::Verified(_)
        ),
        "a chain to an unpinned root must not verify"
    );
}

#[test]
fn signing_refuses_a_grant_issued_to_someone_else() {
    let world = World::new();
    let other = DidKeySigner::new(0x44);
    let delegation = full_delegation(&world.root, &other);
    let payload = UnsignedPayload::parse(COMMIT.to_vec()).expect("payload");
    assert_eq!(
        sign_payload(&payload, &repository(), &world.agent, &delegation, NOW).err(),
        Some(SignError::GrantSubjectMismatch)
    );
}

#[test]
fn the_enabled_method_set_is_configuration_bound_by_trust() {
    let world = World::new();
    let raw_key = RawKeyMethod::new().expect("raw key");
    let delegation = full_delegation(&world.root, &world.agent);
    let (payload, signature) = world.sign(COMMIT, &delegation);
    let both: [&dyn PrincipalMethod; 2] = [&world.did_key, &raw_key];
    let suites = [&world.suite as &dyn SignatureSuite];
    let both_registries = ImmutableRegistries::new(&both, &suites).expect("both");

    // Trust pinned to the did:key-only configuration rejects a verifier that
    // executes a different method set.
    assert!(!matches!(
        verify_signature(
            &payload,
            &signature,
            &world.trust(),
            &both_registries,
            Timestamp::new(NOW)
        ),
        GitVerification::Verified(_)
    ));

    // The same verification path accepts the signature once the trust names
    // the wider set: enabling a method changes configuration, not code.
    let wider = trust(&world.root, &both);
    assert!(matches!(
        verify_signature(
            &payload,
            &signature,
            &wider,
            &both_registries,
            Timestamp::new(NOW)
        ),
        GitVerification::Verified(_)
    ));
}

#[test]
fn raw_objects_verify_through_the_same_path() {
    let world = World::new();
    let delegation = full_delegation(&world.root, &world.agent);
    let (_, signature) = world.sign(COMMIT, &delegation);
    let header_end = COMMIT
        .windows(2)
        .position(|window| window == b"\n\n")
        .expect("headers");
    let signature = String::from_utf8(signature).expect("ascii");
    let mut raw = COMMIT[..header_end].to_vec();
    raw.extend_from_slice(b"\ngpgsig ");
    raw.extend_from_slice(signature.trim_end().replace('\n', "\n ").as_bytes());
    raw.extend_from_slice(&COMMIT[header_end..]);
    assert!(matches!(
        world.verify_raw(&raw),
        GitVerification::Verified(_)
    ));
    assert_eq!(
        world.verify_raw(COMMIT),
        GitVerification::Denied("git.unsigned")
    );
    let tampered = GitSignatureEnvelope::from_armored(signature.as_bytes()).expect("envelope");
    assert_eq!(
        GitSignatureEnvelope::new(tampered.proof().to_vec(), b"other".to_vec())
            .map(|envelope| {
                world.verify(
                    &UnsignedPayload::parse(COMMIT.to_vec()).expect("payload"),
                    envelope.to_armored().as_bytes(),
                    NOW,
                )
            })
            .expect("envelope"),
        GitVerification::Denied("git.action-malformed")
    );
}
