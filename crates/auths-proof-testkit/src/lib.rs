//! Shared fixtures and conformance helpers for `auths-proof`.

#![forbid(unsafe_code)]

use auths_proof_adapter_api::{
    AdapterRegistry, ControlProofInput, PrincipalControlError, PrincipalControlVerifier,
};
use auths_proof_author::{ActionBuilder, GrantBuilder, ProofBundleBuilder};
use auths_proof_codec::{body_digest, encode_bundle, DecodeLimits};
use auths_proof_did_keri::{
    test_signing::TestKeriIdentity, DidKeriAdapter, ED25519_ALGORITHM as KERI_ED25519_ALGORITHM,
};
use auths_proof_did_key::{test_signing::TestDidKeyIdentity, DidKeyAdapter};
use auths_proof_did_web::{
    test_signing::TestDidWebIdentity, DidWebAdapter, DidWebTrustRecord, HistoricalStatementPin,
};
use auths_proof_model::{
    AlgorithmId, AssuranceClaim, AssuranceClaims, AssuranceRequirements, Audience, AuthorityScope,
    CapabilityId, Challenge, Decision, DelegationDepth, Permission, PermissionSet,
    PrincipalEvidenceEntry, PrincipalRef, ProofBundle, ProofPurpose, ResourceId, Timestamp,
    TrustAnchor, TrustVerdict, ValidityWindow, VerificationMethodRef, VerificationPolicy,
};
use auths_proof_raw_key::{
    test_signing::{ed25519_descriptor, p256_descriptor, sign_ed25519, sign_p256},
    RawKeyAdapter,
};
use auths_proof_verifier::{verify, VerificationContext};

pub const ROOT_ED25519_SEED: [u8; 32] = [31; 32];
pub const AGENT_P256_SEED: [u8; 32] = [32; 32];
pub const KERI_ROOT_INCEPTION_SEED: [u8; 32] = [61; 32];
pub const KERI_ROOT_CURRENT_SEED: [u8; 32] = [62; 32];
pub const KERI_ROOT_NEXT_SEED: [u8; 32] = [63; 32];
pub const KERI_AGENT_INCEPTION_SEED: [u8; 32] = [71; 32];
pub const KERI_AGENT_CURRENT_SEED: [u8; 32] = [72; 32];
pub const KERI_AGENT_NEXT_SEED: [u8; 32] = [73; 32];
pub const MIXED_RAW_AGENT_P256_SEED: [u8; 32] = [64; 32];
pub const MIXED_RAW_ROOT_ED25519_SEED: [u8; 32] = [74; 32];
pub const DID_KEY_ROOT_SEED: [u8; 32] = [81; 32];
pub const DID_WEB_AGENT_SEED: [u8; 32] = [82; 32];
pub const ACTION_BODY: &[u8] = br#"{"path":"/reports/q3.pdf"}"#;
pub const ACTION_NOW: u64 = 1_725_000_125;

pub struct MilestoneOneFixture {
    pub bundle: ProofBundle,
    pub encoded: Vec<u8>,
    pub body: Vec<u8>,
    pub audience: Audience,
    pub challenge: Challenge,
    pub anchor: TrustAnchor,
    pub did_web_trust: Vec<DidWebTrustRecord>,
}

pub struct PrincipalAdapterVector {
    pub principal: PrincipalRef,
    pub verification_method: VerificationMethodRef,
    pub algorithm: AlgorithmId,
    pub signing_bytes: Vec<u8>,
    pub signature: Vec<u8>,
    pub evidence: PrincipalEvidenceEntry,
}

pub fn assert_principal_adapter_conformance(
    adapter: &dyn PrincipalControlVerifier,
    vector: &PrincipalAdapterVector,
) {
    let valid = adapter.verify_control(ControlProofInput {
        principal: &vector.principal,
        purpose: ProofPurpose::CapabilityInvocation,
        verification_method: &vector.verification_method,
        algorithm: &vector.algorithm,
        signing_bytes: &vector.signing_bytes,
        signature: &vector.signature,
        evidence: &vector.evidence,
        asserted_signing_time: Timestamp::new(10),
        verification_time: Timestamp::new(11),
    });
    assert!(valid.is_ok(), "valid adapter vector was rejected");

    let mut modified_message = vector.signing_bytes.clone();
    modified_message.push(0);
    let invalid_message = adapter.verify_control(ControlProofInput {
        principal: &vector.principal,
        purpose: ProofPurpose::CapabilityInvocation,
        verification_method: &vector.verification_method,
        algorithm: &vector.algorithm,
        signing_bytes: &modified_message,
        signature: &vector.signature,
        evidence: &vector.evidence,
        asserted_signing_time: Timestamp::new(10),
        verification_time: Timestamp::new(11),
    });
    assert_eq!(
        invalid_message,
        Err(PrincipalControlError::InvalidSignature)
    );

    let wrong_method =
        VerificationMethodRef::parse("key:sha256:wrong").expect("fixed wrong method");
    let invalid_method = adapter.verify_control(ControlProofInput {
        principal: &vector.principal,
        purpose: ProofPurpose::CapabilityInvocation,
        verification_method: &wrong_method,
        algorithm: &vector.algorithm,
        signing_bytes: &vector.signing_bytes,
        signature: &vector.signature,
        evidence: &vector.evidence,
        asserted_signing_time: Timestamp::new(10),
        verification_time: Timestamp::new(11),
    });
    assert_eq!(
        invalid_method,
        Err(PrincipalControlError::VerificationMethodMismatch)
    );

    let wrong_algorithm = AlgorithmId::parse("wrong").expect("fixed wrong algorithm");
    let invalid_algorithm = adapter.verify_control(ControlProofInput {
        principal: &vector.principal,
        purpose: ProofPurpose::CapabilityInvocation,
        verification_method: &vector.verification_method,
        algorithm: &wrong_algorithm,
        signing_bytes: &vector.signing_bytes,
        signature: &vector.signature,
        evidence: &vector.evidence,
        asserted_signing_time: Timestamp::new(10),
        verification_time: Timestamp::new(11),
    });
    assert_eq!(
        invalid_algorithm,
        Err(PrincipalControlError::AlgorithmMismatch)
    );
}

pub fn milestone_one_fixture() -> MilestoneOneFixture {
    let root_descriptor = ed25519_descriptor(ROOT_ED25519_SEED).expect("fixed root key is valid");
    let agent_descriptor = p256_descriptor(AGENT_P256_SEED).expect("fixed agent key is valid");
    let root = root_descriptor.principal().expect("fixed root principal");
    let agent = agent_descriptor.principal().expect("fixed agent principal");
    let permission = Permission::new(
        CapabilityId::parse("mcp.tools.call").expect("fixed capability"),
        ResourceId::parse("mcp://filesystem/read_file").expect("fixed resource"),
    );
    let grant = {
        let draft = GrantBuilder::new(
            root.clone(),
            agent.clone(),
            root_descriptor
                .signature_descriptor()
                .expect("root signature descriptor"),
        )
        .permission(permission.clone())
        .issued_at(Timestamp::new(1_725_000_100))
        .valid_between(Timestamp::new(1_725_000_100), Timestamp::new(1_725_000_200))
        .expect("fixed grant validity")
        .delegation_depth(DelegationDepth::new(0))
        .expiry_only()
        .build()
        .expect("fixed grant");
        let signature = sign_ed25519(ROOT_ED25519_SEED, draft.signing_request().bytes());
        draft.attach(signature).expect("fixed grant signature")
    };

    let body = ACTION_BODY.to_vec();
    let audience = Audience::parse("mcp://filesystem").expect("fixed audience");
    let challenge = Challenge::new([0xa5; 32]);
    let action = {
        let draft = ActionBuilder::new(
            agent,
            agent_descriptor
                .signature_descriptor()
                .expect("agent signature descriptor"),
            permission.clone(),
            body_digest(&body),
            audience.clone(),
            Timestamp::new(1_725_000_120),
            Timestamp::new(1_725_000_130),
            challenge,
        )
        .build()
        .expect("fixed action");
        let signature =
            sign_p256(AGENT_P256_SEED, draft.signing_request().bytes()).expect("P-256 signature");
        draft.attach(signature).expect("fixed action signature")
    };

    let bundle = ProofBundleBuilder::new(
        action,
        agent_descriptor.evidence_entry().expect("agent evidence"),
    )
    .expect("bundle")
    .push_grant(
        grant,
        root_descriptor.evidence_entry().expect("root evidence"),
    )
    .expect("grant")
    .build()
    .expect("bundle");

    let anchor = TrustAnchor::new(
        root,
        AuthorityScope::new(
            PermissionSet::new(vec![permission]).expect("fixed authority permissions"),
        ),
        ValidityWindow::new(Timestamp::new(1_725_000_000), Timestamp::new(1_725_000_300))
            .expect("fixed anchor validity"),
        DelegationDepth::new(1),
        AssuranceRequirements::new(
            AssuranceClaims::new(vec![
                AssuranceClaim::SelfCertifyingIdentifier,
                AssuranceClaim::OfflineVerifiable,
            ]),
            None,
            true,
            true,
        ),
    );
    let encoded = encode_bundle(&bundle).expect("fixed bundle is canonical");

    MilestoneOneFixture {
        bundle,
        encoded,
        body,
        audience,
        challenge,
        anchor,
        did_web_trust: Vec::new(),
    }
}

pub fn keri_root_raw_agent_fixture() -> MilestoneOneFixture {
    let root_identity = TestKeriIdentity::rotated_ed25519(
        KERI_ROOT_INCEPTION_SEED,
        KERI_ROOT_CURRENT_SEED,
        KERI_ROOT_NEXT_SEED,
    )
    .expect("fixed KERI root is valid");
    let agent_descriptor =
        p256_descriptor(MIXED_RAW_AGENT_P256_SEED).expect("fixed raw agent is valid");
    let root = root_identity.principal().clone();
    let agent = agent_descriptor.principal().expect("fixed agent principal");
    let permission = fixture_permission();
    let grant = {
        let draft = GrantBuilder::new(
            root.clone(),
            agent.clone(),
            root_identity
                .signature_descriptor()
                .expect("KERI root signature descriptor"),
        )
        .permission(permission.clone())
        .issued_at(Timestamp::new(1_725_000_100))
        .valid_between(Timestamp::new(1_725_000_100), Timestamp::new(1_725_000_200))
        .expect("fixed grant validity")
        .delegation_depth(DelegationDepth::new(0))
        .expiry_only()
        .build()
        .expect("fixed grant");
        let signature = root_identity.sign(draft.signing_request().bytes());
        draft.attach(signature).expect("fixed grant signature")
    };

    let body = ACTION_BODY.to_vec();
    let audience = fixture_audience();
    let challenge = fixture_challenge();
    let action = {
        let draft = ActionBuilder::new(
            agent,
            agent_descriptor
                .signature_descriptor()
                .expect("raw agent signature descriptor"),
            permission.clone(),
            body_digest(&body),
            audience.clone(),
            Timestamp::new(1_725_000_120),
            Timestamp::new(1_725_000_130),
            challenge,
        )
        .build()
        .expect("fixed action");
        let signature = sign_p256(MIXED_RAW_AGENT_P256_SEED, draft.signing_request().bytes())
            .expect("P-256 signature");
        draft.attach(signature).expect("fixed action signature")
    };

    let bundle = ProofBundleBuilder::new(
        action,
        agent_descriptor
            .evidence_entry()
            .expect("raw agent evidence"),
    )
    .expect("bundle")
    .push_grant(
        grant,
        root_identity.evidence_entry().expect("KERI root evidence"),
    )
    .expect("grant")
    .build()
    .expect("bundle");

    fixture_from_parts(bundle, body, audience, challenge, root, permission)
}

pub fn raw_root_keri_agent_fixture() -> MilestoneOneFixture {
    let root_descriptor =
        ed25519_descriptor(MIXED_RAW_ROOT_ED25519_SEED).expect("fixed raw root is valid");
    let agent_identity = TestKeriIdentity::rotated_ed25519(
        KERI_AGENT_INCEPTION_SEED,
        KERI_AGENT_CURRENT_SEED,
        KERI_AGENT_NEXT_SEED,
    )
    .expect("fixed KERI agent is valid");
    let root = root_descriptor.principal().expect("fixed root principal");
    let agent = agent_identity.principal().clone();
    let permission = fixture_permission();
    let grant = {
        let draft = GrantBuilder::new(
            root.clone(),
            agent.clone(),
            root_descriptor
                .signature_descriptor()
                .expect("raw root signature descriptor"),
        )
        .permission(permission.clone())
        .issued_at(Timestamp::new(1_725_000_100))
        .valid_between(Timestamp::new(1_725_000_100), Timestamp::new(1_725_000_200))
        .expect("fixed grant validity")
        .delegation_depth(DelegationDepth::new(0))
        .expiry_only()
        .build()
        .expect("fixed grant");
        let signature = sign_ed25519(MIXED_RAW_ROOT_ED25519_SEED, draft.signing_request().bytes());
        draft.attach(signature).expect("fixed grant signature")
    };

    let body = ACTION_BODY.to_vec();
    let audience = fixture_audience();
    let challenge = fixture_challenge();
    let action = {
        let draft = ActionBuilder::new(
            agent,
            agent_identity
                .signature_descriptor()
                .expect("KERI agent signature descriptor"),
            permission.clone(),
            body_digest(&body),
            audience.clone(),
            Timestamp::new(1_725_000_120),
            Timestamp::new(1_725_000_130),
            challenge,
        )
        .build()
        .expect("fixed action");
        let signature = agent_identity.sign(draft.signing_request().bytes());
        draft.attach(signature).expect("fixed action signature")
    };

    let bundle = ProofBundleBuilder::new(
        action,
        agent_identity
            .evidence_entry()
            .expect("KERI agent evidence"),
    )
    .expect("bundle")
    .push_grant(
        grant,
        root_descriptor.evidence_entry().expect("raw root evidence"),
    )
    .expect("grant")
    .build()
    .expect("bundle");

    fixture_from_parts(bundle, body, audience, challenge, root, permission)
}

#[derive(Clone, Copy)]
enum DidWebFixtureTrust {
    Current,
    HistoricalPinned,
    HistoricalWithoutStatement,
}

pub fn did_key_root_did_web_agent_fixture() -> MilestoneOneFixture {
    did_key_did_web_fixture(DidWebFixtureTrust::Current)
}

pub fn historically_pinned_did_web_fixture() -> MilestoneOneFixture {
    did_key_did_web_fixture(DidWebFixtureTrust::HistoricalPinned)
}

pub fn historical_did_web_without_statement_fixture() -> MilestoneOneFixture {
    did_key_did_web_fixture(DidWebFixtureTrust::HistoricalWithoutStatement)
}

fn did_key_did_web_fixture(trust_mode: DidWebFixtureTrust) -> MilestoneOneFixture {
    let root_identity = TestDidKeyIdentity::ed25519(DID_KEY_ROOT_SEED).expect("fixed did:key root");
    let agent_identity =
        TestDidWebIdentity::ed25519("did:web:agents.example.com:build", DID_WEB_AGENT_SEED)
            .expect("fixed did:web agent");
    let root = root_identity.principal().expect("root principal");
    let agent = agent_identity.principal().clone();
    let permission = fixture_permission();
    let grant = {
        let draft = GrantBuilder::new(
            root.clone(),
            agent.clone(),
            root_identity
                .signature_descriptor()
                .expect("did:key root descriptor"),
        )
        .permission(permission.clone())
        .issued_at(Timestamp::new(1_725_000_100))
        .valid_between(Timestamp::new(1_725_000_100), Timestamp::new(1_725_000_200))
        .expect("fixed grant validity")
        .delegation_depth(DelegationDepth::new(0))
        .expiry_only()
        .build()
        .expect("fixed grant");
        let signature = root_identity
            .sign(draft.signing_request().bytes())
            .expect("did:key signature");
        draft.attach(signature).expect("fixed grant signature")
    };

    let body = ACTION_BODY.to_vec();
    let audience = fixture_audience();
    let challenge = fixture_challenge();
    let action_draft = ActionBuilder::new(
        agent,
        agent_identity
            .signature_descriptor()
            .expect("did:web agent descriptor"),
        permission.clone(),
        body_digest(&body),
        audience.clone(),
        Timestamp::new(1_725_000_120),
        Timestamp::new(1_725_000_130),
        challenge,
    )
    .build()
    .expect("fixed action");
    let action_signing_bytes = action_draft.signing_request().bytes().to_vec();
    let action = action_draft
        .attach(agent_identity.sign(&action_signing_bytes))
        .expect("fixed action signature");

    let did_web_trust = match trust_mode {
        DidWebFixtureTrust::Current => agent_identity
            .current_trust(Timestamp::new(1_725_000_115), Timestamp::new(1_725_000_130))
            .expect("current trust"),
        DidWebFixtureTrust::HistoricalPinned => agent_identity
            .historical_trust(
                Timestamp::new(1_725_000_100),
                Timestamp::new(1_725_000_122),
                Some(HistoricalStatementPin::new(
                    &action_signing_bytes,
                    Timestamp::new(1_725_000_121),
                )),
            )
            .expect("historical trust"),
        DidWebFixtureTrust::HistoricalWithoutStatement => agent_identity
            .historical_trust(
                Timestamp::new(1_725_000_100),
                Timestamp::new(1_725_000_122),
                None,
            )
            .expect("historical trust"),
    };

    let bundle = ProofBundleBuilder::new(
        action,
        agent_identity
            .evidence_entry()
            .expect("did:web agent evidence"),
    )
    .expect("bundle")
    .push_grant(
        grant,
        root_identity
            .evidence_entry()
            .expect("did:key root evidence"),
    )
    .expect("grant")
    .build()
    .expect("bundle");

    let mut fixture = fixture_from_parts(bundle, body, audience, challenge, root, permission);
    fixture.did_web_trust.push(did_web_trust);
    fixture
}

fn fixture_permission() -> Permission {
    Permission::new(
        CapabilityId::parse("mcp.tools.call").expect("fixed capability"),
        ResourceId::parse("mcp://filesystem/read_file").expect("fixed resource"),
    )
}

fn fixture_audience() -> Audience {
    Audience::parse("mcp://filesystem").expect("fixed audience")
}

const fn fixture_challenge() -> Challenge {
    Challenge::new([0xa5; 32])
}

fn fixture_from_parts(
    bundle: ProofBundle,
    body: Vec<u8>,
    audience: Audience,
    challenge: Challenge,
    root: PrincipalRef,
    permission: Permission,
) -> MilestoneOneFixture {
    let anchor = TrustAnchor::new(
        root,
        AuthorityScope::new(
            PermissionSet::new(vec![permission]).expect("fixed authority permissions"),
        ),
        ValidityWindow::new(Timestamp::new(1_725_000_000), Timestamp::new(1_725_000_300))
            .expect("fixed anchor validity"),
        DelegationDepth::new(1),
        AssuranceRequirements::new(
            AssuranceClaims::new(vec![
                AssuranceClaim::SelfCertifyingIdentifier,
                AssuranceClaim::OfflineVerifiable,
            ]),
            None,
            true,
            true,
        ),
    );
    let encoded = encode_bundle(&bundle).expect("fixed bundle is canonical");
    MilestoneOneFixture {
        bundle,
        encoded,
        body,
        audience,
        challenge,
        anchor,
        did_web_trust: Vec::new(),
    }
}

pub fn verify_milestone_fixture(fixture: &MilestoneOneFixture, body: &[u8]) -> TrustVerdict {
    verify_milestone_bytes(fixture, &fixture.encoded, body)
}

pub fn verify_milestone_bytes(
    fixture: &MilestoneOneFixture,
    encoded: &[u8],
    body: &[u8],
) -> TrustVerdict {
    let raw_key = RawKeyAdapter::new().expect("fixed adapter id");
    let did_keri = DidKeriAdapter::new().expect("fixed adapter id");
    let did_key = DidKeyAdapter::new().expect("fixed adapter id");
    let did_web = DidWebAdapter::new(fixture.did_web_trust.clone()).expect("fixed did:web trust");
    let principal_adapters: [&dyn PrincipalControlVerifier; 4] =
        [&raw_key, &did_keri, &did_key, &did_web];
    let registry = AdapterRegistry::new(&principal_adapters, &[]);
    let policy = VerificationPolicy::live_action();
    verify(
        encoded,
        &VerificationContext {
            now: Timestamp::new(ACTION_NOW),
            expected_audience: &fixture.audience,
            expected_challenge: &fixture.challenge,
            action_body: body,
            trust_anchors: core::slice::from_ref(&fixture.anchor),
            policy: &policy,
            decode_limits: DecodeLimits::standard(),
        },
        &registry,
    )
}

pub fn assert_milestone_one_conformance() {
    let fixture = milestone_one_fixture();
    let verdict = verify_milestone_fixture(&fixture, &fixture.body);
    assert_eq!(verdict.decision(), Decision::Authorized);

    let tampered = verify_milestone_fixture(&fixture, b"tampered");
    assert_eq!(tampered.decision(), Decision::Denied);

    for bit_index in 0..fixture.encoded.len() * 8 {
        let mut mutated = fixture.encoded.clone();
        mutated[bit_index / 8] ^= 1 << (bit_index % 8);
        let verdict = verify_milestone_bytes(&fixture, &mutated, &fixture.body);
        assert_ne!(
            verdict.decision(),
            Decision::Authorized,
            "one-bit mutation {bit_index} was accepted"
        );
    }

    let descriptor = ed25519_descriptor(ROOT_ED25519_SEED).expect("fixed descriptor");
    let message = b"auths-proof conformance vector".to_vec();
    let raw_key = RawKeyAdapter::new().expect("fixed adapter");
    assert_principal_adapter_conformance(
        &raw_key,
        &PrincipalAdapterVector {
            principal: descriptor.principal().expect("fixed principal"),
            verification_method: descriptor
                .verification_method()
                .expect("fixed verification method"),
            algorithm: AlgorithmId::parse("ed25519").expect("fixed algorithm"),
            signature: sign_ed25519(ROOT_ED25519_SEED, &message),
            signing_bytes: message,
            evidence: descriptor.evidence_entry().expect("fixed evidence"),
        },
    );
}

pub fn assert_milestone_two_conformance() {
    for fixture in [keri_root_raw_agent_fixture(), raw_root_keri_agent_fixture()] {
        let verdict = verify_milestone_fixture(&fixture, &fixture.body);
        assert_eq!(verdict.decision(), Decision::Authorized);

        let tampered = verify_milestone_fixture(&fixture, b"tampered");
        assert_eq!(tampered.decision(), Decision::Denied);
    }

    let identity = TestKeriIdentity::rotated_ed25519(
        KERI_AGENT_INCEPTION_SEED,
        KERI_AGENT_CURRENT_SEED,
        KERI_AGENT_NEXT_SEED,
    )
    .expect("fixed KERI identity");
    let message = b"auths-proof KERI conformance vector".to_vec();
    let did_keri = DidKeriAdapter::new().expect("fixed KERI adapter");
    assert_principal_adapter_conformance(
        &did_keri,
        &PrincipalAdapterVector {
            principal: identity.principal().clone(),
            verification_method: identity.verification_method().expect("fixed method"),
            algorithm: AlgorithmId::parse(KERI_ED25519_ALGORITHM).expect("fixed algorithm"),
            signature: identity.sign(&message),
            signing_bytes: message,
            evidence: identity.evidence_entry().expect("fixed evidence"),
        },
    );
}

pub fn assert_milestone_three_conformance() {
    let current = did_key_root_did_web_agent_fixture();
    let historical = historically_pinned_did_web_fixture();
    assert_eq!(
        current.encoded, historical.encoded,
        "resolver trust must not change the bundled proof"
    );
    for fixture in [current, historical] {
        let verdict = verify_milestone_fixture(&fixture, &fixture.body);
        assert_eq!(verdict.decision(), Decision::Authorized);
    }

    let incomplete = historical_did_web_without_statement_fixture();
    let verdict = verify_milestone_fixture(&incomplete, &incomplete.body);
    assert_eq!(verdict.decision(), Decision::Indeterminate);
    assert_eq!(
        verdict.reasons(),
        [auths_proof_model::VerdictReason::HistoricalStateUnavailable]
    );

    let did_key_identity =
        TestDidKeyIdentity::ed25519(DID_KEY_ROOT_SEED).expect("fixed did:key identity");
    let message = b"auths-proof did:key conformance vector".to_vec();
    let did_key = DidKeyAdapter::new().expect("fixed did:key adapter");
    let did_key_descriptor = did_key_identity
        .signature_descriptor()
        .expect("did:key descriptor");
    assert_principal_adapter_conformance(
        &did_key,
        &PrincipalAdapterVector {
            principal: did_key_identity.principal().expect("did:key principal"),
            verification_method: did_key_descriptor.verification_method().clone(),
            algorithm: did_key_descriptor.algorithm().clone(),
            signature: did_key_identity.sign(&message).expect("did:key signature"),
            signing_bytes: message,
            evidence: did_key_identity.evidence_entry().expect("did:key evidence"),
        },
    );

    let did_web_identity = TestDidWebIdentity::ed25519("did:web:example.com", DID_WEB_AGENT_SEED)
        .expect("fixed did:web identity");
    let message = b"auths-proof did:web conformance vector".to_vec();
    let did_web = DidWebAdapter::new(vec![did_web_identity
        .current_trust(Timestamp::new(10), Timestamp::new(20))
        .expect("did:web trust")])
    .expect("fixed did:web adapter");
    let did_web_descriptor = did_web_identity
        .signature_descriptor()
        .expect("did:web descriptor");
    assert_principal_adapter_conformance(
        &did_web,
        &PrincipalAdapterVector {
            principal: did_web_identity.principal().clone(),
            verification_method: did_web_descriptor.verification_method().clone(),
            algorithm: did_web_descriptor.algorithm().clone(),
            signature: did_web_identity.sign(&message),
            signing_bytes: message,
            evidence: did_web_identity.evidence_entry().expect("did:web evidence"),
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_proof_codec::decode_bundle;

    #[test]
    fn mixed_algorithm_fixture_is_authorized() {
        assert_milestone_one_conformance();
    }

    #[test]
    fn mixed_principal_fixtures_are_authorized() {
        assert_milestone_two_conformance();
    }

    #[test]
    fn resolver_separation_fixtures_have_explicit_assurance() {
        assert_milestone_three_conformance();
    }

    #[test]
    fn fixture_is_canonical_and_round_trips() {
        let fixture = milestone_one_fixture();
        let decoded =
            decode_bundle(&fixture.encoded, DecodeLimits::standard()).expect("decode fixture");
        assert_eq!(
            encode_bundle(&decoded).expect("encode fixture"),
            fixture.encoded
        );
    }
}
