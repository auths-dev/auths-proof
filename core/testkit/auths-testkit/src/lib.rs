//! Language-neutral target V1 corpus construction helpers.

#![forbid(unsafe_code)]

use auths_author::{prepare_action, prepare_grant, prepare_grant_status, prepare_principal_status};
use auths_codec::{
    action_id, attachment_digest, body_digest, decode_bundle, encode_bundle,
    encode_verifier_context, evidence_id, grant_id, grant_status_id, plan_id, principal_status_id,
};
use auths_did_keri::{
    ADAPTER_ID as DID_KERI_V1, ED25519_SUITE as KERI_ED25519_SUITE,
    EVIDENCE_MEDIA_TYPE as DID_KERI_MEDIA_TYPE, KeriEvidence, test_signing::TestKeriIdentity,
};
use auths_did_key::{DID_KEY_MEDIA_TYPE, DID_KEY_V1, DidKeyEvidence};
use auths_did_web::{DID_WEB_MEDIA_TYPE, DID_WEB_V1, DidWebEvidence, DidWebTrustRecord};
use auths_hsm_attested::{
    HSM_ATTESTED_MEDIA_TYPE, HSM_ATTESTED_V1, HsmAttestationEvidence, HsmKeyRecord,
};
use auths_model::{
    AcceptedRegistries, ActionConstraint, ActionEnvelope, AssuranceClaimId, AssurancePolicy,
    AssurancePolicyId, AssuranceQuantifier, AssuranceRequirement, AttachmentDescriptor,
    AttachmentDigest, Audience, AudienceSet, AuthorizationPlan, BudgetAlgebraId, BudgetCeiling,
    BundleHeader, CanonicalAction, CapabilityId, Challenge, ChannelBindingId,
    CompositionRequirement, ControlBinding, CriticalExtension, CriticalExtensions, DenialReason,
    DetachedAttachment, Digest, DispositionId, EvidenceId, EvidenceObject, EvidenceTypeId,
    ExtensionId, FreshnessLimit, GrantId, GrantState, GrantStatement, GrantStatusSnapshot,
    GrantStatusStatement, LimitKind, MediaType, ParticipantRole, Permission, PermissionSet, PlanId,
    PrincipalId, PrincipalMethodId, PrincipalState, PrincipalStatusSnapshot,
    PrincipalStatusStatement, ProfileId, ProfilePolicyId, ProfileRef, ProofBundle, ProofRef,
    PurposeId, RegistryManifestId, Requirement, ResourceId, ResourceMatcherId, SignatureBytes,
    SignatureDescriptor, SignatureEnvelope, SignatureSuiteId, SignedAction, SignedGrant,
    SignedGrantStatus, SignedPrincipalStatus, StatementRef, StatusMethodId, StatusPolicy,
    StatusSnapshotId, Timestamp, TrustAnchor, TrustAnchorId, ValidityWindow, VerificationMethod,
    VerifierConfigurationId, VerifierContext, VerifierLimits,
};
use auths_multikey::{Multikey, MultikeyType};
use auths_raw_key::{RAW_KEY_MEDIA_TYPE, RAW_KEY_V1, RawKeyDescriptor, RawKeyType};
use auths_signature::{ED25519_V1, P256_SHA256_V1};
use auths_spiffe_x509::{
    SPIFFE_X509_MEDIA_TYPE, SPIFFE_X509_V1, SpiffeStatusRecord, SpiffeTrustDomain,
    SpiffeX509Evidence, svid_verification_method,
};
use auths_webauthn::{
    CounterPolicy, WEBAUTHN_MEDIA_TYPE, WEBAUTHN_V1, WebAuthnCredential, WebAuthnEvidence,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey, pkcs8::EncodePrivateKey as _};
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ED25519, SanType, SerialNumber,
};
use rustls_pki_types::PrivatePkcs8KeyDer;
use sha2::{Digest as _, Sha256};

const BODY: &[u8] = &[
    0xa2, 0x00, 0x64, b'r', b'e', b'a', b'd', 0x01, 0x6f, b'/', b'r', b'e', b'p', b'o', b'r', b't',
    b's', b'/', b'q', b'3', b'.', b'p', b'd', b'f',
];
const ASSURANCE_CLAIMS: [&str; 13] = [
    "self-certifying-identifier",
    "offline-verifiable",
    "controller-state-current-at",
    "historical-at",
    "statement-existence-proven-at",
    "rotation-aware",
    "revocation-checked-at",
    "witness-threshold-met",
    "pki-chain-validated",
    "workload-attested",
    "hardware-attested",
    "user-verified",
    "origin-bound",
];

/// Expected normative verifier result for one corpus case.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Expected {
    /// Successful authorization.
    Authorized,
    /// Stable denial.
    Denied(DenialReason),
    /// Stable unavailable-fact requirement.
    Indeterminate(Requirement),
}

/// Complete language-neutral input set for one corpus case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorpusFixture {
    name: &'static str,
    class: &'static str,
    proof_bytes: Vec<u8>,
    context_bytes: Vec<u8>,
    canonical_action: CanonicalAction,
    expected: Expected,
}

impl CorpusFixture {
    /// Returns the stable corpus name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the manifest fixture class.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        self.class
    }

    /// Returns canonical proof bytes.
    #[must_use]
    pub fn proof_bytes(&self) -> &[u8] {
        &self.proof_bytes
    }

    /// Returns canonical public context bytes.
    #[must_use]
    pub fn context_bytes(&self) -> &[u8] {
        &self.context_bytes
    }

    /// Returns the separately supplied canonical action.
    #[must_use]
    pub const fn canonical_action(&self) -> &CanonicalAction {
        &self.canonical_action
    }

    /// Returns the normative expected result.
    #[must_use]
    pub const fn expected(&self) -> Expected {
        self.expected
    }
}

#[derive(Clone)]
enum TestKey {
    Ed25519(Ed25519SigningKey),
    P256(P256SigningKey),
}

#[derive(Clone)]
struct Identity {
    key: TestKey,
    principal_kind: PrincipalKind,
    principal: PrincipalId,
}

#[derive(Clone)]
enum PrincipalKind {
    Raw(RawKeyDescriptor),
    DidKey(DidKeyEvidence),
    DidKeri {
        evidence: KeriEvidence,
        verification_method: VerificationMethod,
    },
    DidWeb {
        evidence: DidWebEvidence,
        verification_method: VerificationMethod,
    },
    WebAuthn {
        credential: WebAuthnCredential,
        evidence: WebAuthnEvidence,
    },
    Hsm {
        record: HsmKeyRecord,
        evidence: HsmAttestationEvidence,
    },
    Spiffe {
        evidence: SpiffeX509Evidence,
        verification_method: VerificationMethod,
    },
}

impl Identity {
    fn ed25519(seed: u8) -> Self {
        let key = Ed25519SigningKey::from_bytes(&[seed; 32]);
        let raw =
            RawKeyDescriptor::new(RawKeyType::Ed25519, key.verifying_key().to_bytes().to_vec())
                .expect("fixed Ed25519 key");
        let principal = raw.principal().expect("derived principal");
        Self {
            key: TestKey::Ed25519(key),
            principal_kind: PrincipalKind::Raw(raw),
            principal,
        }
    }

    fn p256(seed: u8) -> Self {
        let mut scalar = [0; 32];
        scalar[31] = seed.max(1);
        let key = P256SigningKey::from_bytes((&scalar).into()).expect("fixed P-256 scalar");
        let public_key = key.verifying_key().to_encoded_point(true);
        let raw = RawKeyDescriptor::new(RawKeyType::P256, public_key.as_bytes().to_vec())
            .expect("fixed P-256 key");
        let principal = raw.principal().expect("derived principal");
        Self {
            key: TestKey::P256(key),
            principal_kind: PrincipalKind::Raw(raw),
            principal,
        }
    }

    fn did_key_ed25519(seed: u8) -> Self {
        let key = Ed25519SigningKey::from_bytes(&[seed; 32]);
        let evidence = DidKeyEvidence::new(
            Multikey::from_public_key(
                MultikeyType::Ed25519,
                key.verifying_key().to_bytes().to_vec(),
            )
            .expect("fixed did:key"),
        );
        let principal = evidence.principal().expect("derived did:key principal");
        Self {
            key: TestKey::Ed25519(key),
            principal_kind: PrincipalKind::DidKey(evidence),
            principal,
        }
    }

    fn did_web_ed25519(principal: &str, seed: u8) -> Self {
        let key = Ed25519SigningKey::from_bytes(&[seed; 32]);
        let principal = PrincipalId::parse(principal).expect("fixed did:web principal");
        let multikey = Multikey::from_public_key(
            MultikeyType::Ed25519,
            key.verifying_key().to_bytes().to_vec(),
        )
        .expect("fixed did:web Multikey");
        let verification_method =
            VerificationMethod::parse(&format!("{}#key-1", principal.as_str()))
                .expect("fixed did:web method");
        let document = format!(
            r#"{{"verificationMethod":[{{"publicKeyMultibase":"{}","controller":"{}","type":"Multikey","id":"{}"}}],"id":"{}","capabilityInvocation":["{}"],"capabilityDelegation":["{}"],"assertionMethod":["{}"],"@context":"https://www.w3.org/ns/did/v1"}}"#,
            multikey.encoded(),
            principal.as_str(),
            verification_method.as_str(),
            principal.as_str(),
            verification_method.as_str(),
            verification_method.as_str(),
            verification_method.as_str(),
        );
        let evidence = DidWebEvidence::canonicalize(principal.clone(), document.as_bytes())
            .expect("fixed did:web document");
        Self {
            key: TestKey::Ed25519(key),
            principal_kind: PrincipalKind::DidWeb {
                evidence,
                verification_method,
            },
            principal,
        }
    }

    fn did_keri_ed25519(seed: u8) -> Self {
        let inception = [seed; 32];
        let current_seed = seed.checked_add(1).expect("small fixture seed");
        let next_seed = seed.checked_add(2).expect("small fixture seed");
        let identity =
            TestKeriIdentity::rotated_ed25519(inception, [current_seed; 32], [next_seed; 32])
                .expect("fixed did:keri identity");
        Self {
            key: TestKey::Ed25519(Ed25519SigningKey::from_bytes(&[current_seed; 32])),
            principal: identity.principal().clone(),
            principal_kind: PrincipalKind::DidKeri {
                evidence: identity.evidence().clone(),
                verification_method: identity
                    .verification_method()
                    .expect("fixed did:keri method"),
            },
        }
    }

    fn webauthn_p256(seed: u8, signing_preimage: &[u8]) -> Self {
        let (key, credential) = webauthn_credential(seed);
        let challenge = Base64UrlUnpadded::encode_string(&Sha256::digest(signing_preimage));
        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://auths.example","crossOrigin":false}}"#
        )
        .into_bytes();
        let mut authenticator_data = Vec::with_capacity(37);
        authenticator_data.extend_from_slice(&Sha256::digest(b"auths.example"));
        authenticator_data.push(0x05);
        authenticator_data.extend_from_slice(&1u32.to_be_bytes());
        let evidence = WebAuthnEvidence::new(vec![seed; 16], authenticator_data, client_data_json)
            .expect("fixed WebAuthn assertion");
        Self {
            key: TestKey::P256(key),
            principal: credential.principal().clone(),
            principal_kind: PrincipalKind::WebAuthn {
                credential,
                evidence,
            },
        }
    }

    fn hsm_ed25519(seed: u8, signing_preimage: &[u8]) -> Self {
        let (key, record) = hsm_record(seed);
        let evidence = HsmAttestationEvidence::for_record(&record, signing_preimage);
        Self {
            key: TestKey::Ed25519(key),
            principal: record.principal().clone(),
            principal_kind: PrincipalKind::Hsm { record, evidence },
        }
    }

    fn spiffe_ed25519(seed: u8) -> Self {
        let material = spiffe_material(seed);
        Self {
            key: TestKey::Ed25519(material.key),
            principal: material.principal,
            principal_kind: PrincipalKind::Spiffe {
                evidence: material.evidence,
                verification_method: material.verification_method,
            },
        }
    }

    fn descriptor(&self) -> SignatureDescriptor {
        SignatureDescriptor::new(
            PrincipalMethodId::parse(self.method_id()).expect("registry ID"),
            self.verification_method(),
            SignatureSuiteId::parse(self.suite()).expect("suite ID"),
        )
    }

    fn method_id(&self) -> &'static str {
        match &self.principal_kind {
            PrincipalKind::Raw(_) => RAW_KEY_V1,
            PrincipalKind::DidKey(_) => DID_KEY_V1,
            PrincipalKind::DidKeri { .. } => DID_KERI_V1,
            PrincipalKind::DidWeb { .. } => DID_WEB_V1,
            PrincipalKind::WebAuthn { .. } => WEBAUTHN_V1,
            PrincipalKind::Hsm { .. } => HSM_ATTESTED_V1,
            PrincipalKind::Spiffe { .. } => SPIFFE_X509_V1,
        }
    }

    fn suite(&self) -> &'static str {
        match &self.principal_kind {
            PrincipalKind::Raw(raw) => raw.suite(),
            PrincipalKind::DidKey(evidence) => evidence.multikey().key_type().suite(),
            PrincipalKind::DidKeri { .. } => KERI_ED25519_SUITE,
            PrincipalKind::DidWeb { .. }
            | PrincipalKind::Hsm { .. }
            | PrincipalKind::Spiffe { .. } => ED25519_V1,
            PrincipalKind::WebAuthn { .. } => P256_SHA256_V1,
        }
    }

    fn verification_method(&self) -> VerificationMethod {
        match &self.principal_kind {
            PrincipalKind::Raw(_) => {
                VerificationMethod::parse(self.principal.as_str()).expect("verification method")
            }
            PrincipalKind::DidKey(evidence) => evidence
                .verification_method()
                .expect("did:key verification method"),
            PrincipalKind::DidKeri {
                verification_method,
                ..
            }
            | PrincipalKind::DidWeb {
                verification_method,
                ..
            }
            | PrincipalKind::Spiffe {
                verification_method,
                ..
            } => verification_method.clone(),
            PrincipalKind::WebAuthn { credential, .. } => credential.verification_method().clone(),
            PrincipalKind::Hsm { record, .. } => record.verification_method().clone(),
        }
    }

    fn sign(&self, preimage: &[u8]) -> SignatureBytes {
        let bytes = match &self.key {
            TestKey::Ed25519(key) => key.sign(preimage).to_bytes().to_vec(),
            TestKey::P256(key) => {
                let signature: P256Signature = key.sign(preimage);
                signature
                    .normalize_s()
                    .unwrap_or(signature)
                    .to_bytes()
                    .to_vec()
            }
        };
        let bytes = if let PrincipalKind::WebAuthn { evidence, .. } = &self.principal_kind {
            let TestKey::P256(key) = &self.key else {
                panic!("WebAuthn fixture requires P-256");
            };
            let signature: P256Signature = key.sign(&evidence.signature_message());
            signature
                .normalize_s()
                .unwrap_or(signature)
                .to_bytes()
                .to_vec()
        } else {
            bytes
        };
        SignatureBytes::new(bytes).expect("registered signature length")
    }

    fn sign_high_s(&self, preimage: &[u8]) -> SignatureBytes {
        let TestKey::P256(key) = &self.key else {
            panic!("high-S fixture requires P-256");
        };
        let signature: P256Signature = key.sign(preimage);
        let low = signature.normalize_s().unwrap_or(signature);
        let (r, s) = low.split_scalars();
        let high =
            P256Signature::from_scalars(r.to_bytes(), (-s).to_bytes()).expect("high-S signature");
        SignatureBytes::new(high.to_bytes().to_vec()).expect("registered signature length")
    }

    fn evidence(&self) -> EvidenceObject {
        let (evidence_type, media_type, bytes) = match &self.principal_kind {
            PrincipalKind::Raw(raw) => (RAW_KEY_V1, RAW_KEY_MEDIA_TYPE, raw.encode()),
            PrincipalKind::DidKey(evidence) => (
                DID_KEY_V1,
                DID_KEY_MEDIA_TYPE,
                evidence.encode().expect("did:key evidence"),
            ),
            PrincipalKind::DidKeri { evidence, .. } => (
                DID_KERI_V1,
                DID_KERI_MEDIA_TYPE,
                evidence.encode().expect("did:keri evidence"),
            ),
            PrincipalKind::DidWeb { evidence, .. } => (
                DID_WEB_V1,
                DID_WEB_MEDIA_TYPE,
                evidence.encode().expect("did:web evidence"),
            ),
            PrincipalKind::WebAuthn { evidence, .. } => (
                WEBAUTHN_V1,
                WEBAUTHN_MEDIA_TYPE,
                evidence.encode().expect("WebAuthn evidence"),
            ),
            PrincipalKind::Hsm { evidence, .. } => (
                HSM_ATTESTED_V1,
                HSM_ATTESTED_MEDIA_TYPE,
                evidence.encode().expect("HSM evidence"),
            ),
            PrincipalKind::Spiffe { evidence, .. } => (
                SPIFFE_X509_V1,
                SPIFFE_X509_MEDIA_TYPE,
                evidence.encode().expect("SPIFFE X.509 evidence"),
            ),
        };
        let unaddressed = EvidenceObject::new(
            EvidenceId::new([0; 32]),
            EvidenceTypeId::parse(evidence_type).expect("evidence type"),
            MediaType::parse(media_type).expect("evidence media type"),
            bytes,
        )
        .expect("raw evidence");
        EvidenceObject::new(
            evidence_id(&unaddressed).expect("evidence ID"),
            unaddressed.evidence_type().clone(),
            unaddressed.media_type().clone(),
            unaddressed.bytes().to_vec(),
        )
        .expect("addressed raw evidence")
    }

    fn assurance_claim(&self) -> &'static str {
        match &self.principal_kind {
            PrincipalKind::Raw(_) | PrincipalKind::DidKey(_) | PrincipalKind::DidKeri { .. } => {
                "self-certifying-identifier"
            }
            PrincipalKind::DidWeb { .. } => "controller-state-current-at",
            PrincipalKind::WebAuthn { .. } => "user-verified",
            PrincipalKind::Hsm { .. } => "hardware-attested",
            PrincipalKind::Spiffe { .. } => "workload-attested",
        }
    }

    fn did_web_current_trust(&self) -> Option<DidWebTrustRecord> {
        let PrincipalKind::DidWeb { evidence, .. } = &self.principal_kind else {
            return None;
        };
        Some(
            DidWebTrustRecord::current(
                self.principal.clone(),
                evidence.document_digest(),
                Timestamp::new(40),
                Timestamp::new(60),
            )
            .expect("fixed did:web trust"),
        )
    }
}

fn webauthn_credential(seed: u8) -> (P256SigningKey, WebAuthnCredential) {
    let mut scalar = [0; 32];
    scalar[31] = seed.max(1);
    let key = P256SigningKey::from_bytes((&scalar).into()).expect("fixed WebAuthn scalar");
    let point = key.verifying_key().to_encoded_point(true);
    let public_key: [u8; 33] = point
        .as_bytes()
        .try_into()
        .expect("compressed WebAuthn key");
    let credential = WebAuthnCredential::new(
        vec![seed; 16],
        public_key,
        "auths.example".to_string(),
        vec!["https://auths.example".to_string()],
        true,
        CounterPolicy::GreaterThan(0),
        Some("non-exportable".to_string()),
        Timestamp::new(40),
        Timestamp::new(60),
    )
    .expect("fixed WebAuthn credential");
    (key, credential)
}

fn hsm_record(seed: u8) -> (Ed25519SigningKey, HsmKeyRecord) {
    let key = Ed25519SigningKey::from_bytes(&[seed; 32]);
    let record = HsmKeyRecord::new(
        SignatureSuiteId::parse(ED25519_V1).expect("suite"),
        key.verifying_key().to_bytes().to_vec(),
        "pkcs11-v1".to_string(),
        "auths-test-hsm".to_string(),
        "non-exportable".to_string(),
        [seed; 32],
        [seed.wrapping_add(1); 32],
        true,
        Timestamp::new(40),
        Timestamp::new(60),
    )
    .expect("fixed HSM record");
    (key, record)
}

struct SpiffeMaterial {
    key: Ed25519SigningKey,
    principal: PrincipalId,
    verification_method: VerificationMethod,
    evidence: SpiffeX509Evidence,
    trust: SpiffeTrustDomain,
    status: SpiffeStatusRecord,
}

fn rcgen_ed25519_key(key: &Ed25519SigningKey) -> KeyPair {
    let document = key.to_pkcs8_der().expect("fixed Ed25519 PKCS#8");
    let der = PrivatePkcs8KeyDer::from(document.as_bytes().to_vec());
    KeyPair::from_pkcs8_der_and_sign_algo(&der, &PKCS_ED25519).expect("rcgen Ed25519 key")
}

fn spiffe_material(seed: u8) -> SpiffeMaterial {
    let ca_signing_key = Ed25519SigningKey::from_bytes(&[60; 32]);
    let ca_key = rcgen_ed25519_key(&ca_signing_key);
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA parameters");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    ca_params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    ca_params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    ca_params.serial_number = Some(SerialNumber::from(60u64));
    let ca_certificate = ca_params.self_signed(&ca_key).expect("CA certificate");

    let key = Ed25519SigningKey::from_bytes(&[seed; 32]);
    let leaf_key = rcgen_ed25519_key(&key);
    let principal =
        PrincipalId::parse(&format!("spiffe://auths.example/workload/{seed}")).expect("SPIFFE ID");
    let mut leaf_params = CertificateParams::new(Vec::<String>::new()).expect("leaf parameters");
    leaf_params.subject_alt_names = vec![SanType::URI(
        principal.as_str().try_into().expect("SPIFFE URI"),
    )];
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    leaf_params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    leaf_params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    leaf_params.serial_number = Some(SerialNumber::from(u64::from(seed)));
    let leaf = leaf_params
        .signed_by(&leaf_key, &ca_certificate, &ca_key)
        .expect("leaf certificate");
    let evidence = SpiffeX509Evidence::new(vec![leaf.der().to_vec()]).expect("SVID evidence");
    let leaf_digest = evidence.leaf_digest();
    SpiffeMaterial {
        key,
        principal: principal.clone(),
        verification_method: svid_verification_method(&principal, leaf_digest)
            .expect("SVID method"),
        evidence,
        trust: SpiffeTrustDomain::new(
            "auths.example".to_string(),
            vec![ca_certificate.der().to_vec()],
            true,
        )
        .expect("SPIFFE trust"),
        status: SpiffeStatusRecord::new(leaf_digest, true, Timestamp::new(40), Timestamp::new(60))
            .expect("SVID status"),
    }
}

fn profile() -> ProfileRef {
    ProfileRef::new(ProfileId::parse("auths.mcp").expect("profile"), 1).expect("profile version")
}

fn permission() -> Permission {
    Permission::new(
        CapabilityId::parse("tools/call").expect("capability"),
        ResourceId::parse("mcp://reports/read").expect("resource"),
    )
}

fn audience() -> Audience {
    Audience::parse("mcp://reports").expect("audience")
}

fn canonical_action(body: Vec<u8>) -> CanonicalAction {
    CanonicalAction::new(
        profile(),
        MediaType::parse("application/vnd.auths.mcp-call.v1+cbor").expect("media type"),
        body,
        permission(),
        Some(BudgetCeiling::new(
            BudgetAlgebraId::parse("numeric-ceiling-v1").expect("budget algebra"),
            5,
        )),
    )
    .expect("canonical action")
}

fn assurance_policy(identities: &[Identity]) -> AssurancePolicy {
    let root_claim = AssuranceClaimId::parse(
        identities
            .first()
            .expect("fixture identity")
            .assurance_claim(),
    )
    .expect("claim");
    let actor_claim = AssuranceClaimId::parse(
        identities
            .last()
            .expect("fixture identity")
            .assurance_claim(),
    )
    .expect("claim");
    AssurancePolicy::new(
        AssurancePolicyId::parse("raw-key-baseline").expect("policy"),
        vec![
            AssuranceRequirement::new(
                ParticipantRole::Root,
                AssuranceQuantifier::Every,
                root_claim,
                None,
            ),
            AssuranceRequirement::new(
                ParticipantRole::Actor,
                AssuranceQuantifier::Every,
                actor_claim,
                None,
            ),
        ],
    )
    .expect("assurance policy")
}

fn registries_with_status(
    identities: &[Identity],
    principal_status_methods: Vec<StatusMethodId>,
    grant_status_methods: Vec<StatusMethodId>,
) -> AcceptedRegistries {
    let mut suites: Vec<_> = identities
        .iter()
        .map(|identity| SignatureSuiteId::parse(identity.suite()).expect("suite"))
        .collect();
    suites.sort();
    suites.dedup();
    let mut methods: Vec<_> = identities
        .iter()
        .map(|identity| PrincipalMethodId::parse(identity.method_id()).expect("method"))
        .collect();
    methods.sort();
    methods.dedup();
    let mut evidence_types: Vec<_> = identities
        .iter()
        .map(|identity| EvidenceTypeId::parse(identity.method_id()).expect("evidence"))
        .collect();
    evidence_types.sort();
    evidence_types.dedup();
    AcceptedRegistries::new(
        RegistryManifestId::new([0x33; 32]),
        methods,
        suites,
        evidence_types,
        principal_status_methods,
        grant_status_methods,
        ASSURANCE_CLAIMS
            .iter()
            .map(|claim| AssuranceClaimId::parse(claim).expect("claim"))
            .collect(),
        Vec::new(),
        vec![auths_model::ResourceMatcherId::parse("uri-namespace-v1").expect("resource matcher")],
        vec![BudgetAlgebraId::parse("numeric-ceiling-v1").expect("budget")],
        Vec::new(),
        vec![profile()],
        vec![ProfilePolicyId::parse("exact-v1").expect("profile policy")],
    )
    .expect("accepted registries")
}

fn registries(identities: &[Identity]) -> AcceptedRegistries {
    registries_with_status(identities, Vec::new(), Vec::new())
}

fn anchor_with_status(identity: &Identity, depth: u16, status_policy: StatusPolicy) -> TrustAnchor {
    anchor_for_policy(
        identity,
        depth,
        status_policy,
        AssurancePolicyId::parse("raw-key-baseline").expect("policy"),
    )
}

fn anchor_for_policy(
    identity: &Identity,
    depth: u16,
    status_policy: StatusPolicy,
    assurance_policy: AssurancePolicyId,
) -> TrustAnchor {
    TrustAnchor::new(
        TrustAnchorId::parse(identity.principal.as_str()).expect("anchor"),
        identity.principal.clone(),
        vec![PrincipalMethodId::parse(identity.method_id()).expect("method")],
        vec![profile()],
        PermissionSet::new(vec![permission()]).expect("permissions"),
        vec![ResourceId::parse("mcp://reports").expect("namespace")],
        AudienceSet::new(vec![audience()]).expect("audiences"),
        ValidityWindow::new(Timestamp::new(0), Timestamp::new(100)).expect("validity"),
        Some(BudgetCeiling::new(
            BudgetAlgebraId::parse("numeric-ceiling-v1").expect("budget"),
            20,
        )),
        depth,
        assurance_policy,
        status_policy,
    )
    .expect("trust anchor")
}

fn anchor(identity: &Identity, depth: u16) -> TrustAnchor {
    anchor_with_status(identity, depth, StatusPolicy::ExpiryOnly)
}

fn context(identities: &[Identity], anchors: Vec<TrustAnchor>) -> VerifierContext {
    context_with_assurance(identities, anchors, assurance_policy(identities))
}

fn context_with_assurance(
    identities: &[Identity],
    anchors: Vec<TrustAnchor>,
    assurance: AssurancePolicy,
) -> VerifierContext {
    VerifierContext::new(
        corpus_configuration_id(),
        CompositionRequirement::new(None, 1, 1, 1).expect("baseline composition"),
        anchors,
        registries(identities),
        audience(),
        Challenge::new([0x22; 32]),
        Timestamp::new(50),
        assurance,
        PrincipalStatusSnapshot::new(
            StatusSnapshotId::new([0x44; 32]),
            Timestamp::new(0),
            Timestamp::new(100),
            Vec::new(),
            Vec::new(),
        )
        .expect("principal snapshot"),
        GrantStatusSnapshot::new(
            StatusSnapshotId::new([0x55; 32]),
            Timestamp::new(0),
            Timestamp::new(100),
            Vec::new(),
            Vec::new(),
        )
        .expect("grant snapshot"),
        auths_model::ResourceMatcherId::parse("uri-namespace-v1").expect("resource matcher"),
        ProfilePolicyId::parse("exact-v1").expect("profile policy"),
        ChannelBindingId::parse("none-v1").expect("channel policy"),
        VerifierLimits::default(),
    )
    .expect("context")
}

/// Returns the exact executable verifier configuration used by the V1 corpus.
///
/// # Panics
///
/// Panics if a fixed corpus adapter, signature suite, or canonical registry
/// cannot initialize. Such a failure means the compiled test corpus and its
/// audited implementation inventory are internally inconsistent.
#[must_use]
pub fn corpus_configuration_id() -> VerifierConfigurationId {
    static CONFIGURATION: std::sync::OnceLock<VerifierConfigurationId> = std::sync::OnceLock::new();
    *CONFIGURATION.get_or_init(|| {
        let raw_key = auths_raw_key::RawKeyMethod::new().expect("raw-key method");
        let did_key = auths_did_key::DidKeyMethod::new().expect("did:key method");
        let did_keri = auths_did_keri::DidKeriMethod::new().expect("KERI method");
        let did_web = auths_did_web::DidWebMethod::new(did_web_corpus_trust_records())
            .expect("DID-web method");
        let webauthn = auths_webauthn::WebAuthnMethod::new(webauthn_corpus_credentials())
            .expect("WebAuthn method");
        let hsm =
            auths_hsm_attested::HsmAttestedMethod::new(hsm_corpus_records()).expect("HSM method");
        let (spiffe_trust, spiffe_status) = spiffe_corpus_context();
        let spiffe = auths_spiffe_x509::SpiffeX509Method::new(spiffe_trust, spiffe_status)
            .expect("SPIFFE method");
        let ed25519 = auths_signature::Ed25519Suite::new().expect("Ed25519 suite");
        let p256 = auths_signature::P256Sha256Suite::new().expect("P-256 suite");
        let methods: [&dyn auths_ports::PrincipalMethod; 7] = [
            &raw_key, &did_key, &did_keri, &did_web, &webauthn, &hsm, &spiffe,
        ];
        let suites: [&dyn auths_ports::SignatureSuite; 2] = [&ed25519, &p256];
        auths_registries::ImmutableRegistries::new(&methods, &suites)
            .expect("canonical corpus registries")
            .configuration_id()
    })
}

fn action_envelope(
    identity: &Identity,
    canonical: &CanonicalAction,
    plan: PlanId,
    proof_ref: ProofRef,
    terminal_grant: Option<GrantId>,
) -> ActionEnvelope {
    ActionEnvelope::new(
        canonical.profile().clone(),
        canonical.media_type().clone(),
        body_digest(canonical.body()),
        canonical.permission().clone(),
        canonical.requested_budget().cloned(),
        audience(),
        Challenge::new([0x22; 32]),
        ValidityWindow::new(Timestamp::new(40), Timestamp::new(60)).expect("validity"),
        identity.principal.clone(),
        terminal_grant,
        plan,
        ChannelBindingId::parse("none-v1").expect("channel"),
        proof_ref,
        Vec::new(),
        CriticalExtensions::empty(),
    )
}

fn signed_action(identity: &Identity, envelope: ActionEnvelope) -> SignedAction {
    let request = prepare_action(envelope, identity.descriptor()).expect("action request");
    let signature = identity.sign(request.signing_preimage());
    request.complete(signature)
}

fn signed_grant(identity: &Identity, statement: GrantStatement) -> SignedGrant {
    let request = prepare_grant(statement, identity.descriptor()).expect("grant request");
    let signature = identity.sign(request.signing_preimage());
    request.complete(signature)
}

fn signed_grant_status(identity: &Identity, statement: GrantStatusStatement) -> SignedGrantStatus {
    let request =
        prepare_grant_status(statement, identity.descriptor()).expect("grant-status request");
    let signature = identity.sign(request.signing_preimage());
    request.complete(signature)
}

fn signed_principal_status(
    identity: &Identity,
    statement: PrincipalStatusStatement,
) -> SignedPrincipalStatus {
    let request = prepare_principal_status(statement, identity.descriptor())
        .expect("principal-status request");
    let signature = identity.sign(request.signing_preimage());
    request.complete(signature)
}

fn addressed_evidence(identities: &[Identity]) -> Vec<EvidenceObject> {
    let mut evidence: Vec<_> = identities.iter().map(Identity::evidence).collect();
    evidence.sort_by_key(EvidenceObject::id);
    evidence
}

fn fixture(
    name: &'static str,
    class: &'static str,
    bundle: &ProofBundle,
    context: &VerifierContext,
    canonical_action: CanonicalAction,
    expected: Expected,
) -> CorpusFixture {
    let expected_plan = plan_id(bundle.plan()).expect("fixture plan ID");
    let context = context
        .clone()
        .with_composition(CompositionRequirement::exact(expected_plan))
        .expect("exact fixture composition");
    CorpusFixture {
        name,
        class,
        proof_bytes: encode_bundle(bundle).expect("canonical proof"),
        context_bytes: encode_verifier_context(&context).expect("canonical context"),
        canonical_action,
        expected,
    }
}

fn composed_fixture(
    name: &'static str,
    identities: &[Identity],
    invalid_signature_indices: &[usize],
    make_plan: impl FnOnce(Vec<AuthorizationPlan>) -> AuthorizationPlan,
    expected: Expected,
) -> CorpusFixture {
    let canonical = canonical_action(BODY.to_vec());
    let proof_refs: Vec<_> = (0..identities.len())
        .map(|index| ProofRef::new([u8::try_from(index + 1).expect("small fixture"); 32]))
        .collect();
    let plan = make_plan(
        proof_refs
            .iter()
            .copied()
            .map(AuthorizationPlan::proof)
            .collect(),
    );
    let plan_identifier = plan_id(&plan).expect("plan ID");
    let actions: Vec<_> = identities
        .iter()
        .zip(proof_refs)
        .enumerate()
        .map(|(index, (identity, reference))| {
            let envelope = action_envelope(identity, &canonical, plan_identifier, reference, None);
            let request = prepare_action(envelope, identity.descriptor()).expect("action request");
            let signature = identity.sign(request.signing_preimage());
            if invalid_signature_indices.contains(&index) {
                let mut bytes = signature.as_slice().to_vec();
                bytes[0] ^= 1;
                request.complete(SignatureBytes::new(bytes).expect("mutated signature"))
            } else {
                request.complete(signature)
            }
        })
        .collect();
    let mut evidence = addressed_evidence(identities);
    evidence.dedup_by_key(|object| object.id());
    let bindings = actions
        .iter()
        .zip(identities.iter())
        .map(|(action, identity)| {
            ControlBinding::new(
                StatementRef::Action(action_id(action.envelope()).expect("action ID")),
                vec![identity.evidence().id()],
            )
            .expect("binding")
        })
        .collect();
    let mut anchors = Vec::new();
    for identity in identities {
        if !anchors
            .iter()
            .any(|candidate: &TrustAnchor| candidate.principal() == &identity.principal)
        {
            anchors.push(anchor(identity, 4));
        }
    }
    let offline = AssuranceClaimId::parse("offline-verifiable").expect("assurance claim");
    let verifier_context = context_with_assurance(
        identities,
        anchors,
        AssurancePolicy::new(
            AssurancePolicyId::parse("raw-key-baseline").expect("assurance policy"),
            vec![
                AssuranceRequirement::new(
                    ParticipantRole::Root,
                    AssuranceQuantifier::Every,
                    offline.clone(),
                    None,
                ),
                AssuranceRequirement::new(
                    ParticipantRole::Actor,
                    AssuranceQuantifier::Every,
                    offline,
                    None,
                ),
            ],
        )
        .expect("composition assurance policy"),
    );
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        Vec::new(),
        actions,
        plan,
        evidence,
        bindings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .expect("proof bundle");
    fixture(
        name,
        match expected {
            Expected::Authorized => "valid",
            Expected::Denied(_) => "denied",
            Expected::Indeterminate(_) => "indeterminate",
        },
        &bundle,
        &verifier_context,
        canonical,
        expected,
    )
}

#[derive(Clone, Copy)]
enum FixtureSignature {
    Normal,
    HighS,
}

struct DirectCase {
    name: &'static str,
    plan: AuthorizationPlan,
    proof_ref: ProofRef,
    terminal_grant: Option<GrantId>,
    descriptor: Option<SignatureDescriptor>,
    extra_registry_identities: Vec<Identity>,
    signature: FixtureSignature,
    expected: Expected,
}

fn direct_case(identity: &Identity, case: DirectCase) -> CorpusFixture {
    let canonical = canonical_action(BODY.to_vec());
    let plan_identifier = plan_id(&case.plan).expect("plan ID");
    let envelope = action_envelope(
        identity,
        &canonical,
        plan_identifier,
        case.proof_ref,
        case.terminal_grant,
    );
    let request = prepare_action(
        envelope,
        case.descriptor.unwrap_or_else(|| identity.descriptor()),
    )
    .expect("action request");
    let signature = match case.signature {
        FixtureSignature::Normal => identity.sign(request.signing_preimage()),
        FixtureSignature::HighS => identity.sign_high_s(request.signing_preimage()),
    };
    let action = request.complete(signature);
    let evidence = identity.evidence();
    let binding = ControlBinding::new(
        StatementRef::Action(action_id(action.envelope()).expect("action ID")),
        vec![evidence.id()],
    )
    .expect("action binding");
    let mut registry_identities = vec![identity.clone()];
    registry_identities.extend(case.extra_registry_identities);
    let verifier_context = context(&registry_identities, vec![anchor(identity, 0)]);
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        Vec::new(),
        vec![action],
        case.plan,
        vec![evidence],
        vec![binding],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .expect("direct proof");
    fixture(
        case.name,
        "invalid",
        &bundle,
        &verifier_context,
        canonical,
        case.expected,
    )
}

#[derive(Clone, Copy)]
enum GrantVariation {
    Exact,
    PermissionExpanded,
    ValidityExpanded,
    AudienceExpanded,
    BudgetExpanded,
    DepthExpanded,
    AssuranceChanged,
}

#[allow(clippy::too_many_lines)]
fn two_party_chain(
    name: &'static str,
    identities: &[Identity; 2],
    variation: GrantVariation,
) -> CorpusFixture {
    let canonical = canonical_action(BODY.to_vec());
    let proof_ref = ProofRef::new([1; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let plan_identifier = plan_id(&plan).expect("plan ID");
    let permissions = if matches!(variation, GrantVariation::PermissionExpanded) {
        PermissionSet::new(vec![Permission::new(
            CapabilityId::parse("tools/admin").expect("capability"),
            ResourceId::parse("mcp://reports/admin").expect("resource"),
        )])
        .expect("permissions")
    } else {
        PermissionSet::new(vec![permission()]).expect("permissions")
    };
    let validity = if matches!(variation, GrantVariation::ValidityExpanded) {
        ValidityWindow::new(Timestamp::new(0), Timestamp::new(101)).expect("validity")
    } else {
        ValidityWindow::new(Timestamp::new(20), Timestamp::new(80)).expect("validity")
    };
    let audiences = if matches!(variation, GrantVariation::AudienceExpanded) {
        AudienceSet::new(vec![
            Audience::parse("mcp://other-service").expect("audience"),
        ])
        .expect("audience")
    } else {
        AudienceSet::new(vec![audience()]).expect("audience")
    };
    let budget = if matches!(variation, GrantVariation::BudgetExpanded) {
        21
    } else {
        10
    };
    let depth = u16::from(matches!(variation, GrantVariation::DepthExpanded));
    let assurance = if matches!(variation, GrantVariation::AssuranceChanged) {
        AssurancePolicyId::parse("other-policy").expect("policy")
    } else {
        AssurancePolicyId::parse("raw-key-baseline").expect("policy")
    };
    let grant_statement = GrantStatement::new(
        identities[0].principal.clone(),
        identities[1].principal.clone(),
        profile(),
        permissions,
        validity,
        audiences,
        ActionConstraint::ExactBodyDigest(body_digest(canonical.body())),
        Some(BudgetCeiling::new(
            BudgetAlgebraId::parse("numeric-ceiling-v1").expect("budget"),
            budget,
        )),
        depth,
        None,
        StatusPolicy::ExpiryOnly,
        assurance,
        CriticalExtensions::empty(),
    );
    let grant = signed_grant(&identities[0], grant_statement);
    let grant_identifier = grant_id(grant.statement()).expect("grant ID");
    let action = signed_action(
        &identities[1],
        action_envelope(
            &identities[1],
            &canonical,
            plan_identifier,
            proof_ref,
            Some(grant_identifier),
        ),
    );
    let evidence = addressed_evidence(identities);
    let bindings = vec![
        ControlBinding::new(
            StatementRef::Grant(grant_identifier),
            vec![identities[0].evidence().id()],
        )
        .expect("grant binding"),
        ControlBinding::new(
            StatementRef::Action(action_id(action.envelope()).expect("action ID")),
            vec![identities[1].evidence().id()],
        )
        .expect("action binding"),
    ];
    let verifier_context = context(identities, vec![anchor(&identities[0], 1)]);
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        vec![grant],
        vec![action],
        plan,
        evidence,
        bindings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .expect("proof bundle");
    fixture(
        name,
        if matches!(variation, GrantVariation::Exact) {
            "valid"
        } else {
            "denied"
        },
        &bundle,
        &verifier_context,
        canonical,
        if matches!(variation, GrantVariation::Exact) {
            Expected::Authorized
        } else {
            Expected::Denied(DenialReason::DelegationExpanded)
        },
    )
}

/// Hand-reviewed exact-body raw-key delegation chain.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn raw_key_chain() -> CorpusFixture {
    two_party_chain(
        "raw-key-chain",
        &[Identity::ed25519(11), Identity::ed25519(12)],
        GrantVariation::Exact,
    )
}

/// `did:key` root delegates to a raw-key actor.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn did_key_root_raw_key_actor() -> CorpusFixture {
    two_party_chain(
        "did-key-root-raw-key-actor",
        &[Identity::did_key_ed25519(13), Identity::ed25519(14)],
        GrantVariation::Exact,
    )
}

/// Raw-key root delegates to a `did:key` actor.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn raw_key_root_did_key_actor() -> CorpusFixture {
    two_party_chain(
        "raw-key-root-did-key-actor",
        &[Identity::ed25519(15), Identity::did_key_ed25519(16)],
        GrantVariation::Exact,
    )
}

/// Rotated `did:keri` root delegates to a raw-key actor.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn did_keri_root_raw_key_actor() -> CorpusFixture {
    two_party_chain(
        "did-keri-root-raw-key-actor",
        &[Identity::did_keri_ed25519(23), Identity::ed25519(25)],
        GrantVariation::Exact,
    )
}

/// Raw-key root delegates to a rotated `did:keri` actor.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn raw_key_root_did_keri_actor() -> CorpusFixture {
    two_party_chain(
        "raw-key-root-did-keri-actor",
        &[Identity::ed25519(26), Identity::did_keri_ed25519(27)],
        GrantVariation::Exact,
    )
}

/// A SPIFFE X.509-SVID workload root delegates to a raw-key actor.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn spiffe_root_raw_key_actor() -> CorpusFixture {
    two_party_chain(
        "spiffe-root-raw-key-actor",
        &[Identity::spiffe_ed25519(61), Identity::ed25519(63)],
        GrantVariation::Exact,
    )
}

/// A raw-key root delegates to a SPIFFE X.509-SVID workload actor.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn raw_key_root_spiffe_actor() -> CorpusFixture {
    two_party_chain(
        "raw-key-root-spiffe-actor",
        &[Identity::ed25519(64), Identity::spiffe_ed25519(65)],
        GrantVariation::Exact,
    )
}

/// Bundled `did:web` root delegates to a raw-key actor.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn did_web_root_raw_key_actor() -> CorpusFixture {
    two_party_chain(
        "did-web-root-raw-key-actor",
        &[
            Identity::did_web_ed25519("did:web:root.auths.example", 17),
            Identity::ed25519(18),
        ],
        GrantVariation::Exact,
    )
}

/// Raw-key root delegates to a bundled `did:web` actor.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn raw_key_root_did_web_actor() -> CorpusFixture {
    two_party_chain(
        "raw-key-root-did-web-actor",
        &[
            Identity::ed25519(19),
            Identity::did_web_ed25519("did:web:actor.auths.example", 20),
        ],
        GrantVariation::Exact,
    )
}

fn exact_grant_statement(
    issuer: &PrincipalId,
    subject: &PrincipalId,
    canonical: &CanonicalAction,
) -> GrantStatement {
    GrantStatement::new(
        issuer.clone(),
        subject.clone(),
        profile(),
        PermissionSet::new(vec![permission()]).expect("permissions"),
        ValidityWindow::new(Timestamp::new(20), Timestamp::new(80)).expect("validity"),
        AudienceSet::new(vec![audience()]).expect("audience"),
        ActionConstraint::ExactBodyDigest(body_digest(canonical.body())),
        Some(BudgetCeiling::new(
            BudgetAlgebraId::parse("numeric-ceiling-v1").expect("budget"),
            10,
        )),
        0,
        None,
        StatusPolicy::ExpiryOnly,
        AssurancePolicyId::parse("raw-key-baseline").expect("policy"),
        CriticalExtensions::empty(),
    )
}

/// A user-verified `WebAuthn` root delegates to a raw-key actor.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn webauthn_root_raw_key_actor() -> CorpusFixture {
    let canonical = canonical_action(BODY.to_vec());
    let (_, credential) = webauthn_credential(31);
    let actor = Identity::ed25519(33);
    let statement = exact_grant_statement(credential.principal(), &actor.principal, &canonical);
    let descriptor = SignatureDescriptor::new(
        PrincipalMethodId::parse(WEBAUTHN_V1).expect("method"),
        credential.verification_method().clone(),
        SignatureSuiteId::parse(P256_SHA256_V1).expect("suite"),
    );
    let request = prepare_grant(statement.clone(), descriptor).expect("grant request");
    let root = Identity::webauthn_p256(31, request.signing_preimage());
    let grant = signed_grant(&root, statement);
    mixed_chain_fixture(
        "webauthn-root-raw-key-actor",
        &[root, actor],
        grant,
        canonical,
    )
}

/// A raw-key root delegates to a user-verified `WebAuthn` actor.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn raw_key_root_webauthn_actor() -> CorpusFixture {
    let canonical = canonical_action(BODY.to_vec());
    let root = Identity::ed25519(34);
    let (_, credential) = webauthn_credential(35);
    let statement = exact_grant_statement(&root.principal, credential.principal(), &canonical);
    let grant = signed_grant(&root, statement);
    let grant_identifier = grant_id(grant.statement()).expect("grant ID");
    let proof_ref = ProofRef::new([1; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let envelope = ActionEnvelope::new(
        canonical.profile().clone(),
        canonical.media_type().clone(),
        body_digest(canonical.body()),
        canonical.permission().clone(),
        canonical.requested_budget().cloned(),
        audience(),
        Challenge::new([0x22; 32]),
        ValidityWindow::new(Timestamp::new(40), Timestamp::new(60)).expect("validity"),
        credential.principal().clone(),
        Some(grant_identifier),
        plan_id(&plan).expect("plan ID"),
        ChannelBindingId::parse("none-v1").expect("channel"),
        proof_ref,
        Vec::new(),
        CriticalExtensions::empty(),
    );
    let descriptor = SignatureDescriptor::new(
        PrincipalMethodId::parse(WEBAUTHN_V1).expect("method"),
        credential.verification_method().clone(),
        SignatureSuiteId::parse(P256_SHA256_V1).expect("suite"),
    );
    let request = prepare_action(envelope, descriptor).expect("action request");
    let actor = Identity::webauthn_p256(35, request.signing_preimage());
    mixed_chain_fixture(
        "raw-key-root-webauthn-actor",
        &[root, actor],
        grant,
        canonical,
    )
}

/// An HSM-attested root delegates to a raw-key actor.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn hsm_root_raw_key_actor() -> CorpusFixture {
    let canonical = canonical_action(BODY.to_vec());
    let (_, record) = hsm_record(41);
    let actor = Identity::ed25519(43);
    let statement = exact_grant_statement(record.principal(), &actor.principal, &canonical);
    let descriptor = SignatureDescriptor::new(
        PrincipalMethodId::parse(HSM_ATTESTED_V1).expect("method"),
        record.verification_method().clone(),
        SignatureSuiteId::parse(ED25519_V1).expect("suite"),
    );
    let request = prepare_grant(statement.clone(), descriptor).expect("grant request");
    let root = Identity::hsm_ed25519(41, request.signing_preimage());
    let grant = signed_grant(&root, statement);
    mixed_chain_fixture("hsm-root-raw-key-actor", &[root, actor], grant, canonical)
}

/// A raw-key root delegates to an HSM-attested actor.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn raw_key_root_hsm_actor() -> CorpusFixture {
    let canonical = canonical_action(BODY.to_vec());
    let root = Identity::ed25519(44);
    let (_, record) = hsm_record(45);
    let statement = exact_grant_statement(&root.principal, record.principal(), &canonical);
    let grant = signed_grant(&root, statement);
    let grant_identifier = grant_id(grant.statement()).expect("grant ID");
    let proof_ref = ProofRef::new([1; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let envelope = ActionEnvelope::new(
        canonical.profile().clone(),
        canonical.media_type().clone(),
        body_digest(canonical.body()),
        canonical.permission().clone(),
        canonical.requested_budget().cloned(),
        audience(),
        Challenge::new([0x22; 32]),
        ValidityWindow::new(Timestamp::new(40), Timestamp::new(60)).expect("validity"),
        record.principal().clone(),
        Some(grant_identifier),
        plan_id(&plan).expect("plan ID"),
        ChannelBindingId::parse("none-v1").expect("channel"),
        proof_ref,
        Vec::new(),
        CriticalExtensions::empty(),
    );
    let descriptor = SignatureDescriptor::new(
        PrincipalMethodId::parse(HSM_ATTESTED_V1).expect("method"),
        record.verification_method().clone(),
        SignatureSuiteId::parse(ED25519_V1).expect("suite"),
    );
    let request = prepare_action(envelope, descriptor).expect("action request");
    let actor = Identity::hsm_ed25519(45, request.signing_preimage());
    mixed_chain_fixture("raw-key-root-hsm-actor", &[root, actor], grant, canonical)
}

fn mixed_chain_fixture(
    name: &'static str,
    identities: &[Identity; 2],
    grant: SignedGrant,
    canonical: CanonicalAction,
) -> CorpusFixture {
    let proof_ref = ProofRef::new([1; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let grant_identifier = grant_id(grant.statement()).expect("grant ID");
    let action = signed_action(
        &identities[1],
        action_envelope(
            &identities[1],
            &canonical,
            plan_id(&plan).expect("plan ID"),
            proof_ref,
            Some(grant_identifier),
        ),
    );
    let evidence = addressed_evidence(identities);
    let bindings = vec![
        ControlBinding::new(
            StatementRef::Grant(grant_identifier),
            vec![identities[0].evidence().id()],
        )
        .expect("grant binding"),
        ControlBinding::new(
            StatementRef::Action(action_id(action.envelope()).expect("action ID")),
            vec![identities[1].evidence().id()],
        )
        .expect("action binding"),
    ];
    let verifier_context = context(identities, vec![anchor(&identities[0], 1)]);
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        vec![grant],
        vec![action],
        plan,
        evidence,
        bindings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .expect("mixed-method proof");
    fixture(
        name,
        "valid",
        &bundle,
        &verifier_context,
        canonical,
        Expected::Authorized,
    )
}

/// Returns verifier-local `WebAuthn` registrations used by the shared corpus.
#[must_use]
pub fn webauthn_corpus_credentials() -> Vec<WebAuthnCredential> {
    [31, 35]
        .into_iter()
        .map(|seed| webauthn_credential(seed).1)
        .collect()
}

/// Returns verifier-local HSM attestation records used by the shared corpus.
#[must_use]
pub fn hsm_corpus_records() -> Vec<HsmKeyRecord> {
    [41, 45]
        .into_iter()
        .map(|seed| hsm_record(seed).1)
        .collect()
}

/// Returns verifier-local SPIFFE trust bundles and leaf status used by the
/// shared corpus.
#[must_use]
pub fn spiffe_corpus_context() -> (Vec<SpiffeTrustDomain>, Vec<SpiffeStatusRecord>) {
    let first = spiffe_material(61);
    let second = spiffe_material(65);
    (vec![first.trust], vec![first.status, second.status])
}

/// A valid bundled document without verifier-local trust is indeterminate.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn untrusted_did_web_document() -> CorpusFixture {
    let identity = Identity::did_web_ed25519("did:web:untrusted.auths.example", 22);
    let proof_ref = ProofRef::new([0xd1; 32]);
    direct_case(
        &identity,
        DirectCase {
            name: "untrusted-did-web-document",
            plan: AuthorizationPlan::proof(proof_ref),
            proof_ref,
            terminal_grant: None,
            descriptor: None,
            extra_registry_identities: Vec::new(),
            signature: FixtureSignature::Normal,
            expected: Expected::Indeterminate(Requirement::ExternalFactUnavailable),
        },
    )
}

/// Historical controller state without exact statement existence cannot
/// satisfy a policy that requires both facts.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn did_web_history_without_statement_existence() -> CorpusFixture {
    let identity = Identity::did_web_ed25519("did:web:historical.auths.example", 21);
    let canonical = canonical_action(BODY.to_vec());
    let proof_ref = ProofRef::new([0xd2; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let plan_identifier = plan_id(&plan).expect("plan ID");
    let action = signed_action(
        &identity,
        action_envelope(&identity, &canonical, plan_identifier, proof_ref, None),
    );
    let evidence = identity.evidence();
    let binding = ControlBinding::new(
        StatementRef::Action(action_id(action.envelope()).expect("action ID")),
        vec![evidence.id()],
    )
    .expect("action binding");
    let policy_id = AssurancePolicyId::parse("did-web-history-v1").expect("policy");
    let assurance = AssurancePolicy::new(
        policy_id.clone(),
        vec![
            AssuranceRequirement::new(
                ParticipantRole::Root,
                AssuranceQuantifier::Every,
                AssuranceClaimId::parse("historical-at").expect("claim"),
                None,
            ),
            AssuranceRequirement::new(
                ParticipantRole::Actor,
                AssuranceQuantifier::Every,
                AssuranceClaimId::parse("statement-existence-proven-at").expect("claim"),
                None,
            ),
        ],
    )
    .expect("assurance policy");
    let verifier_context = context_with_assurance(
        core::slice::from_ref(&identity),
        vec![anchor_for_policy(
            &identity,
            0,
            StatusPolicy::ExpiryOnly,
            policy_id,
        )],
        assurance,
    );
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        Vec::new(),
        vec![action],
        plan,
        vec![evidence],
        vec![binding],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .expect("historical did:web proof");
    fixture(
        "did-web-history-without-statement-existence",
        "indeterminate",
        &bundle,
        &verifier_context,
        canonical,
        Expected::Indeterminate(Requirement::AssuranceRequirementNotMet),
    )
}

/// A known bundled document without a historical interval covering signing
/// time is indeterminate rather than silently treated as current.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn did_web_historical_state_unavailable() -> CorpusFixture {
    let identity = Identity::did_web_ed25519("did:web:history-unavailable.auths.example", 29);
    let proof_ref = ProofRef::new([0xd3; 32]);
    direct_case(
        &identity,
        DirectCase {
            name: "did-web-historical-state-unavailable",
            plan: AuthorizationPlan::proof(proof_ref),
            proof_ref,
            terminal_grant: None,
            descriptor: None,
            extra_registry_identities: Vec::new(),
            signature: FixtureSignature::Normal,
            expected: Expected::Indeterminate(Requirement::HistoricalStateUnavailable),
        },
    )
}

/// Returns verifier-local trust records for every bundled `did:web` corpus
/// identity.
///
/// # Panics
///
/// Panics only if repository-owned fixed trust inputs violate target model
/// invariants.
#[must_use]
pub fn did_web_corpus_trust_records() -> Vec<DidWebTrustRecord> {
    [
        Identity::did_web_ed25519("did:web:root.auths.example", 17),
        Identity::did_web_ed25519("did:web:actor.auths.example", 20),
        Identity::did_web_ed25519("did:web:historical.auths.example", 21),
        Identity::did_web_ed25519("did:web:history-unavailable.auths.example", 29),
    ]
    .iter()
    .filter_map(|identity| {
        if identity.principal.as_str() == "did:web:historical.auths.example" {
            let PrincipalKind::DidWeb { evidence, .. } = &identity.principal_kind else {
                return None;
            };
            Some(
                DidWebTrustRecord::historical(
                    identity.principal.clone(),
                    evidence.document_digest(),
                    Timestamp::new(0),
                    Timestamp::new(45),
                    None,
                )
                .expect("fixed historical did:web trust"),
            )
        } else if identity.principal.as_str() == "did:web:history-unavailable.auths.example" {
            let PrincipalKind::DidWeb { evidence, .. } = &identity.principal_kind else {
                return None;
            };
            Some(
                DidWebTrustRecord::historical(
                    identity.principal.clone(),
                    evidence.document_digest(),
                    Timestamp::new(0),
                    Timestamp::new(10),
                    None,
                )
                .expect("fixed unavailable historical did:web trust"),
            )
        } else {
            identity.did_web_current_trust()
        }
    })
    .collect()
}

fn widening(variation: GrantVariation, name: &'static str) -> CorpusFixture {
    two_party_chain(
        name,
        &[Identity::ed25519(71), Identity::ed25519(72)],
        variation,
    )
}

/// Grant permission exceeds the root scope.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn permission_widening() -> CorpusFixture {
    widening(GrantVariation::PermissionExpanded, "permission-widening")
}

/// Grant validity exceeds the root window.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn validity_widening() -> CorpusFixture {
    widening(GrantVariation::ValidityExpanded, "validity-widening")
}

/// Grant audience is outside the root audience set.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn audience_widening() -> CorpusFixture {
    widening(GrantVariation::AudienceExpanded, "audience-widening")
}

/// Grant budget exceeds the root ceiling.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn budget_widening() -> CorpusFixture {
    widening(GrantVariation::BudgetExpanded, "budget-widening")
}

/// Grant depth fails to decrease from the root.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn depth_widening() -> CorpusFixture {
    widening(GrantVariation::DepthExpanded, "depth-widening")
}

/// Grant changes the root-required assurance policy.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn assurance_policy_change() -> CorpusFixture {
    widening(GrantVariation::AssuranceChanged, "assurance-policy-change")
}

#[derive(Clone, Copy)]
enum StatusVariation {
    ActiveGrant,
    MissingGrant,
    StaleGrant,
    RevokedGrant,
    GrantSequenceRollback,
    WrongGrantMethod,
    UntrustedGrantIssuer,
    GrantFreshnessBoundary,
    GrantFreshnessBeyond,
    ConflictingGrant,
    UnsupportedGrantMethod,
    RevokedPrincipal,
}

fn required_status(method: &str) -> StatusPolicy {
    StatusPolicy::SnapshotRequired {
        method: StatusMethodId::parse(method).expect("status method"),
        max_age: FreshnessLimit::new(20).expect("freshness"),
    }
}

#[allow(clippy::too_many_lines)]
fn status_fixture(name: &'static str, variation: StatusVariation) -> CorpusFixture {
    const PRINCIPAL_STATUS_METHOD: &str = "auths-principal-status-v1";
    const GRANT_STATUS_METHOD: &str = "auths-grant-status-v1";
    let identities = [Identity::ed25519(91), Identity::ed25519(92)];
    let canonical = canonical_action(BODY.to_vec());
    let proof_ref = ProofRef::new([0x91; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let plan_identifier = plan_id(&plan).expect("plan ID");
    let grant_policy = match variation {
        StatusVariation::MissingGrant
        | StatusVariation::StaleGrant
        | StatusVariation::RevokedGrant
        | StatusVariation::GrantSequenceRollback
        | StatusVariation::ActiveGrant
        | StatusVariation::WrongGrantMethod
        | StatusVariation::UntrustedGrantIssuer
        | StatusVariation::GrantFreshnessBoundary
        | StatusVariation::GrantFreshnessBeyond
        | StatusVariation::ConflictingGrant => required_status(GRANT_STATUS_METHOD),
        StatusVariation::UnsupportedGrantMethod => required_status("unknown-status-v1"),
        StatusVariation::RevokedPrincipal => StatusPolicy::ExpiryOnly,
    };
    let grant = signed_grant(
        &identities[0],
        GrantStatement::new(
            identities[0].principal.clone(),
            identities[1].principal.clone(),
            profile(),
            PermissionSet::new(vec![permission()]).expect("permissions"),
            ValidityWindow::new(Timestamp::new(20), Timestamp::new(80)).expect("validity"),
            AudienceSet::new(vec![audience()]).expect("audience"),
            ActionConstraint::ExactBodyDigest(body_digest(canonical.body())),
            Some(BudgetCeiling::new(
                BudgetAlgebraId::parse("numeric-ceiling-v1").expect("budget"),
                10,
            )),
            0,
            None,
            grant_policy,
            AssurancePolicyId::parse("raw-key-baseline").expect("policy"),
            CriticalExtensions::empty(),
        ),
    );
    let grant_identifier = grant_id(grant.statement()).expect("grant ID");
    let action = signed_action(
        &identities[1],
        action_envelope(
            &identities[1],
            &canonical,
            plan_identifier,
            proof_ref,
            Some(grant_identifier),
        ),
    );
    let evidence = addressed_evidence(&identities);
    let mut bindings = vec![
        ControlBinding::new(
            StatementRef::Grant(grant_identifier),
            vec![identities[0].evidence().id()],
        )
        .expect("grant binding"),
        ControlBinding::new(
            StatementRef::Action(action_id(action.envelope()).expect("action ID")),
            vec![identities[1].evidence().id()],
        )
        .expect("action binding"),
    ];

    let mut carried_principal_status = Vec::new();
    let mut carried_grant_status = Vec::new();
    let principal_snapshot = if matches!(variation, StatusVariation::RevokedPrincipal) {
        let issuer = &identities[0];
        let statement = PrincipalStatusStatement::new(
            StatusMethodId::parse(PRINCIPAL_STATUS_METHOD).expect("status method"),
            identities[0].principal.clone(),
            PurposeId::parse(PRINCIPAL_STATUS_METHOD).expect("purpose"),
            PrincipalState::Revoked,
            1,
            Timestamp::new(40),
            Timestamp::new(100),
            issuer.principal.clone(),
            CriticalExtensions::empty(),
        )
        .expect("principal status");
        let signed = signed_principal_status(issuer, statement);
        let identifier = principal_status_id(signed.statement()).expect("principal status ID");
        bindings.push(
            ControlBinding::new(
                StatementRef::PrincipalStatus(identifier),
                vec![issuer.evidence().id()],
            )
            .expect("principal-status binding"),
        );
        carried_principal_status.push(signed.clone());
        PrincipalStatusSnapshot::with_trust(
            StatusSnapshotId::new([0x92; 32]),
            Timestamp::new(40),
            Timestamp::new(100),
            vec![signed],
            Vec::new(),
            vec![auths_model::StatusTrustRule::new(
                StatusMethodId::parse(PRINCIPAL_STATUS_METHOD).expect("status method"),
                identities[0].principal.clone(),
                1,
            )],
        )
        .expect("principal snapshot")
    } else {
        PrincipalStatusSnapshot::new(
            StatusSnapshotId::new([0x92; 32]),
            Timestamp::new(0),
            Timestamp::new(100),
            Vec::new(),
            Vec::new(),
        )
        .expect("principal snapshot")
    };
    let grant_snapshot = if matches!(
        variation,
        StatusVariation::ActiveGrant
            | StatusVariation::RevokedGrant
            | StatusVariation::GrantSequenceRollback
            | StatusVariation::WrongGrantMethod
            | StatusVariation::UntrustedGrantIssuer
            | StatusVariation::GrantFreshnessBoundary
            | StatusVariation::GrantFreshnessBeyond
            | StatusVariation::ConflictingGrant
    ) {
        let (state, sequence) = if matches!(variation, StatusVariation::GrantSequenceRollback) {
            let older = GrantStatusStatement::new(
                StatusMethodId::parse(GRANT_STATUS_METHOD).expect("status method"),
                grant_identifier,
                GrantState::Active,
                1,
                Timestamp::new(30),
                Timestamp::new(100),
                identities[0].principal.clone(),
                CriticalExtensions::empty(),
            )
            .expect("older grant status");
            carried_grant_status.push(signed_grant_status(&identities[0], older));
            (GrantState::Active, 2)
        } else if matches!(
            variation,
            StatusVariation::RevokedGrant | StatusVariation::ConflictingGrant
        ) {
            (GrantState::Revoked, 1)
        } else {
            (GrantState::Active, 1)
        };
        let method = if matches!(variation, StatusVariation::WrongGrantMethod) {
            "other-grant-status-v1"
        } else {
            GRANT_STATUS_METHOD
        };
        let issuer = if matches!(variation, StatusVariation::UntrustedGrantIssuer) {
            &identities[1]
        } else {
            &identities[0]
        };
        let observed_at = if matches!(variation, StatusVariation::GrantFreshnessBeyond) {
            29
        } else if matches!(variation, StatusVariation::GrantFreshnessBoundary) {
            30
        } else {
            40
        };
        let statement = GrantStatusStatement::new(
            StatusMethodId::parse(method).expect("status method"),
            grant_identifier,
            state,
            sequence,
            Timestamp::new(observed_at),
            Timestamp::new(100),
            issuer.principal.clone(),
            CriticalExtensions::empty(),
        )
        .expect("grant status");
        let signed = signed_grant_status(issuer, statement);
        let identifier = grant_status_id(signed.statement()).expect("grant status ID");
        bindings.push(
            ControlBinding::new(
                StatementRef::GrantStatus(identifier),
                vec![issuer.evidence().id()],
            )
            .expect("grant-status binding"),
        );
        let mut statements = vec![signed.clone()];
        let mut trust = vec![auths_model::StatusTrustRule::new(
            StatusMethodId::parse(GRANT_STATUS_METHOD).expect("status method"),
            identities[0].principal.clone(),
            1,
        )];
        if matches!(variation, StatusVariation::ConflictingGrant) {
            let active = GrantStatusStatement::new(
                StatusMethodId::parse(GRANT_STATUS_METHOD).expect("status method"),
                grant_identifier,
                GrantState::Active,
                1,
                Timestamp::new(40),
                Timestamp::new(100),
                identities[1].principal.clone(),
                CriticalExtensions::empty(),
            )
            .expect("conflicting active grant status");
            let signed_active = signed_grant_status(&identities[1], active);
            let active_id =
                grant_status_id(signed_active.statement()).expect("active grant status ID");
            bindings.push(
                ControlBinding::new(
                    StatementRef::GrantStatus(active_id),
                    vec![identities[1].evidence().id()],
                )
                .expect("active grant-status binding"),
            );
            statements.push(signed_active);
            trust.push(auths_model::StatusTrustRule::new(
                StatusMethodId::parse(GRANT_STATUS_METHOD).expect("status method"),
                identities[1].principal.clone(),
                1,
            ));
        }
        if matches!(variation, StatusVariation::RevokedGrant) {
            carried_grant_status.push(signed.clone());
        }
        GrantStatusSnapshot::with_trust(
            StatusSnapshotId::new([0x93; 32]),
            Timestamp::new(40),
            Timestamp::new(100),
            statements,
            Vec::new(),
            trust,
        )
        .expect("grant snapshot")
    } else if matches!(variation, StatusVariation::StaleGrant) {
        GrantStatusSnapshot::new(
            StatusSnapshotId::new([0x93; 32]),
            Timestamp::new(0),
            Timestamp::new(49),
            Vec::new(),
            Vec::new(),
        )
        .expect("stale grant snapshot")
    } else {
        GrantStatusSnapshot::new(
            StatusSnapshotId::new([0x93; 32]),
            Timestamp::new(0),
            Timestamp::new(100),
            Vec::new(),
            Vec::new(),
        )
        .expect("grant snapshot")
    };

    let principal_methods = if matches!(variation, StatusVariation::RevokedPrincipal) {
        vec![StatusMethodId::parse(PRINCIPAL_STATUS_METHOD).expect("status method")]
    } else {
        Vec::new()
    };
    let grant_methods = if matches!(
        variation,
        StatusVariation::MissingGrant
            | StatusVariation::StaleGrant
            | StatusVariation::RevokedGrant
            | StatusVariation::GrantSequenceRollback
            | StatusVariation::ActiveGrant
            | StatusVariation::WrongGrantMethod
            | StatusVariation::UntrustedGrantIssuer
            | StatusVariation::GrantFreshnessBoundary
            | StatusVariation::GrantFreshnessBeyond
            | StatusVariation::ConflictingGrant
    ) {
        vec![StatusMethodId::parse(GRANT_STATUS_METHOD).expect("status method")]
    } else {
        Vec::new()
    };
    let anchor_policy = if matches!(variation, StatusVariation::RevokedPrincipal) {
        required_status(PRINCIPAL_STATUS_METHOD)
    } else {
        StatusPolicy::ExpiryOnly
    };
    let verifier_context = VerifierContext::new(
        corpus_configuration_id(),
        CompositionRequirement::new(None, 1, 1, 1).expect("baseline composition"),
        vec![anchor_with_status(&identities[0], 1, anchor_policy)],
        registries_with_status(&identities, principal_methods, grant_methods),
        audience(),
        Challenge::new([0x22; 32]),
        Timestamp::new(50),
        assurance_policy(&identities),
        principal_snapshot,
        grant_snapshot,
        auths_model::ResourceMatcherId::parse("uri-namespace-v1").expect("resource matcher"),
        ProfilePolicyId::parse("exact-v1").expect("profile policy"),
        ChannelBindingId::parse("none-v1").expect("channel policy"),
        VerifierLimits::default(),
    )
    .expect("status context");
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        vec![grant],
        vec![action],
        plan,
        evidence,
        bindings,
        carried_principal_status,
        carried_grant_status,
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .expect("status proof");
    let expected = match variation {
        StatusVariation::ActiveGrant | StatusVariation::GrantFreshnessBoundary => {
            Expected::Authorized
        }
        StatusVariation::MissingGrant => Expected::Indeterminate(Requirement::MissingGrantStatus),
        StatusVariation::StaleGrant | StatusVariation::GrantFreshnessBeyond => {
            Expected::Indeterminate(Requirement::StaleStatus)
        }
        StatusVariation::RevokedGrant | StatusVariation::ConflictingGrant => {
            Expected::Denied(DenialReason::GrantRevoked)
        }
        StatusVariation::GrantSequenceRollback => {
            Expected::Denied(DenialReason::StatusSequenceRollback)
        }
        StatusVariation::WrongGrantMethod => Expected::Denied(DenialReason::StatusMethodMismatch),
        StatusVariation::UntrustedGrantIssuer => {
            Expected::Denied(DenialReason::StatusIssuerUntrusted)
        }
        StatusVariation::UnsupportedGrantMethod => {
            Expected::Indeterminate(Requirement::UnsupportedStatusMethod)
        }
        StatusVariation::RevokedPrincipal => Expected::Denied(DenialReason::PrincipalRevoked),
    };
    fixture(
        name,
        "denied",
        &bundle,
        &verifier_context,
        canonical,
        expected,
    )
}

/// Required grant status is absent.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn missing_grant_status() -> CorpusFixture {
    status_fixture("missing-grant-status", StatusVariation::MissingGrant)
}

/// Required grant status snapshot is stale at evaluation time.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn stale_grant_status() -> CorpusFixture {
    status_fixture("stale-grant-status", StatusVariation::StaleGrant)
}

/// Signed current grant status explicitly revokes the parent grant.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn revoked_grant_status() -> CorpusFixture {
    status_fixture("revoked-grant-status", StatusVariation::RevokedGrant)
}

/// Proof-carried grant status is older than the verifier's current sequence.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn grant_status_sequence_rollback() -> CorpusFixture {
    status_fixture(
        "grant-status-sequence-rollback",
        StatusVariation::GrantSequenceRollback,
    )
}

/// Grant selects a status method absent from the exact registry.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn unsupported_grant_status_method() -> CorpusFixture {
    status_fixture(
        "unsupported-grant-status-method",
        StatusVariation::UnsupportedGrantMethod,
    )
}

/// Signed current principal status explicitly revokes the root principal.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn revoked_principal_status() -> CorpusFixture {
    status_fixture(
        "revoked-principal-status",
        StatusVariation::RevokedPrincipal,
    )
}

fn principal_status_selection_fixture(
    name: &'static str,
    untrusted_issuer: bool,
    expected: Expected,
) -> CorpusFixture {
    const METHOD: &str = "auths-principal-status-v1";
    let root = Identity::ed25519(151);
    let other = Identity::ed25519(152);
    let issuer = if untrusted_issuer { &other } else { &root };
    let canonical = canonical_action(BODY.to_vec());
    let proof_ref = ProofRef::new([0x96; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let action = signed_action(
        &root,
        action_envelope(
            &root,
            &canonical,
            plan_id(&plan).expect("plan ID"),
            proof_ref,
            None,
        ),
    );
    let statement = PrincipalStatusStatement::new(
        StatusMethodId::parse(METHOD).expect("status method"),
        root.principal.clone(),
        PurposeId::parse(METHOD).expect("purpose"),
        PrincipalState::Active,
        1,
        Timestamp::new(40),
        Timestamp::new(100),
        issuer.principal.clone(),
        CriticalExtensions::empty(),
    )
    .expect("principal status");
    let status = signed_principal_status(issuer, statement);
    let status_id = principal_status_id(status.statement()).expect("status ID");
    let action_id = action_id(action.envelope()).expect("action ID");
    let context = VerifierContext::new(
        corpus_configuration_id(),
        CompositionRequirement::new(None, 1, 1, 1).expect("baseline composition"),
        vec![anchor_with_status(&root, 1, required_status(METHOD))],
        registries_with_status(
            core::slice::from_ref(&root),
            vec![StatusMethodId::parse(METHOD).expect("status method")],
            Vec::new(),
        ),
        audience(),
        Challenge::new([0x22; 32]),
        Timestamp::new(50),
        assurance_policy(core::slice::from_ref(&root)),
        PrincipalStatusSnapshot::with_trust(
            StatusSnapshotId::new([0x97; 32]),
            Timestamp::new(40),
            Timestamp::new(100),
            vec![status],
            Vec::new(),
            vec![auths_model::StatusTrustRule::new(
                StatusMethodId::parse(METHOD).expect("status method"),
                root.principal.clone(),
                1,
            )],
        )
        .expect("principal status snapshot"),
        GrantStatusSnapshot::new(
            StatusSnapshotId::new([0x98; 32]),
            Timestamp::new(0),
            Timestamp::new(100),
            Vec::new(),
            Vec::new(),
        )
        .expect("grant snapshot"),
        ResourceMatcherId::parse("uri-namespace-v1").expect("resource matcher"),
        ProfilePolicyId::parse("exact-v1").expect("profile policy"),
        ChannelBindingId::parse("none-v1").expect("channel"),
        VerifierLimits::default(),
    )
    .expect("principal status context");
    let evidence = if untrusted_issuer {
        vec![root.evidence(), other.evidence()]
    } else {
        vec![root.evidence()]
    };
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        Vec::new(),
        vec![action],
        plan,
        evidence,
        vec![
            ControlBinding::new(StatementRef::Action(action_id), vec![root.evidence().id()])
                .expect("action binding"),
            ControlBinding::new(
                StatementRef::PrincipalStatus(status_id),
                vec![issuer.evidence().id()],
            )
            .expect("status binding"),
        ],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .expect("principal status proof");
    fixture(name, "status", &bundle, &context, canonical, expected)
}

#[derive(Clone, Copy)]
enum ActionVariation {
    Permission,
    Constraint,
    Budget,
    Validity,
    Actor,
    UnsupportedProfile,
    UnknownExtension,
    Channel,
}

#[allow(clippy::too_many_lines)]
fn action_authority_fixture(name: &'static str, variation: ActionVariation) -> CorpusFixture {
    let root = Identity::ed25519(101);
    let granted_actor = Identity::ed25519(102);
    let actual_actor = if matches!(variation, ActionVariation::Actor) {
        Identity::ed25519(103)
    } else {
        granted_actor.clone()
    };
    let action_permission = if matches!(variation, ActionVariation::Permission) {
        Permission::new(
            CapabilityId::parse("tools/admin").expect("capability"),
            ResourceId::parse("mcp://reports/admin").expect("resource"),
        )
    } else {
        permission()
    };
    let action_body = if matches!(variation, ActionVariation::Constraint) {
        let mut body = BODY.to_vec();
        body.push(0);
        body
    } else {
        BODY.to_vec()
    };
    let action_budget = if matches!(variation, ActionVariation::Budget) {
        11
    } else {
        5
    };
    let action_profile = if matches!(variation, ActionVariation::UnsupportedProfile) {
        ProfileRef::new(ProfileId::parse("auths.unknown").expect("profile"), 1)
            .expect("profile version")
    } else {
        profile()
    };
    let canonical = CanonicalAction::new(
        action_profile.clone(),
        MediaType::parse("application/vnd.auths.mcp-call.v1+cbor").expect("media type"),
        action_body,
        action_permission.clone(),
        Some(BudgetCeiling::new(
            BudgetAlgebraId::parse("numeric-ceiling-v1").expect("budget algebra"),
            action_budget,
        )),
    )
    .expect("canonical action");
    let proof_ref = ProofRef::new([0xa1; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let plan_identifier = plan_id(&plan).expect("plan ID");
    let grant = signed_grant(
        &root,
        GrantStatement::new(
            root.principal.clone(),
            granted_actor.principal,
            profile(),
            PermissionSet::new(vec![permission()]).expect("permissions"),
            ValidityWindow::new(Timestamp::new(20), Timestamp::new(80)).expect("validity"),
            AudienceSet::new(vec![audience()]).expect("audience"),
            ActionConstraint::ExactBodyDigest(body_digest(BODY)),
            Some(BudgetCeiling::new(
                BudgetAlgebraId::parse("numeric-ceiling-v1").expect("budget"),
                10,
            )),
            0,
            None,
            StatusPolicy::ExpiryOnly,
            AssurancePolicyId::parse("raw-key-baseline").expect("policy"),
            CriticalExtensions::empty(),
        ),
    );
    let grant_identifier = grant_id(grant.statement()).expect("grant ID");
    let action_validity = if matches!(variation, ActionVariation::Validity) {
        ValidityWindow::new(Timestamp::new(10), Timestamp::new(90)).expect("validity")
    } else {
        ValidityWindow::new(Timestamp::new(40), Timestamp::new(60)).expect("validity")
    };
    let extensions = if matches!(variation, ActionVariation::UnknownExtension) {
        CriticalExtensions::new(vec![
            CriticalExtension::new(
                ExtensionId::parse("unknown-critical-v1").expect("extension"),
                vec![1],
            )
            .expect("extension"),
        ])
        .expect("extensions")
    } else {
        CriticalExtensions::empty()
    };
    let channel = if matches!(variation, ActionVariation::Channel) {
        ChannelBindingId::parse("bound-recipient-v1").expect("channel")
    } else {
        ChannelBindingId::parse("none-v1").expect("channel")
    };
    let envelope = ActionEnvelope::new(
        action_profile,
        canonical.media_type().clone(),
        body_digest(canonical.body()),
        action_permission,
        canonical.requested_budget().cloned(),
        audience(),
        Challenge::new([0x22; 32]),
        action_validity,
        actual_actor.principal.clone(),
        Some(grant_identifier),
        plan_identifier,
        channel,
        proof_ref,
        Vec::new(),
        extensions,
    );
    let action = signed_action(&actual_actor, envelope);
    let identities = vec![root.clone(), actual_actor.clone()];
    let evidence = addressed_evidence(&identities);
    let bindings = vec![
        ControlBinding::new(
            StatementRef::Grant(grant_identifier),
            vec![root.evidence().id()],
        )
        .expect("grant binding"),
        ControlBinding::new(
            StatementRef::Action(action_id(action.envelope()).expect("action ID")),
            vec![actual_actor.evidence().id()],
        )
        .expect("action binding"),
    ];
    let verifier_context = context(&identities, vec![anchor(&root, 1)]);
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        vec![grant],
        vec![action],
        plan,
        evidence,
        bindings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .expect("action authority proof");
    let expected = match variation {
        ActionVariation::Permission => Expected::Denied(DenialReason::PermissionNotGranted),
        ActionVariation::Constraint => Expected::Denied(DenialReason::ActionConstraintMismatch),
        ActionVariation::Budget => Expected::Denied(DenialReason::BudgetCeilingExceeded),
        ActionVariation::Validity => Expected::Denied(DenialReason::ActionOutsideValidity),
        ActionVariation::Actor => Expected::Denied(DenialReason::BrokenGrantChain),
        ActionVariation::UnsupportedProfile => {
            Expected::Indeterminate(Requirement::UnsupportedProfile)
        }
        ActionVariation::UnknownExtension => {
            Expected::Denied(DenialReason::CriticalExtensionUnknown)
        }
        ActionVariation::Channel => Expected::Denied(DenialReason::LocalPolicyDenied),
    };
    fixture(
        name,
        "denied",
        &bundle,
        &verifier_context,
        canonical,
        expected,
    )
}

macro_rules! action_fixture {
    ($(#[$meta:meta])* $function:ident, $name:literal, $variation:ident) => {
        $(#[$meta])*
        ///
        /// # Panics
        ///
        /// Panics only if repository-owned fixture constants violate model
        /// invariants.
        #[must_use]
        pub fn $function() -> CorpusFixture {
            action_authority_fixture($name, ActionVariation::$variation)
        }
    };
}

action_fixture!(
    /// Signed action requests a permission absent from terminal authority.
    action_permission_not_granted,
    "action-permission-not-granted",
    Permission
);
action_fixture!(
    /// Signed action body falls outside the exact grant constraint.
    action_constraint_mismatch,
    "action-constraint-mismatch",
    Constraint
);
action_fixture!(
    /// Signed action requests more stateful budget than the grant permits.
    action_budget_exceeded,
    "action-budget-exceeded",
    Budget
);
action_fixture!(
    /// Signed action validity exceeds the grant window.
    action_validity_expanded,
    "action-validity-expanded",
    Validity
);
action_fixture!(
    /// Signed action actor differs from the terminal grant subject.
    action_actor_mismatch,
    "action-actor-mismatch",
    Actor
);
action_fixture!(
    /// Signed action selects a profile absent from the exact registry.
    unsupported_action_profile,
    "unsupported-action-profile",
    UnsupportedProfile
);
action_fixture!(
    /// Signed action carries an unregistered critical extension.
    unknown_action_extension,
    "unknown-action-extension",
    UnknownExtension
);
action_fixture!(
    /// Signed action channel requirement differs from verifier policy.
    action_channel_mismatch,
    "action-channel-mismatch",
    Channel
);

/// Two-party conjunction fixture.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn all_of() -> CorpusFixture {
    composed_fixture(
        "all-of",
        &[Identity::ed25519(21), Identity::ed25519(22)],
        &[],
        |members| AuthorizationPlan::all_of(members).expect("all-of"),
        Expected::Authorized,
    )
}

/// Mixed-suite two-of-three threshold fixture.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn threshold() -> CorpusFixture {
    composed_fixture(
        "threshold-2-of-3",
        &[
            Identity::ed25519(31),
            Identity::p256(2),
            Identity::ed25519(33),
        ],
        &[],
        |members| AuthorizationPlan::k_of_n(2, members).expect("threshold"),
        Expected::Authorized,
    )
}

/// Two authorized plan branches controlled by the same actor and root.
///
/// This fixture is intentionally outside the normative corpus and exists to
/// isolate verifier composition-diversity tests.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn composition_same_actor_two_branches() -> CorpusFixture {
    let actor = Identity::ed25519(34);
    composed_fixture(
        "composition-same-actor-two-branches",
        &[actor.clone(), actor],
        &[],
        |members| AuthorizationPlan::all_of(members).expect("all-of"),
        Expected::Authorized,
    )
}

/// Two authorized actors delegated by one shared root.
///
/// This fixture is intentionally outside the normative corpus and exists to
/// isolate verifier composition-diversity tests.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn composition_shared_root_two_actors() -> CorpusFixture {
    let root = Identity::ed25519(35);
    let actors = [Identity::ed25519(36), Identity::ed25519(37)];
    let canonical = canonical_action(BODY.to_vec());
    let proof_refs = [ProofRef::new([1; 32]), ProofRef::new([2; 32])];
    let plan = AuthorizationPlan::all_of(
        proof_refs
            .iter()
            .copied()
            .map(AuthorizationPlan::proof)
            .collect(),
    )
    .expect("all-of");
    let plan_identifier = plan_id(&plan).expect("plan ID");
    let grants: Vec<_> = actors
        .iter()
        .map(|actor| {
            signed_grant(
                &root,
                exact_grant_statement(&root.principal, &actor.principal, &canonical),
            )
        })
        .collect();
    let actions: Vec<_> = actors
        .iter()
        .zip(proof_refs)
        .zip(grants.iter())
        .map(|((actor, proof_ref), grant)| {
            signed_action(
                actor,
                action_envelope(
                    actor,
                    &canonical,
                    plan_identifier,
                    proof_ref,
                    Some(grant_id(grant.statement()).expect("grant ID")),
                ),
            )
        })
        .collect();
    let identities = [root.clone(), actors[0].clone(), actors[1].clone()];
    let evidence = addressed_evidence(&identities);
    let mut bindings = Vec::new();
    for grant in &grants {
        bindings.push(
            ControlBinding::new(
                StatementRef::Grant(grant_id(grant.statement()).expect("grant ID")),
                vec![root.evidence().id()],
            )
            .expect("grant binding"),
        );
    }
    for (action, actor) in actions.iter().zip(&actors) {
        bindings.push(
            ControlBinding::new(
                StatementRef::Action(action_id(action.envelope()).expect("action ID")),
                vec![actor.evidence().id()],
            )
            .expect("action binding"),
        );
    }
    let verifier_context = context(&identities, vec![anchor(&root, 1)]);
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        grants,
        actions,
        plan,
        evidence,
        bindings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .expect("shared-root composition proof");
    fixture(
        "composition-shared-root-two-actors",
        "valid",
        &bundle,
        &verifier_context,
        canonical,
        Expected::Authorized,
    )
}

/// Two authorized actors that are also two distinct roots.
///
/// This fixture is intentionally outside the normative corpus and exists to
/// isolate verifier composition-diversity tests.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn composition_distinct_roots_two_actors() -> CorpusFixture {
    composed_fixture(
        "composition-distinct-roots-two-actors",
        &[Identity::ed25519(38), Identity::ed25519(39)],
        &[],
        |members| AuthorizationPlan::all_of(members).expect("all-of"),
        Expected::Authorized,
    )
}

/// A valid `AnyOf` branch authorizes even when another branch has an invalid
/// signature; both branches still contribute reserved work.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn any_of_valid_invalid_signature() -> CorpusFixture {
    composed_fixture(
        "any-of-valid-invalid-signature",
        &[Identity::ed25519(41), Identity::ed25519(42)],
        &[1],
        |members| AuthorizationPlan::any_of(members).expect("any-of"),
        Expected::Authorized,
    )
}

/// `AnyOf` preserves an unavailable fact when no branch authorizes, even when
/// another branch is definitively denied.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn any_of_denied_indeterminate() -> CorpusFixture {
    composed_fixture(
        "any-of-denied-indeterminate",
        &[
            Identity::ed25519(43),
            Identity::did_web_ed25519("did:web:any-unavailable.auths.example", 44),
        ],
        &[0],
        |members| AuthorizationPlan::any_of(members).expect("any-of"),
        Expected::Indeterminate(Requirement::ExternalFactUnavailable),
    )
}

/// Two valid branches authorize a threshold even when the remaining branch is
/// denied; every branch is still evaluated and charged.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn threshold_mixed_success() -> CorpusFixture {
    composed_fixture(
        "threshold-mixed-success",
        &[
            Identity::ed25519(45),
            Identity::ed25519(46),
            Identity::ed25519(47),
        ],
        &[2],
        |members| AuthorizationPlan::k_of_n(2, members).expect("threshold"),
        Expected::Authorized,
    )
}

/// One valid, one denied, and one unavailable branch leave a two-of-three
/// threshold indeterminate.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn threshold_mixed_indeterminate() -> CorpusFixture {
    composed_fixture(
        "threshold-mixed-indeterminate",
        &[
            Identity::ed25519(48),
            Identity::ed25519(49),
            Identity::did_web_ed25519("did:web:threshold-unavailable.auths.example", 50),
        ],
        &[1],
        |members| AuthorizationPlan::k_of_n(2, members).expect("threshold"),
        Expected::Indeterminate(Requirement::ExternalFactUnavailable),
    )
}

/// A two-of-three threshold is denied when only one branch can authorize and
/// the remaining branches are definitively invalid.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn threshold_mixed_denied() -> CorpusFixture {
    composed_fixture(
        "threshold-mixed-denied",
        &[
            Identity::ed25519(51),
            Identity::ed25519(52),
            Identity::ed25519(53),
        ],
        &[1, 2],
        |members| AuthorizationPlan::k_of_n(2, members).expect("threshold"),
        Expected::Denied(DenialReason::InvalidSignature),
    )
}

/// Canonically encoded proof with one invalid signature.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn invalid_signature() -> CorpusFixture {
    let identities = vec![Identity::ed25519(41)];
    let canonical = canonical_action(BODY.to_vec());
    let proof_ref = ProofRef::new([1; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let envelope = action_envelope(
        &identities[0],
        &canonical,
        plan_id(&plan).expect("plan"),
        proof_ref,
        None,
    );
    let request = prepare_action(envelope, identities[0].descriptor()).expect("request");
    let mut signature = identities[0]
        .sign(request.signing_preimage())
        .as_slice()
        .to_vec();
    signature[0] ^= 1;
    let action = request.complete(SignatureBytes::new(signature).expect("signature"));
    let evidence = addressed_evidence(&identities);
    let binding = ControlBinding::new(
        StatementRef::Action(action_id(action.envelope()).expect("action ID")),
        vec![identities[0].evidence().id()],
    )
    .expect("binding");
    let verifier_context = context(&identities, vec![anchor(&identities[0], 1)]);
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        Vec::new(),
        vec![action],
        plan,
        evidence,
        vec![binding],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .expect("bundle");
    fixture(
        "invalid-signature",
        "denied",
        &bundle,
        &verifier_context,
        canonical,
        Expected::Denied(DenialReason::InvalidSignature),
    )
}

/// Action points at a grant identifier absent from the proof.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn missing_grant_reference() -> CorpusFixture {
    let proof_ref = ProofRef::new([0x81; 32]);
    direct_case(
        &Identity::ed25519(81),
        DirectCase {
            name: "missing-grant-reference",
            plan: AuthorizationPlan::proof(proof_ref),
            proof_ref,
            terminal_grant: Some(GrantId::new([0x99; 32])),
            descriptor: None,
            extra_registry_identities: Vec::new(),
            signature: FixtureSignature::Normal,
            expected: Expected::Denied(DenialReason::MissingReference),
        },
    )
}

/// Authorization plan contains a leaf with no corresponding action.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn missing_plan_leaf() -> CorpusFixture {
    let proof_ref = ProofRef::new([0x82; 32]);
    let missing = ProofRef::new([0x83; 32]);
    direct_case(
        &Identity::ed25519(82),
        DirectCase {
            name: "missing-plan-leaf",
            plan: AuthorizationPlan::all_of(vec![
                AuthorizationPlan::proof(proof_ref),
                AuthorizationPlan::proof(missing),
            ])
            .expect("all-of"),
            proof_ref,
            terminal_grant: None,
            descriptor: None,
            extra_registry_identities: Vec::new(),
            signature: FixtureSignature::Normal,
            expected: Expected::Denied(DenialReason::MissingReference),
        },
    )
}

/// Ed25519 evidence is submitted under the P-256 suite identifier.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn signature_suite_substitution() -> CorpusFixture {
    let identity = Identity::ed25519(83);
    let proof_ref = ProofRef::new([0x84; 32]);
    let descriptor = SignatureDescriptor::new(
        PrincipalMethodId::parse(RAW_KEY_V1).expect("method"),
        identity.verification_method(),
        SignatureSuiteId::parse(P256_SHA256_V1).expect("suite"),
    );
    direct_case(
        &identity,
        DirectCase {
            name: "signature-suite-substitution",
            plan: AuthorizationPlan::proof(proof_ref),
            proof_ref,
            terminal_grant: None,
            descriptor: Some(descriptor),
            extra_registry_identities: vec![Identity::p256(4)],
            signature: FixtureSignature::Normal,
            expected: Expected::Denied(DenialReason::SignatureSuiteMismatch),
        },
    )
}

/// Signed descriptor selects an unregistered signature suite.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn unknown_signature_suite() -> CorpusFixture {
    let identity = Identity::ed25519(84);
    let proof_ref = ProofRef::new([0x85; 32]);
    let descriptor = SignatureDescriptor::new(
        PrincipalMethodId::parse(RAW_KEY_V1).expect("method"),
        identity.verification_method(),
        SignatureSuiteId::parse("unknown-suite-v1").expect("suite"),
    );
    direct_case(
        &identity,
        DirectCase {
            name: "unknown-signature-suite",
            plan: AuthorizationPlan::proof(proof_ref),
            proof_ref,
            terminal_grant: None,
            descriptor: Some(descriptor),
            extra_registry_identities: Vec::new(),
            signature: FixtureSignature::Normal,
            expected: Expected::Indeterminate(Requirement::UnsupportedSignatureSuite),
        },
    )
}

/// Signed descriptor selects an unregistered principal method.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn unknown_principal_method() -> CorpusFixture {
    let identity = Identity::ed25519(85);
    let proof_ref = ProofRef::new([0x86; 32]);
    let descriptor = SignatureDescriptor::new(
        PrincipalMethodId::parse("unknown-method-v1").expect("method"),
        identity.verification_method(),
        SignatureSuiteId::parse(ED25519_V1).expect("suite"),
    );
    direct_case(
        &identity,
        DirectCase {
            name: "unknown-principal-method",
            plan: AuthorizationPlan::proof(proof_ref),
            proof_ref,
            terminal_grant: None,
            descriptor: Some(descriptor),
            extra_registry_identities: Vec::new(),
            signature: FixtureSignature::Normal,
            expected: Expected::Indeterminate(Requirement::UnsupportedPrincipalMethod),
        },
    )
}

/// Valid P-256 signature is represented with its forbidden high-S twin.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn p256_high_s_signature() -> CorpusFixture {
    let proof_ref = ProofRef::new([0x87; 32]);
    direct_case(
        &Identity::p256(5),
        DirectCase {
            name: "p256-high-s-signature",
            plan: AuthorizationPlan::proof(proof_ref),
            proof_ref,
            terminal_grant: None,
            descriptor: None,
            extra_registry_identities: Vec::new(),
            signature: FixtureSignature::HighS,
            expected: Expected::Denied(DenialReason::InvalidSignature),
        },
    )
}

fn decoded_bundle(fixture: &CorpusFixture) -> ProofBundle {
    let context = decode_context(fixture);
    decode_bundle(fixture.proof_bytes(), context.limits()).expect("repository-owned proof")
}

fn replace_context(
    mut fixture: CorpusFixture,
    name: &'static str,
    limits: VerifierLimits,
    expected: Expected,
) -> CorpusFixture {
    let context = decode_context(&fixture);
    let limited = VerifierContext::new(
        context.configuration(),
        context.composition(),
        context.trust_anchors().to_vec(),
        context.accepted_registries().clone(),
        context.expected_audience().clone(),
        context.expected_challenge(),
        context.evaluation_time(),
        context.assurance_policy().clone(),
        context.principal_status_snapshot().clone(),
        context.grant_status_snapshot().clone(),
        context.resource_matcher().clone(),
        context.profile_policy().clone(),
        context.channel_policy().clone(),
        limits,
    )
    .expect("limited context");
    fixture.name = name;
    fixture.class = "invalid";
    fixture.context_bytes = encode_verifier_context(&limited).expect("canonical context");
    fixture.expected = expected;
    fixture
}

/// Canonical proof exceeds a verifier's deployment byte limit.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn bundle_byte_limit_exceeded() -> CorpusFixture {
    let fixture = raw_key_chain();
    let limit = fixture.proof_bytes().len().saturating_sub(1);
    let limits = VerifierLimits::default()
        .with_limit(LimitKind::BundleBytes, limit)
        .expect("bundle limit");
    replace_context(
        fixture,
        "bundle-byte-limit-exceeded",
        limits,
        Expected::Denied(DenialReason::ResourceLimitExceeded),
    )
}

/// Canonical proof exceeds the deterministic adapter/crypto work budget.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn verification_work_limit_exceeded() -> CorpusFixture {
    let limits = VerifierLimits::default()
        .with_work_units(100)
        .expect("work limit");
    replace_context(
        raw_key_chain(),
        "verification-work-limit-exceeded",
        limits,
        Expected::Denied(DenialReason::ResourceLimitExceeded),
    )
}

/// Canonical plan exceeds a verifier's deployment nesting limit.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn plan_depth_limit_exceeded() -> CorpusFixture {
    let limits = VerifierLimits::default()
        .with_limit(LimitKind::PlanDepth, 0)
        .expect("plan-depth limit");
    replace_context(
        raw_key_chain(),
        "plan-depth-limit-exceeded",
        limits,
        Expected::Denied(DenialReason::ResourceLimitExceeded),
    )
}

fn replace_bundle(
    mut fixture: CorpusFixture,
    name: &'static str,
    bundle: &ProofBundle,
    expected: Expected,
) -> CorpusFixture {
    fixture.name = name;
    fixture.class = "invalid";
    fixture.proof_bytes = encode_bundle(bundle).expect("canonical proof");
    fixture.expected = expected;
    fixture
}

/// Canonical proof omitting all evidence and control bindings.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn missing_principal_evidence() -> CorpusFixture {
    let fixture = raw_key_chain();
    let bundle = decoded_bundle(&fixture);
    let rebuilt = ProofBundle::new(
        bundle.header().clone(),
        bundle.grants().to_vec(),
        bundle.actions().to_vec(),
        bundle.plan().clone(),
        Vec::new(),
        Vec::new(),
        bundle.principal_status().to_vec(),
        bundle.grant_status().to_vec(),
        bundle.attachments().to_vec(),
        bundle.canonical_body().map(<[u8]>::to_vec),
    )
    .expect("proof without evidence");
    replace_bundle(
        fixture,
        "missing-principal-evidence",
        &rebuilt,
        Expected::Indeterminate(Requirement::MissingPrincipalEvidence),
    )
}

/// Canonical proof carrying valid but unbound critical evidence.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn unused_critical_evidence() -> CorpusFixture {
    let fixture = raw_key_chain();
    let bundle = decoded_bundle(&fixture);
    let mut evidence = bundle.evidence().to_vec();
    evidence.push(Identity::ed25519(73).evidence());
    let rebuilt = ProofBundle::new(
        bundle.header().clone(),
        bundle.grants().to_vec(),
        bundle.actions().to_vec(),
        bundle.plan().clone(),
        evidence,
        bundle.bindings().to_vec(),
        bundle.principal_status().to_vec(),
        bundle.grant_status().to_vec(),
        bundle.attachments().to_vec(),
        bundle.canonical_body().map(<[u8]>::to_vec),
    )
    .expect("proof with unused evidence");
    replace_bundle(
        fixture,
        "unused-critical-evidence",
        &rebuilt,
        Expected::Denied(DenialReason::UnusedCriticalEvidence),
    )
}

/// Canonical proof containing the same action object twice.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn duplicate_action_object() -> CorpusFixture {
    let fixture = raw_key_chain();
    let bundle = decoded_bundle(&fixture);
    let action = bundle.actions()[0].clone();
    let rebuilt = ProofBundle::new(
        bundle.header().clone(),
        bundle.grants().to_vec(),
        vec![action.clone(), action],
        bundle.plan().clone(),
        bundle.evidence().to_vec(),
        bundle.bindings().to_vec(),
        bundle.principal_status().to_vec(),
        bundle.grant_status().to_vec(),
        bundle.attachments().to_vec(),
        bundle.canonical_body().map(<[u8]>::to_vec),
    )
    .expect("proof with duplicate action");
    replace_bundle(
        fixture,
        "duplicate-action-object",
        &rebuilt,
        Expected::Denied(DenialReason::DuplicateObject),
    )
}

/// Canonical proof containing the same control binding twice.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn duplicate_control_binding() -> CorpusFixture {
    let fixture = raw_key_chain();
    let bundle = decoded_bundle(&fixture);
    let binding = bundle.bindings()[0].clone();
    let mut bindings = bundle.bindings().to_vec();
    bindings.push(binding);
    let rebuilt = ProofBundle::new(
        bundle.header().clone(),
        bundle.grants().to_vec(),
        bundle.actions().to_vec(),
        bundle.plan().clone(),
        bundle.evidence().to_vec(),
        bindings,
        bundle.principal_status().to_vec(),
        bundle.grant_status().to_vec(),
        bundle.attachments().to_vec(),
        bundle.canonical_body().map(<[u8]>::to_vec),
    )
    .expect("proof with duplicate binding");
    replace_bundle(
        fixture,
        "duplicate-control-binding",
        &rebuilt,
        Expected::Denied(DenialReason::DuplicateObject),
    )
}

/// Canonical proof containing an unreferenced signed grant.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn unused_grant_object() -> CorpusFixture {
    let fixture = raw_key_chain();
    let bundle = decoded_bundle(&fixture);
    let issuer = Identity::ed25519(74);
    let subject = Identity::ed25519(75);
    let statement = GrantStatement::new(
        issuer.principal.clone(),
        subject.principal,
        profile(),
        PermissionSet::new(vec![permission()]).expect("permissions"),
        ValidityWindow::new(Timestamp::new(20), Timestamp::new(80)).expect("validity"),
        AudienceSet::new(vec![audience()]).expect("audience"),
        ActionConstraint::AnyBody,
        None,
        0,
        None,
        StatusPolicy::ExpiryOnly,
        AssurancePolicyId::parse("raw-key-baseline").expect("policy"),
        CriticalExtensions::empty(),
    );
    let mut grants = bundle.grants().to_vec();
    grants.push(signed_grant(&issuer, statement));
    let rebuilt = ProofBundle::new(
        bundle.header().clone(),
        grants,
        bundle.actions().to_vec(),
        bundle.plan().clone(),
        bundle.evidence().to_vec(),
        bundle.bindings().to_vec(),
        bundle.principal_status().to_vec(),
        bundle.grant_status().to_vec(),
        bundle.attachments().to_vec(),
        bundle.canonical_body().map(<[u8]>::to_vec),
    )
    .expect("proof with unused grant");
    replace_bundle(
        fixture,
        "unused-grant-object",
        &rebuilt,
        Expected::Denied(DenialReason::UnusedCriticalEvidence),
    )
}

/// Proof carries one more evidence object than the default deployment limit.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn evidence_count_over_default() -> CorpusFixture {
    let fixture = raw_key_chain();
    let bundle = decoded_bundle(&fixture);
    let mut evidence = bundle.evidence().to_vec();
    for seed in 120..151 {
        evidence.push(Identity::ed25519(seed).evidence());
    }
    let rebuilt = ProofBundle::new(
        bundle.header().clone(),
        bundle.grants().to_vec(),
        bundle.actions().to_vec(),
        bundle.plan().clone(),
        evidence,
        bundle.bindings().to_vec(),
        bundle.principal_status().to_vec(),
        bundle.grant_status().to_vec(),
        bundle.attachments().to_vec(),
        bundle.canonical_body().map(<[u8]>::to_vec),
    )
    .expect("over-default evidence proof");
    replace_bundle(
        fixture,
        "evidence-count-over-default",
        &rebuilt,
        Expected::Denied(DenialReason::ResourceLimitExceeded),
    )
}

fn proof_mutation(
    name: &'static str,
    mutate: impl FnOnce(&mut Vec<u8>),
    expected: DenialReason,
) -> CorpusFixture {
    proof_mutation_expected(name, mutate, Expected::Denied(expected))
}

fn proof_mutation_expected(
    name: &'static str,
    mutate: impl FnOnce(&mut Vec<u8>),
    expected: Expected,
) -> CorpusFixture {
    let mut fixture = raw_key_chain();
    fixture.name = name;
    fixture.class = "invalid";
    mutate(&mut fixture.proof_bytes);
    fixture.expected = expected;
    fixture
}

fn unsupported_protocol() -> CorpusFixture {
    proof_mutation_expected(
        "unsupported-protocol",
        |bytes| {
            assert_eq!(bytes.get(4), Some(&1));
            bytes[4] = 2;
        },
        Expected::Indeterminate(Requirement::UnsupportedProtocol),
    )
}

/// Definite-map input containing a duplicate top-level key.
#[must_use]
pub fn duplicate_cbor_key() -> CorpusFixture {
    proof_mutation(
        "duplicate-cbor-key",
        |bytes| {
            bytes[0] = 0xab;
            bytes.extend_from_slice(&[0x09, 0x80]);
        },
        DenialReason::MalformedProof,
    )
}

/// Canonical proof rewritten with a non-minimal integer representation.
///
/// # Panics
///
/// Panics if the hand-reviewed base fixture no longer has its normative CBOR
/// prefix.
#[must_use]
pub fn non_minimal_integer() -> CorpusFixture {
    proof_mutation(
        "non-minimal-integer",
        |bytes| {
            assert_eq!(&bytes[..6], &[0xaa, 0x00, 0xa2, 0x00, 0x01, 0x01]);
            bytes[4] = 0x18;
            bytes.insert(5, 0x01);
        },
        DenialReason::NonCanonicalProof,
    )
}

/// Canonical proof followed by an unconsumed byte.
#[must_use]
pub fn trailing_bytes() -> CorpusFixture {
    proof_mutation(
        "trailing-bytes",
        |bytes| bytes.push(0),
        DenialReason::MalformedProof,
    )
}

/// Proof submitted with a different application-profile version.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn mismatched_profile_version() -> CorpusFixture {
    let mut fixture = raw_key_chain();
    let source = fixture.canonical_action.clone();
    fixture.name = "mismatched-profile-version";
    fixture.class = "denied";
    fixture.canonical_action = CanonicalAction::new(
        ProfileRef::new(ProfileId::parse("auths.mcp").expect("profile"), 2)
            .expect("profile version"),
        source.media_type().clone(),
        source.body().to_vec(),
        source.permission().clone(),
        source.requested_budget().cloned(),
    )
    .expect("mismatched action");
    fixture.expected = Expected::Denied(DenialReason::ActionBodyMismatch);
    fixture
}

/// Semantically similar but byte-distinct application body.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn byte_distinct_action() -> CorpusFixture {
    let mut fixture = raw_key_chain();
    let source = fixture.canonical_action.clone();
    let mut body = source.body().to_vec();
    body.push(0);
    fixture.name = "byte-distinct-action";
    fixture.class = "denied";
    fixture.canonical_action = CanonicalAction::new(
        source.profile().clone(),
        source.media_type().clone(),
        body,
        source.permission().clone(),
        source.requested_budget().cloned(),
    )
    .expect("byte-distinct action");
    fixture.expected = Expected::Denied(DenialReason::ActionBodyMismatch);
    fixture
}

/// Verifier-local audience differs from the signed action audience.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn wrong_audience() -> CorpusFixture {
    let mut fixture = raw_key_chain();
    let context = decode_context(&fixture);
    let context = context
        .for_request(
            Audience::parse("mcp://other-service").expect("other audience"),
            context.expected_challenge(),
            context.evaluation_time(),
        )
        .expect("request context");
    fixture.name = "wrong-audience";
    fixture.class = "denied";
    fixture.context_bytes = encode_verifier_context(&context).expect("canonical context");
    fixture.expected = Expected::Denied(DenialReason::AudienceMismatch);
    fixture
}

/// Verifier-local challenge differs from the signed action challenge.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn wrong_challenge() -> CorpusFixture {
    let mut fixture = raw_key_chain();
    let context = decode_context(&fixture);
    let context = context
        .for_request(
            context.expected_audience().clone(),
            Challenge::new([0x99; 32]),
            context.evaluation_time(),
        )
        .expect("request context");
    fixture.name = "wrong-challenge";
    fixture.class = "denied";
    fixture.context_bytes = encode_verifier_context(&context).expect("canonical context");
    fixture.expected = Expected::Denied(DenialReason::ChallengeMismatch);
    fixture
}

/// Trusted context requires a different authorization plan.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn composition_requirement_not_met() -> CorpusFixture {
    let mut fixture = raw_key_chain();
    let context = decode_context(&fixture)
        .with_composition(CompositionRequirement::exact(PlanId::new([0xa5; 32])))
        .expect("composition replacement");
    fixture.name = "composition-requirement-not-met";
    fixture.class = "denied";
    fixture.context_bytes = encode_verifier_context(&context).expect("canonical context");
    fixture.expected = Expected::Denied(DenialReason::CompositionRequirementNotMet);
    fixture
}

/// Trusted context commitment differs from the executable verifier registry.
///
/// # Panics
///
/// Panics only if repository-owned fixture constants violate model invariants.
#[must_use]
pub fn verifier_configuration_mismatch() -> CorpusFixture {
    let mut fixture = raw_key_chain();
    let context = decode_context(&fixture)
        .with_configuration(VerifierConfigurationId::new([0x5a; 32]))
        .expect("configuration replacement");
    fixture.name = "verifier-configuration-mismatch";
    fixture.class = "denied";
    fixture.context_bytes = encode_verifier_context(&context).expect("canonical context");
    fixture.expected = Expected::Denied(DenialReason::VerifierConfigurationMismatch);
    fixture
}

fn decode_context(fixture: &CorpusFixture) -> VerifierContext {
    auths_codec::decode_verifier_context(fixture.context_bytes())
        .expect("repository-owned canonical context")
}

#[allow(clippy::too_many_arguments)]
fn accepted_from(
    source: &AcceptedRegistries,
    manifest: RegistryManifestId,
    resource_matchers: Vec<ResourceMatcherId>,
    critical_extensions: Vec<ExtensionId>,
    profile_policies: Vec<ProfilePolicyId>,
) -> AcceptedRegistries {
    AcceptedRegistries::new(
        manifest,
        source.principal_methods().to_vec(),
        source.signature_suites().to_vec(),
        source.evidence_types().to_vec(),
        source.principal_status_methods().to_vec(),
        source.grant_status_methods().to_vec(),
        source.assurance_claims().to_vec(),
        source.assurance_implications().to_vec(),
        resource_matchers,
        source.budget_algebras().to_vec(),
        critical_extensions,
        source.profiles().to_vec(),
        profile_policies,
    )
    .expect("accepted registry replacement")
}

fn context_replacement(
    source: &VerifierContext,
    anchors: Vec<TrustAnchor>,
    accepted: AcceptedRegistries,
    resource_matcher: ResourceMatcherId,
    profile_policy: ProfilePolicyId,
) -> VerifierContext {
    VerifierContext::new(
        source.configuration(),
        source.composition(),
        anchors,
        accepted,
        source.expected_audience().clone(),
        source.expected_challenge(),
        source.evaluation_time(),
        source.assurance_policy().clone(),
        source.principal_status_snapshot().clone(),
        source.grant_status_snapshot().clone(),
        resource_matcher,
        profile_policy,
        source.channel_policy().clone(),
        source.limits().clone(),
    )
    .expect("context replacement")
}

fn registry_semantics_fixture(
    name: &'static str,
    mutate: impl FnOnce(&VerifierContext) -> VerifierContext,
    expected: Expected,
) -> CorpusFixture {
    let mut fixture = raw_key_chain();
    let context = mutate(&decode_context(&fixture));
    fixture.name = name;
    fixture.class = match expected {
        Expected::Denied(_) => "denied",
        Expected::Indeterminate(_) => "indeterminate",
        Expected::Authorized => "valid",
    };
    fixture.context_bytes = encode_verifier_context(&context).expect("canonical context");
    fixture.expected = expected;
    fixture
}

fn registry_manifest_mismatch() -> CorpusFixture {
    registry_semantics_fixture(
        "registry-manifest-mismatch",
        |context| {
            let accepted = accepted_from(
                context.accepted_registries(),
                RegistryManifestId::new([0x99; 32]),
                context.accepted_registries().resource_matchers().to_vec(),
                context.accepted_registries().critical_extensions().to_vec(),
                context.accepted_registries().profile_policies().to_vec(),
            );
            context_replacement(
                context,
                context.trust_anchors().to_vec(),
                accepted,
                context.resource_matcher().clone(),
                context.profile_policy().clone(),
            )
        },
        Expected::Denied(DenialReason::RegistryManifestMismatch),
    )
}

fn unsupported_resource_matcher() -> CorpusFixture {
    registry_semantics_fixture(
        "unsupported-resource-matcher",
        |context| {
            let selected = ResourceMatcherId::parse("unknown-resource-v1").expect("matcher");
            let accepted = accepted_from(
                context.accepted_registries(),
                context.accepted_registries().manifest_id(),
                vec![selected.clone()],
                context.accepted_registries().critical_extensions().to_vec(),
                context.accepted_registries().profile_policies().to_vec(),
            );
            context_replacement(
                context,
                context.trust_anchors().to_vec(),
                accepted,
                selected,
                context.profile_policy().clone(),
            )
        },
        Expected::Indeterminate(Requirement::UnsupportedResourceMatcher),
    )
}

fn unsupported_profile_policy() -> CorpusFixture {
    registry_semantics_fixture(
        "unsupported-profile-policy",
        |context| {
            let selected = ProfilePolicyId::parse("unknown-profile-policy-v1").expect("policy");
            let accepted = accepted_from(
                context.accepted_registries(),
                context.accepted_registries().manifest_id(),
                context.accepted_registries().resource_matchers().to_vec(),
                context.accepted_registries().critical_extensions().to_vec(),
                vec![selected.clone()],
            );
            context_replacement(
                context,
                context.trust_anchors().to_vec(),
                accepted,
                context.resource_matcher().clone(),
                selected,
            )
        },
        Expected::Indeterminate(Requirement::UnsupportedProfilePolicy),
    )
}

fn accepted_extension_without_handler() -> CorpusFixture {
    let mut fixture = unknown_action_extension();
    let context = decode_context(&fixture);
    let extension = ExtensionId::parse("unknown-critical-v1").expect("extension");
    let accepted = accepted_from(
        context.accepted_registries(),
        context.accepted_registries().manifest_id(),
        context.accepted_registries().resource_matchers().to_vec(),
        vec![extension],
        context.accepted_registries().profile_policies().to_vec(),
    );
    let replacement = context_replacement(
        &context,
        context.trust_anchors().to_vec(),
        accepted,
        context.resource_matcher().clone(),
        context.profile_policy().clone(),
    );
    fixture.name = "accepted-extension-without-handler";
    fixture.class = "indeterminate";
    fixture.context_bytes = encode_verifier_context(&replacement).expect("canonical context");
    fixture.expected = Expected::Indeterminate(Requirement::UnsupportedCriticalExtension);
    fixture
}

fn exact_marker_extension(name: &'static str, bytes: Vec<u8>, expected: Expected) -> CorpusFixture {
    let identity = Identity::ed25519(191);
    let canonical = canonical_action(BODY.to_vec());
    let proof_ref = ProofRef::new([0xad; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let extension_id = ExtensionId::parse("exact-marker-v1").expect("extension ID");
    let envelope = ActionEnvelope::new(
        canonical.profile().clone(),
        canonical.media_type().clone(),
        body_digest(canonical.body()),
        canonical.permission().clone(),
        canonical.requested_budget().cloned(),
        audience(),
        Challenge::new([0x22; 32]),
        ValidityWindow::new(Timestamp::new(40), Timestamp::new(60)).expect("validity"),
        identity.principal.clone(),
        None,
        plan_id(&plan).expect("plan ID"),
        ChannelBindingId::parse("none-v1").expect("channel"),
        proof_ref,
        Vec::new(),
        CriticalExtensions::new(vec![
            CriticalExtension::new(extension_id.clone(), bytes).expect("extension"),
        ])
        .expect("extension set"),
    );
    let action = signed_action(&identity, envelope);
    let evidence = identity.evidence();
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        Vec::new(),
        vec![action.clone()],
        plan,
        vec![evidence.clone()],
        vec![
            ControlBinding::new(
                StatementRef::Action(action_id(action.envelope()).expect("action ID")),
                vec![evidence.id()],
            )
            .expect("binding"),
        ],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(BODY.to_vec()),
    )
    .expect("extension proof");
    let base = context(core::slice::from_ref(&identity), vec![anchor(&identity, 1)]);
    let accepted = accepted_from(
        base.accepted_registries(),
        base.accepted_registries().manifest_id(),
        base.accepted_registries().resource_matchers().to_vec(),
        vec![extension_id],
        base.accepted_registries().profile_policies().to_vec(),
    );
    let context = context_replacement(
        &base,
        base.trust_anchors().to_vec(),
        accepted,
        base.resource_matcher().clone(),
        base.profile_policy().clone(),
    );
    fixture(
        name,
        match expected {
            Expected::Authorized => "valid",
            Expected::Denied(_) => "denied",
            Expected::Indeterminate(_) => "indeterminate",
        },
        &bundle,
        &context,
        canonical,
        expected,
    )
}

fn resource_namespace_mismatch() -> CorpusFixture {
    registry_semantics_fixture(
        "resource-namespace-mismatch",
        |context| {
            let anchor = &context.trust_anchors()[0];
            let replacement = TrustAnchor::new(
                anchor.id().clone(),
                anchor.principal().clone(),
                anchor.accepted_methods().to_vec(),
                anchor.profiles().to_vec(),
                anchor.permissions().clone(),
                vec![ResourceId::parse("mcp://elsewhere").expect("namespace")],
                anchor.audiences().clone(),
                anchor.validity(),
                anchor.budget_ceiling().cloned(),
                anchor.max_delegation_depth(),
                anchor.assurance_policy().clone(),
                anchor.status_policy().clone(),
            )
            .expect("replacement anchor");
            context_replacement(
                context,
                vec![replacement],
                context.accepted_registries().clone(),
                context.resource_matcher().clone(),
                context.profile_policy().clone(),
            )
        },
        Expected::Denied(DenialReason::ResourceNamespaceMismatch),
    )
}

fn untrusted_root() -> CorpusFixture {
    registry_semantics_fixture(
        "untrusted-root",
        |context| {
            let source = &context.trust_anchors()[0];
            let anchor = TrustAnchor::new(
                TrustAnchorId::parse("different-local-root").expect("anchor"),
                PrincipalId::parse("raw:untrusted-root").expect("principal"),
                source.accepted_methods().to_vec(),
                source.profiles().to_vec(),
                source.permissions().clone(),
                source.resource_namespaces().to_vec(),
                source.audiences().clone(),
                source.validity(),
                source.budget_ceiling().cloned(),
                source.max_delegation_depth(),
                source.assurance_policy().clone(),
                source.status_policy().clone(),
            )
            .expect("unrelated anchor");
            context_replacement(
                context,
                vec![anchor],
                context.accepted_registries().clone(),
                context.resource_matcher().clone(),
                context.profile_policy().clone(),
            )
        },
        Expected::Denied(DenialReason::UntrustedRoot),
    )
}

fn unsupported_assurance_claim() -> CorpusFixture {
    registry_semantics_fixture(
        "unsupported-assurance-claim",
        |context| {
            let source = context.accepted_registries();
            let accepted = AcceptedRegistries::new(
                source.manifest_id(),
                source.principal_methods().to_vec(),
                source.signature_suites().to_vec(),
                source.evidence_types().to_vec(),
                source.principal_status_methods().to_vec(),
                source.grant_status_methods().to_vec(),
                source
                    .assurance_claims()
                    .iter()
                    .filter(|claim| claim.as_str() != "offline-verifiable")
                    .cloned()
                    .collect(),
                source.assurance_implications().to_vec(),
                source.resource_matchers().to_vec(),
                source.budget_algebras().to_vec(),
                source.critical_extensions().to_vec(),
                source.profiles().to_vec(),
                source.profile_policies().to_vec(),
            )
            .expect("claim registry");
            context_replacement(
                context,
                context.trust_anchors().to_vec(),
                accepted,
                context.resource_matcher().clone(),
                context.profile_policy().clone(),
            )
        },
        Expected::Indeterminate(Requirement::UnsupportedAssuranceClaim),
    )
}

fn missing_principal_status() -> CorpusFixture {
    registry_semantics_fixture(
        "missing-principal-status",
        |context| {
            let method = StatusMethodId::parse("auths-principal-status-v1").expect("status method");
            let source = context.accepted_registries();
            let accepted = AcceptedRegistries::new(
                source.manifest_id(),
                source.principal_methods().to_vec(),
                source.signature_suites().to_vec(),
                source.evidence_types().to_vec(),
                vec![method.clone()],
                source.grant_status_methods().to_vec(),
                source.assurance_claims().to_vec(),
                source.assurance_implications().to_vec(),
                source.resource_matchers().to_vec(),
                source.budget_algebras().to_vec(),
                source.critical_extensions().to_vec(),
                source.profiles().to_vec(),
                source.profile_policies().to_vec(),
            )
            .expect("status registry");
            let source = &context.trust_anchors()[0];
            let anchor = TrustAnchor::new(
                source.id().clone(),
                source.principal().clone(),
                source.accepted_methods().to_vec(),
                source.profiles().to_vec(),
                source.permissions().clone(),
                source.resource_namespaces().to_vec(),
                source.audiences().clone(),
                source.validity(),
                source.budget_ceiling().cloned(),
                source.max_delegation_depth(),
                source.assurance_policy().clone(),
                StatusPolicy::SnapshotRequired {
                    method,
                    max_age: FreshnessLimit::new(20).unwrap(),
                },
            )
            .expect("status anchor");
            context_replacement(
                context,
                vec![anchor],
                accepted,
                context.resource_matcher().clone(),
                context.profile_policy().clone(),
            )
        },
        Expected::Indeterminate(Requirement::MissingPrincipalStatus),
    )
}

fn unsupported_evidence_type() -> CorpusFixture {
    let fixture = raw_key_chain();
    let bundle = decoded_bundle(&fixture);
    let original = &bundle.evidence()[0];
    let unaddressed = EvidenceObject::new(
        EvidenceId::new([0; 32]),
        EvidenceTypeId::parse("unknown-evidence-v1").expect("evidence type"),
        original.media_type().clone(),
        original.bytes().to_vec(),
    )
    .expect("unknown evidence");
    let replacement = EvidenceObject::new(
        evidence_id(&unaddressed).expect("evidence ID"),
        unaddressed.evidence_type().clone(),
        unaddressed.media_type().clone(),
        unaddressed.bytes().to_vec(),
    )
    .expect("addressed evidence");
    let binding = ControlBinding::new(bundle.bindings()[0].statement(), vec![replacement.id()])
        .expect("replacement binding");
    let rebuilt = ProofBundle::new(
        bundle.header().clone(),
        bundle.grants().to_vec(),
        bundle.actions().to_vec(),
        bundle.plan().clone(),
        vec![replacement],
        vec![binding],
        bundle.principal_status().to_vec(),
        bundle.grant_status().to_vec(),
        bundle.attachments().to_vec(),
        bundle.canonical_body().map(<[u8]>::to_vec),
    )
    .expect("unknown evidence bundle");
    replace_bundle(
        fixture,
        "unsupported-evidence-type",
        &rebuilt,
        Expected::Indeterminate(Requirement::UnsupportedEvidenceType),
    )
}

fn unsupported_budget_algebra() -> CorpusFixture {
    let identity = Identity::ed25519(161);
    let algebra = BudgetAlgebraId::parse("unknown-budget-v1").expect("budget algebra");
    let canonical = CanonicalAction::new(
        profile(),
        MediaType::parse("application/vnd.auths.mcp-call.v1+cbor").expect("media type"),
        BODY.to_vec(),
        permission(),
        Some(BudgetCeiling::new(algebra.clone(), 5)),
    )
    .expect("canonical action");
    let proof_ref = ProofRef::new([0xa9; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let action = signed_action(
        &identity,
        action_envelope(
            &identity,
            &canonical,
            plan_id(&plan).unwrap(),
            proof_ref,
            None,
        ),
    );
    let evidence = identity.evidence();
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        Vec::new(),
        vec![action.clone()],
        plan,
        vec![evidence.clone()],
        vec![
            ControlBinding::new(
                StatementRef::Action(action_id(action.envelope()).unwrap()),
                vec![evidence.id()],
            )
            .unwrap(),
        ],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(BODY.to_vec()),
    )
    .unwrap();
    let accepted = AcceptedRegistries::new(
        RegistryManifestId::new([0x33; 32]),
        vec![PrincipalMethodId::parse(RAW_KEY_V1).unwrap()],
        vec![SignatureSuiteId::parse(ED25519_V1).unwrap()],
        vec![EvidenceTypeId::parse(RAW_KEY_V1).unwrap()],
        Vec::new(),
        Vec::new(),
        ASSURANCE_CLAIMS
            .iter()
            .map(|claim| AssuranceClaimId::parse(claim).unwrap())
            .collect(),
        Vec::new(),
        vec![ResourceMatcherId::parse("uri-namespace-v1").unwrap()],
        vec![algebra.clone()],
        Vec::new(),
        vec![profile()],
        vec![ProfilePolicyId::parse("exact-v1").unwrap()],
    )
    .unwrap();
    let anchor = TrustAnchor::new(
        TrustAnchorId::parse("unknown-budget-root").unwrap(),
        identity.principal.clone(),
        vec![PrincipalMethodId::parse(RAW_KEY_V1).unwrap()],
        vec![profile()],
        PermissionSet::new(vec![permission()]).unwrap(),
        vec![ResourceId::parse("mcp://reports").unwrap()],
        AudienceSet::new(vec![audience()]).unwrap(),
        ValidityWindow::new(Timestamp::new(0), Timestamp::new(100)).unwrap(),
        Some(BudgetCeiling::new(algebra, 20)),
        1,
        AssurancePolicyId::parse("raw-key-baseline").unwrap(),
        StatusPolicy::ExpiryOnly,
    )
    .unwrap();
    let base = context(core::slice::from_ref(&identity), vec![anchor.clone()]);
    let verifier_context = context_replacement(
        &base,
        vec![anchor],
        accepted,
        ResourceMatcherId::parse("uri-namespace-v1").unwrap(),
        ProfilePolicyId::parse("exact-v1").unwrap(),
    );
    fixture(
        "unsupported-budget-algebra",
        "indeterminate",
        &bundle,
        &verifier_context,
        canonical,
        Expected::Indeterminate(Requirement::UnsupportedBudgetAlgebra),
    )
}

#[derive(Clone, Copy)]
enum ControlMismatch {
    Principal,
    VerificationMethod,
}

fn control_mismatch(name: &'static str, mismatch: ControlMismatch) -> CorpusFixture {
    let identity = Identity::ed25519(171);
    let canonical = canonical_action(BODY.to_vec());
    let proof_ref = ProofRef::new([0xaa; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let actor = if matches!(mismatch, ControlMismatch::Principal) {
        PrincipalId::parse("raw:different-principal").unwrap()
    } else {
        identity.principal.clone()
    };
    let envelope = ActionEnvelope::new(
        canonical.profile().clone(),
        canonical.media_type().clone(),
        body_digest(canonical.body()),
        canonical.permission().clone(),
        canonical.requested_budget().cloned(),
        audience(),
        Challenge::new([0x22; 32]),
        ValidityWindow::new(Timestamp::new(40), Timestamp::new(60)).unwrap(),
        actor.clone(),
        None,
        plan_id(&plan).unwrap(),
        ChannelBindingId::parse("none-v1").unwrap(),
        proof_ref,
        Vec::new(),
        CriticalExtensions::empty(),
    );
    let descriptor = SignatureDescriptor::new(
        PrincipalMethodId::parse(RAW_KEY_V1).unwrap(),
        if matches!(mismatch, ControlMismatch::VerificationMethod) {
            VerificationMethod::parse("raw:different-verification-method").unwrap()
        } else {
            identity.descriptor().verification_method().clone()
        },
        SignatureSuiteId::parse(ED25519_V1).unwrap(),
    );
    let request = prepare_action(envelope, descriptor).unwrap();
    let signature = identity.sign(request.signing_preimage());
    let action = request.complete(signature);
    let evidence = identity.evidence();
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        Vec::new(),
        vec![action.clone()],
        plan,
        vec![evidence.clone()],
        vec![
            ControlBinding::new(
                StatementRef::Action(action_id(action.envelope()).unwrap()),
                vec![evidence.id()],
            )
            .unwrap(),
        ],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(BODY.to_vec()),
    )
    .unwrap();
    let anchor = TrustAnchor::new(
        TrustAnchorId::parse("control-mismatch-root").unwrap(),
        actor,
        vec![PrincipalMethodId::parse(RAW_KEY_V1).unwrap()],
        vec![profile()],
        PermissionSet::new(vec![permission()]).unwrap(),
        vec![ResourceId::parse("mcp://reports").unwrap()],
        AudienceSet::new(vec![audience()]).unwrap(),
        ValidityWindow::new(Timestamp::new(0), Timestamp::new(100)).unwrap(),
        Some(BudgetCeiling::new(
            BudgetAlgebraId::parse("numeric-ceiling-v1").unwrap(),
            20,
        )),
        1,
        AssurancePolicyId::parse("raw-key-baseline").unwrap(),
        StatusPolicy::ExpiryOnly,
    )
    .unwrap();
    fixture(
        name,
        "denied",
        &bundle,
        &context(core::slice::from_ref(&identity), vec![anchor]),
        canonical,
        Expected::Denied(match mismatch {
            ControlMismatch::Principal => DenialReason::PrincipalMethodMismatch,
            ControlMismatch::VerificationMethod => DenialReason::VerificationMethodMismatch,
        }),
    )
}

fn plan_action_mismatch() -> CorpusFixture {
    let identity = Identity::ed25519(181);
    let canonical = canonical_action(BODY.to_vec());
    let proof_ref = ProofRef::new([0xab; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let other_plan = AuthorizationPlan::proof(ProofRef::new([0xac; 32]));
    let action = signed_action(
        &identity,
        action_envelope(
            &identity,
            &canonical,
            plan_id(&other_plan).unwrap(),
            proof_ref,
            None,
        ),
    );
    let evidence = identity.evidence();
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        Vec::new(),
        vec![action.clone()],
        plan,
        vec![evidence.clone()],
        vec![
            ControlBinding::new(
                StatementRef::Action(action_id(action.envelope()).unwrap()),
                vec![evidence.id()],
            )
            .unwrap(),
        ],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(BODY.to_vec()),
    )
    .unwrap();
    fixture(
        "plan-action-mismatch",
        "denied",
        &bundle,
        &context(core::slice::from_ref(&identity), vec![anchor(&identity, 1)]),
        canonical,
        Expected::Denied(DenialReason::PlanActionMismatch),
    )
}

fn carried_status_digest_mismatch() -> CorpusFixture {
    let fixture = revoked_grant_status();
    let bundle = decoded_bundle(&fixture);
    let original = &bundle.grant_status()[0];
    let mut signature = original.signature().signature().as_slice().to_vec();
    signature[0] ^= 1;
    let carried = SignedGrantStatus::new(
        original.statement().clone(),
        SignatureEnvelope::new(
            original.signature().descriptor().clone(),
            SignatureBytes::new(signature).unwrap(),
        ),
    );
    let rebuilt = ProofBundle::new(
        bundle.header().clone(),
        bundle.grants().to_vec(),
        bundle.actions().to_vec(),
        bundle.plan().clone(),
        bundle.evidence().to_vec(),
        bundle.bindings().to_vec(),
        bundle.principal_status().to_vec(),
        vec![carried],
        bundle.attachments().to_vec(),
        bundle.canonical_body().map(<[u8]>::to_vec),
    )
    .unwrap();
    replace_bundle(
        fixture,
        "carried-status-digest-mismatch",
        &rebuilt,
        Expected::Denied(DenialReason::DigestMismatch),
    )
}

#[derive(Clone, Copy)]
enum AttachmentVariation {
    Valid,
    Missing,
    WrongDigest,
    WrongLength,
    Duplicate,
    Unused,
    OpaqueAllowed,
    OpaqueDenied,
}

fn attachment_fixture(
    name: &'static str,
    variation: AttachmentVariation,
    expected: Expected,
) -> CorpusFixture {
    let identity = Identity::ed25519(141);
    let bytes = b"offline signed attachment".to_vec();
    let correct_digest = attachment_digest(&bytes);
    let declared_digest = if matches!(variation, AttachmentVariation::WrongDigest) {
        AttachmentDigest::new([0xa7; 32])
    } else {
        correct_digest
    };
    let descriptor = AttachmentDescriptor::new(
        declared_digest,
        MediaType::parse("application/octet-stream").expect("attachment media type"),
        if matches!(variation, AttachmentVariation::WrongLength) {
            u64::try_from(bytes.len()).expect("small attachment") + 1
        } else {
            u64::try_from(bytes.len()).expect("small attachment")
        },
        DispositionId::parse("authorization-input").expect("disposition"),
        matches!(
            variation,
            AttachmentVariation::OpaqueAllowed | AttachmentVariation::OpaqueDenied
        ),
        true,
        matches!(variation, AttachmentVariation::OpaqueAllowed),
    );
    let descriptors = match variation {
        AttachmentVariation::Unused => Vec::new(),
        AttachmentVariation::Duplicate => vec![descriptor.clone(), descriptor],
        _ => vec![descriptor],
    };
    let detached = if matches!(variation, AttachmentVariation::Missing) {
        Vec::new()
    } else {
        vec![DetachedAttachment::new(declared_digest, bytes).expect("bounded detached attachment")]
    };
    let canonical = canonical_action(BODY.to_vec())
        .with_detached_attachments(detached)
        .expect("canonical attachment input");
    let proof_ref = ProofRef::new([0xa8; 32]);
    let plan = AuthorizationPlan::proof(proof_ref);
    let envelope = ActionEnvelope::new(
        canonical.profile().clone(),
        canonical.media_type().clone(),
        body_digest(canonical.body()),
        canonical.permission().clone(),
        canonical.requested_budget().cloned(),
        audience(),
        Challenge::new([0x22; 32]),
        ValidityWindow::new(Timestamp::new(40), Timestamp::new(60)).expect("validity"),
        identity.principal.clone(),
        None,
        plan_id(&plan).expect("plan ID"),
        ChannelBindingId::parse("none-v1").expect("channel"),
        proof_ref,
        descriptors.clone(),
        CriticalExtensions::empty(),
    );
    let action = signed_action(&identity, envelope);
    let evidence = identity.evidence();
    let binding = ControlBinding::new(
        StatementRef::Action(action_id(action.envelope()).expect("action ID")),
        vec![evidence.id()],
    )
    .expect("binding");
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        Vec::new(),
        vec![action],
        plan,
        vec![evidence],
        vec![binding],
        Vec::new(),
        Vec::new(),
        descriptors,
        Some(BODY.to_vec()),
    )
    .expect("attachment bundle");
    fixture(
        name,
        if matches!(
            variation,
            AttachmentVariation::Valid | AttachmentVariation::OpaqueAllowed
        ) {
            "valid"
        } else {
            "denied"
        },
        &bundle,
        &context(core::slice::from_ref(&identity), vec![anchor(&identity, 1)]),
        canonical,
        expected,
    )
}

/// Returns the initial target V1 normative corpus.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn corpus() -> Vec<CorpusFixture> {
    vec![
        raw_key_chain(),
        did_key_root_raw_key_actor(),
        raw_key_root_did_key_actor(),
        did_keri_root_raw_key_actor(),
        raw_key_root_did_keri_actor(),
        spiffe_root_raw_key_actor(),
        raw_key_root_spiffe_actor(),
        did_web_root_raw_key_actor(),
        raw_key_root_did_web_actor(),
        webauthn_root_raw_key_actor(),
        raw_key_root_webauthn_actor(),
        hsm_root_raw_key_actor(),
        raw_key_root_hsm_actor(),
        untrusted_did_web_document(),
        did_web_history_without_statement_existence(),
        did_web_historical_state_unavailable(),
        unsupported_protocol(),
        all_of(),
        any_of_valid_invalid_signature(),
        any_of_denied_indeterminate(),
        threshold(),
        threshold_mixed_success(),
        threshold_mixed_indeterminate(),
        threshold_mixed_denied(),
        permission_widening(),
        validity_widening(),
        audience_widening(),
        budget_widening(),
        depth_widening(),
        assurance_policy_change(),
        status_fixture("active-grant-status", StatusVariation::ActiveGrant),
        missing_grant_status(),
        stale_grant_status(),
        revoked_grant_status(),
        grant_status_sequence_rollback(),
        status_fixture(
            "wrong-grant-status-method",
            StatusVariation::WrongGrantMethod,
        ),
        status_fixture(
            "untrusted-grant-status-issuer",
            StatusVariation::UntrustedGrantIssuer,
        ),
        status_fixture(
            "grant-status-freshness-boundary",
            StatusVariation::GrantFreshnessBoundary,
        ),
        status_fixture(
            "grant-status-freshness-beyond",
            StatusVariation::GrantFreshnessBeyond,
        ),
        status_fixture(
            "conflicting-grant-status",
            StatusVariation::ConflictingGrant,
        ),
        unsupported_grant_status_method(),
        principal_status_selection_fixture("active-principal-status", false, Expected::Authorized),
        principal_status_selection_fixture(
            "untrusted-principal-status-issuer",
            true,
            Expected::Denied(DenialReason::StatusIssuerUntrusted),
        ),
        revoked_principal_status(),
        missing_principal_status(),
        action_permission_not_granted(),
        action_constraint_mismatch(),
        action_budget_exceeded(),
        action_validity_expanded(),
        action_actor_mismatch(),
        unsupported_action_profile(),
        unknown_action_extension(),
        action_channel_mismatch(),
        invalid_signature(),
        missing_grant_reference(),
        missing_plan_leaf(),
        signature_suite_substitution(),
        unknown_signature_suite(),
        unknown_principal_method(),
        unsupported_evidence_type(),
        control_mismatch("principal-method-mismatch", ControlMismatch::Principal),
        control_mismatch(
            "verification-method-mismatch",
            ControlMismatch::VerificationMethod,
        ),
        plan_action_mismatch(),
        carried_status_digest_mismatch(),
        p256_high_s_signature(),
        bundle_byte_limit_exceeded(),
        verification_work_limit_exceeded(),
        plan_depth_limit_exceeded(),
        missing_principal_evidence(),
        unused_critical_evidence(),
        duplicate_action_object(),
        duplicate_control_binding(),
        unused_grant_object(),
        evidence_count_over_default(),
        duplicate_cbor_key(),
        non_minimal_integer(),
        trailing_bytes(),
        mismatched_profile_version(),
        byte_distinct_action(),
        wrong_audience(),
        wrong_challenge(),
        composition_requirement_not_met(),
        verifier_configuration_mismatch(),
        registry_manifest_mismatch(),
        unsupported_resource_matcher(),
        unsupported_profile_policy(),
        exact_marker_extension("exact-marker-extension", vec![1], Expected::Authorized),
        exact_marker_extension(
            "exact-marker-extension-invalid",
            vec![2],
            Expected::Denied(DenialReason::LocalPolicyDenied),
        ),
        accepted_extension_without_handler(),
        resource_namespace_mismatch(),
        untrusted_root(),
        unsupported_assurance_claim(),
        unsupported_budget_algebra(),
        attachment_fixture(
            "attachment-valid",
            AttachmentVariation::Valid,
            Expected::Authorized,
        ),
        attachment_fixture(
            "attachment-missing",
            AttachmentVariation::Missing,
            Expected::Denied(DenialReason::AttachmentMissing),
        ),
        attachment_fixture(
            "attachment-wrong-digest",
            AttachmentVariation::WrongDigest,
            Expected::Denied(DenialReason::AttachmentDigestMismatch),
        ),
        attachment_fixture(
            "attachment-wrong-length",
            AttachmentVariation::WrongLength,
            Expected::Denied(DenialReason::AttachmentLengthMismatch),
        ),
        attachment_fixture(
            "attachment-duplicate",
            AttachmentVariation::Duplicate,
            Expected::Denied(DenialReason::DuplicateAttachment),
        ),
        attachment_fixture(
            "attachment-unused",
            AttachmentVariation::Unused,
            Expected::Denied(DenialReason::UnusedCriticalAttachment),
        ),
        attachment_fixture(
            "attachment-opaque-allowed",
            AttachmentVariation::OpaqueAllowed,
            Expected::Authorized,
        ),
        attachment_fixture(
            "attachment-opaque-denied",
            AttachmentVariation::OpaqueDenied,
            Expected::Denied(DenialReason::OpaqueAttachmentNotAllowed),
        ),
    ]
}

/// Returns exact mandatory suite IDs exercised by the corpus.
#[must_use]
pub fn mandatory_suite_ids() -> [&'static str; 2] {
    [ED25519_V1, P256_SHA256_V1]
}

/// Raw SHA-256 body digest used by the hand-reviewed chain.
#[must_use]
pub fn reviewed_body_digest() -> Digest {
    body_digest(BODY)
}
pub mod adversarial;
pub mod conformance;
