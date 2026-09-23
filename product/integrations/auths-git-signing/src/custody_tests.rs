//! Git-signing roots held behind `auths-custody`: grants and revocation
//! records signed through the transaction-bound custody boundary verify in
//! the kernel, and the shared custody conformance kit holds on this path.

use crate::action::RepositoryId;
use crate::custody::{CustodyError, CustodyKeySigner, SoftwareKey};
use crate::object::UnsignedPayload;
use crate::revoke::sign_revocation;
use crate::sign::{GitProofSigner, SignError, sign_payload};
use crate::trust::{GitCapability, TrustBuildError, issue_grant, repository_trust, window_from};
use crate::verify::{GitTrust, GitVerification, verify_signature};
use auths_codec::{encode_verifier_context, grant_id};
use auths_custody::conformance::{ConformanceExpectation, ConformanceSigner, LIFECYCLE_CASES};
use auths_custody::{
    CustodyConformanceCase, CustodyKey, CustodyKind, CustodyPrincipalForm, KeyLifecycleState,
};
use auths_custody_pkcs11::{
    Pkcs11Api, Pkcs11Configuration, Pkcs11Failure, Pkcs11KeyDescription, Pkcs11ObjectId,
    Pkcs11P256Adapter, Pkcs11SecretProvider, Pkcs11Selector, Pkcs11SignOutput, Pkcs11TokenId,
    SecretPin,
};
use auths_did_key::{DID_KEY_V1, DidKeyMethod};
use auths_model::{PrincipalMethodId, Timestamp};
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_registries::ImmutableRegistries;
use auths_signature::{Ed25519Suite, P256Sha256Suite};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};

const NOW: u64 = 1_790_000_000;
const COMMIT: &[u8] = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor Agent <a@example.invalid> 1790000000 +0000\ncommitter Agent <a@example.invalid> 1790000000 +0000\n\ncustody commit\n";

struct Repository {
    id: RepositoryId,
    did_key: DidKeyMethod,
    ed25519: Ed25519Suite,
    p256: P256Sha256Suite,
    agent: SoftwareKey,
}

impl Repository {
    fn new() -> Self {
        Self {
            id: RepositoryId::parse("github.com/acme/app").expect("repository"),
            did_key: DidKeyMethod::new().expect("did:key"),
            ed25519: Ed25519Suite::new().expect("ed25519"),
            p256: P256Sha256Suite::new().expect("p256"),
            agent: SoftwareKey::from_test_seed(0x52),
        }
    }

    fn with_registries<R>(&self, check: impl FnOnce(&ImmutableRegistries<'_>) -> R) -> R {
        let methods = [&self.did_key as &dyn PrincipalMethod];
        let suites = [
            &self.ed25519 as &dyn SignatureSuite,
            &self.p256 as &dyn SignatureSuite,
        ];
        check(&ImmutableRegistries::new(&methods, &suites).expect("registries"))
    }

    fn trust(&self, root: &dyn GitProofSigner, revocations: &[Vec<u8>]) -> GitTrust {
        let methods = [&self.did_key as &dyn PrincipalMethod];
        let suites = [
            &self.ed25519 as &dyn SignatureSuite,
            &self.p256 as &dyn SignatureSuite,
        ];
        let context = repository_trust(
            &root.principal(),
            &PrincipalMethodId::parse(DID_KEY_V1).expect("method"),
            &self.id,
            &methods,
            &suites,
            &[],
            window_from(NOW - 60, 365 * 86_400).expect("window"),
        )
        .expect("trust");
        let trust =
            GitTrust::decode(&encode_verifier_context(&context).expect("encode")).expect("decode");
        self.with_registries(|registries| trust.with_revocations(revocations, registries))
            .expect("revocations verify")
    }

    fn grant(&self, root: &dyn GitProofSigner) -> Result<crate::sign::Delegation, TrustBuildError> {
        issue_grant(
            root,
            self.agent.principal(),
            &self.id,
            &[GitCapability::SignCommit],
            window_from(NOW - 60, 86_400).expect("window"),
        )
    }

    fn verify(&self, root: &dyn GitProofSigner, revocations: &[Vec<u8>]) -> GitVerification {
        let delegation = self.grant(root).expect("grant");
        let payload = UnsignedPayload::parse(COMMIT.to_vec()).expect("payload");
        let signature = sign_payload(&payload, &self.id, &self.agent, &delegation, NOW - 30)
            .expect("agent signature")
            .to_armored();
        let trust = self.trust(root, revocations);
        self.with_registries(|registries| {
            verify_signature(
                &payload,
                signature.as_bytes(),
                &trust,
                registries,
                Timestamp::new(NOW),
            )
        })
    }
}

fn conformance_root(
    lifecycle: KeyLifecycleState,
    case: CustodyConformanceCase,
) -> (
    CustodyKeySigner,
    auths_custody::conformance::ConformanceProbe,
) {
    let (key, probe) = ConformanceSigner::key(
        CustodyPrincipalForm::DidKeyV1,
        CustodyKind::Kms,
        lifecycle,
        case,
    );
    (
        CustodyKeySigner::new(key).expect("did:key custody root"),
        probe,
    )
}

struct Token(SigningKey);

impl Pkcs11Api for Token {
    fn inspect(
        &self,
        _: &Pkcs11Selector<'_>,
        _: &SecretPin,
    ) -> Result<Pkcs11KeyDescription, Pkcs11Failure> {
        Ok(Pkcs11KeyDescription {
            public_key_sec1: self
                .0
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
            p256: true,
            sign: true,
            enabled: true,
        })
    }

    fn sign_sha256(
        &self,
        _: &Pkcs11Selector<'_>,
        _: &SecretPin,
        message: &[u8],
    ) -> Result<Pkcs11SignOutput, Pkcs11Failure> {
        let signature: Signature = self.0.sign(message);
        Ok(Pkcs11SignOutput {
            signature: signature.normalize_s().unwrap_or(signature).to_vec(),
        })
    }
}

struct Pin;

impl Pkcs11SecretProvider for Pin {
    fn acquire(&self) -> Result<SecretPin, Pkcs11Failure> {
        SecretPin::parse(b"test-only-pin".to_vec()).map_err(|_| Pkcs11Failure::WrongPin)
    }
}

/// A root on a PKCS#11 token through the reference adapter over a mock
/// token API. No module is loaded and no PIN is real.
fn pkcs11_root() -> CustodyKeySigner {
    let adapter = Pkcs11P256Adapter::connect(
        Token(SigningKey::from_slice(&[0x63; 32]).expect("key")),
        Pin,
        Pkcs11Configuration::new(
            std::path::PathBuf::from("/opt/softhsm/lib/softhsm2.so"),
            Pkcs11TokenId::parse("auths-git-root").expect("token"),
            Pkcs11ObjectId::parse(vec![9]).expect("object"),
            1,
            std::time::Duration::from_secs(2),
        )
        .expect("configuration"),
        CustodyPrincipalForm::DidKeyV1,
    )
    .expect("PKCS#11 adapter");
    let identity = adapter.identity().clone();
    CustodyKeySigner::new(CustodyKey::new(Box::new(adapter), identity).expect("custody key"))
        .expect("did:key custody root")
}

#[test]
fn custody_roots_issue_grants_and_revocations_that_verify() {
    let repository = Repository::new();
    let (kms, _) = conformance_root(
        KeyLifecycleState::ActiveCurrent,
        CustodyConformanceCase::Valid,
    );
    for (root, custody) in [(&kms, "kms"), (&pkcs11_root(), "pkcs11")] {
        assert_eq!(root.custody(), custody);
        assert!(root.principal().as_str().starts_with("did:key:zDn"));
        let GitVerification::Verified(verified) = repository.verify(root, &[]) else {
            panic!("{custody}: agent signature under a custody root did not verify");
        };
        assert_eq!(verified.chain(), &[root.principal()]);

        let delegation = repository.grant(root).expect("grant");
        let revoked = grant_id(delegation.terminal().expect("terminal").statement()).expect("id");
        let record = sign_revocation(&repository.id, revoked, root, NOW - 1)
            .expect("custody revocation")
            .to_armored()
            .into_bytes();
        assert_eq!(
            repository.verify(root, &[record]),
            GitVerification::Denied("git.grant-revoked"),
            "{custody}"
        );
    }
}

#[test]
fn custody_root_passes_custody_conformance() {
    let repository = Repository::new();
    for (case, expected) in auths_custody::conformance::cases() {
        let (root, probe) = conformance_root(KeyLifecycleState::ActiveCurrent, case);
        match expected {
            ConformanceExpectation::Startup => continue,
            ConformanceExpectation::Signed => {
                assert!(
                    matches!(repository.verify(&root, &[]), GitVerification::Verified(_)),
                    "{case:?}"
                );
            }
            ConformanceExpectation::Refused(error) => {
                assert_eq!(
                    repository.grant(&root).err(),
                    Some(TrustBuildError::Sign(SignError::Custody(error))),
                    "{case:?}"
                );
                assert!(
                    matches!(
                        sign_revocation(&repository.id, auths_model::GrantId::new([1; 32]), &root, NOW),
                        Err(SignError::Custody(refused)) if refused == error
                    ),
                    "{case:?}"
                );
            }
        }
        assert!(probe.calls() >= 1, "{case:?}");
    }
}

#[test]
fn custody_root_lifecycle_gates_the_provider() {
    let repository = Repository::new();
    for (lifecycle, permitted) in LIFECYCLE_CASES {
        let (root, probe) = conformance_root(*lifecycle, CustodyConformanceCase::Valid);
        let grant = repository.grant(&root);
        assert_eq!(grant.is_ok(), *permitted, "{lifecycle:?}");
        if !permitted {
            assert_eq!(
                grant.err(),
                Some(TrustBuildError::Sign(SignError::Custody(
                    auths_custody::CustodyError::LifecycleNotPermitted
                )))
            );
        }
        assert_eq!(probe.calls(), usize::from(*permitted), "{lifecycle:?}");
    }
}

#[test]
fn custody_root_must_be_presented_as_did_key() {
    let (key, _) = ConformanceSigner::key(
        CustodyPrincipalForm::RawKeyV1,
        CustodyKind::Kms,
        KeyLifecycleState::ActiveCurrent,
        CustodyConformanceCase::Valid,
    );
    assert!(matches!(
        CustodyKeySigner::new(key),
        Err(CustodyError::Identity)
    ));
}
