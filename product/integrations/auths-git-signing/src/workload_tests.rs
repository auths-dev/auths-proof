//! CI workload signers against the kernel, through the same trust and
//! verification path as `did:key` agents: trust pinned to a `did:key` root,
//! workload methods enabled by `methods.json`, one `verify_object` call.

use crate::action::RepositoryId;
use crate::custody::SoftwareKey;
use crate::envelope::GitSignatureEnvelope;
use crate::object::UnsignedPayload;
use crate::sign::{Delegation, GitProofSigner, sign_payload};
use crate::tool::EnabledMethods;
use crate::trust::{GitCapability, issue_grant, repository_trust, window_from};
use crate::verify::{GitTrust, GitVerification, verify_object};
use crate::workload::{OidcWorkloadSigner, SigstoreKeylessSigner};
use crate::workload_fakes::{
    BASE, FakeIssuer, FakeSigstore, GITHUB_ISSUER, MintingSource, NOW, REPOSITORY_ID, SUBJECT,
    methods_file,
};
use auths_codec::{decode_bundle, encode_verifier_context};
use auths_did_key::DID_KEY_V1;
use auths_model::{PrincipalId, PrincipalMethodId, Timestamp, VerifierLimits};

const REPOSITORY: &str = "github.com/acme/app";

fn commit(message: &str) -> Vec<u8> {
    format!(
        "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor CI <ci@example.invalid> {NOW} +0000\ncommitter CI <ci@example.invalid> {NOW} +0000\n\n{message}\n"
    )
    .into_bytes()
}

/// A repository pinned to one `did:key` root, with the verifier's method
/// set built from a `methods.json`.
struct Signing {
    _directory: tempfile::TempDir,
    root: SoftwareKey,
    agent: SoftwareKey,
    repository: RepositoryId,
}

impl Signing {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = SoftwareKey::from_test_seed(0x51);
        let agent = SoftwareKey::from_test_seed(0x52);
        Self {
            _directory: directory,
            root,
            agent,
            repository: RepositoryId::parse(REPOSITORY).expect("repository"),
        }
    }

    fn trust(&self, methods: &EnabledMethods) -> GitTrust {
        let context = methods
            .with_sets(|methods, suites, claims| {
                repository_trust(
                    &self.root.principal(),
                    &PrincipalMethodId::parse(DID_KEY_V1).expect("method"),
                    &self.repository,
                    methods,
                    suites,
                    claims,
                    window_from(BASE, 365 * 86_400).expect("window"),
                )
            })
            .expect("method sets")
            .expect("trust");
        GitTrust::decode(&encode_verifier_context(&context).expect("encode")).expect("decode")
    }

    fn grant(&self, subject: PrincipalId) -> Delegation {
        issue_grant(
            &self.root,
            subject,
            &self.repository,
            &[GitCapability::SignCommit],
            window_from(BASE, 86_400).expect("window"),
        )
        .expect("grant")
    }

    /// Signs `payload` and returns the raw signed commit.
    fn sign(
        &self,
        payload: &[u8],
        signer: &dyn GitProofSigner,
        delegation: &Delegation,
    ) -> Vec<u8> {
        let parsed = UnsignedPayload::parse(payload.to_vec()).expect("payload");
        let armored = sign_payload(&parsed, &self.repository, signer, delegation, NOW - 30)
            .expect("signature")
            .to_armored();
        let header_end = payload
            .windows(2)
            .position(|window| window == b"\n\n")
            .expect("headers");
        let mut raw = payload[..header_end].to_vec();
        raw.extend_from_slice(b"\ngpgsig ");
        raw.extend_from_slice(armored.trim_end().replace('\n', "\n ").as_bytes());
        raw.extend_from_slice(&payload[header_end..]);
        raw
    }
}

fn enabled(methods: &[u8]) -> EnabledMethods {
    EnabledMethods::from_configuration(Some(methods)).expect("methods")
}

fn verify(methods: &EnabledMethods, trust: &GitTrust, raw: &[u8], at: u64) -> GitVerification {
    methods
        .with_registries(|registries| verify_object(raw, trust, registries, Timestamp::new(at)))
        .expect("registries")
}

fn signing_method(raw: &[u8]) -> String {
    let object = crate::object::SignedObject::parse(raw).expect("object");
    let envelope = GitSignatureEnvelope::from_armored(object.signature()).expect("envelope");
    let bundle = decode_bundle(envelope.proof(), &VerifierLimits::default()).expect("bundle");
    bundle.actions()[0]
        .signature()
        .descriptor()
        .principal_method()
        .as_str()
        .to_owned()
}

/// Returns the stable code of a result that must not be verified.
fn refusal(result: GitVerification) -> &'static str {
    match result {
        GitVerification::Verified(verified) => panic!("verified: {verified:?}"),
        GitVerification::Denied(code) | GitVerification::Indeterminate(code) => code,
    }
}

fn oidc_signer(issuer: &FakeIssuer, repository_id: &str, issued_at: u64) -> OidcWorkloadSigner {
    OidcWorkloadSigner::acquire(&MintingSource {
        issuer,
        repository_id,
        issued_at,
    })
    .expect("workload signer")
}

#[test]
fn oidc_workload_commits_verify_under_a_did_key_root_while_the_token_is_live() {
    let repository = Signing::new();
    let issuer = FakeIssuer::new(0x31);
    let methods = enabled(&methods_file(Some(issuer.methods()), None));
    let trust = repository.trust(&methods);
    let signer = oidc_signer(&issuer, REPOSITORY_ID, NOW - 60);
    assert!(
        signer
            .principal()
            .as_str()
            .starts_with("oidc-workload:https%3A%2F%2F")
    );
    let delegation = repository.grant(signer.principal());
    let raw = repository.sign(&commit("oidc"), &signer, &delegation);

    let GitVerification::Verified(verified) = verify(&methods, &trust, &raw, NOW) else {
        panic!("not verified: {:?}", verify(&methods, &trust, &raw, NOW));
    };
    assert_eq!(verified.signer(), &signer.principal());
    assert_eq!(verified.chain(), &[repository.root.principal()]);
    assert_eq!(signing_method(&raw), "oidc-workload-v1");

    // The token's window is [iat - 300, exp + 300); a gate after it fails.
    assert_eq!(
        refusal(verify(&methods, &trust, &raw, NOW - 60 + 300 + 300)),
        "principal-method-mismatch"
    );
}

#[test]
fn expired_tokens_and_tokens_for_other_repositories_are_not_verified() {
    let repository = Signing::new();
    let issuer = FakeIssuer::new(0x32);
    let methods = enabled(&methods_file(Some(issuer.methods()), None));
    let trust = repository.trust(&methods);
    for (repository_id, issued_at) in [(REPOSITORY_ID, NOW - 1_200), ("7999", NOW - 60)] {
        let signer = oidc_signer(&issuer, repository_id, issued_at);
        let delegation = repository.grant(signer.principal());
        let raw = repository.sign(&commit(repository_id), &signer, &delegation);
        assert_eq!(
            refusal(verify(&methods, &trust, &raw, NOW)),
            "principal-method-mismatch"
        );
    }
}

#[test]
fn the_configuration_commitment_binds_the_pinned_issuer_keys() {
    let repository = Signing::new();
    let issuer = FakeIssuer::new(0x33);
    let rotated = FakeIssuer::new(0x34);
    let pinned = enabled(&methods_file(Some(issuer.methods()), None));
    let other = enabled(&methods_file(Some(rotated.methods()), None));
    let trust = repository.trust(&pinned);
    assert_ne!(
        trust.context().configuration(),
        repository.trust(&other).context().configuration(),
        "a different pinned key must change the commitment"
    );
    assert_ne!(
        trust.context().configuration(),
        repository
            .trust(&EnabledMethods::new().expect("did:key"))
            .context()
            .configuration()
    );

    let signer = oidc_signer(&issuer, REPOSITORY_ID, NOW - 60);
    let delegation = repository.grant(signer.principal());
    let raw = repository.sign(&commit("bound"), &signer, &delegation);
    assert!(matches!(
        verify(&pinned, &trust, &raw, NOW),
        GitVerification::Verified(_)
    ));
    // A verifier whose methods.json pins another key runs a configuration
    // the trust does not commit to.
    assert_eq!(
        refusal(verify(&other, &trust, &raw, NOW)),
        "verifier-configuration-mismatch"
    );
}

#[test]
fn sigstore_keyless_commits_verify_under_a_did_key_root() {
    let repository = Signing::new();
    let issuer = FakeIssuer::new(0x41);
    let sigstore = FakeSigstore::new(0x42);
    let methods = enabled(&methods_file(
        None,
        Some(sigstore.methods(GITHUB_ISSUER, SUBJECT)),
    ));
    let trust = repository.trust(&methods);
    let tokens = MintingSource {
        issuer: &issuer,
        repository_id: REPOSITORY_ID,
        issued_at: NOW - 60,
    };
    let signer = SigstoreKeylessSigner::acquire(&tokens, &sigstore).expect("signer");
    let delegation = repository.grant(signer.principal());
    let raw = repository.sign(&commit("sigstore"), &signer, &delegation);
    let GitVerification::Verified(verified) = verify(&methods, &trust, &raw, NOW) else {
        panic!("not verified: {:?}", verify(&methods, &trust, &raw, NOW));
    };
    assert_eq!(verified.signer(), &signer.principal());
    assert_eq!(signing_method(&raw), "sigstore-keyless-v1");
}

/// Public-good Rekor signs with DER ECDSA P-256 and may emit high-S
/// signatures; the fake log always does. The action signature stays the
/// fixed-width low-S form, and Rekor records its DER encoding.
#[test]
fn sigstore_keyless_commits_verify_through_a_p256_log_signing_high_s_der() {
    let repository = Signing::new();
    let issuer = FakeIssuer::new(0x47);
    let sigstore = FakeSigstore::with_p256_log(0x48, 0x49);
    let methods = enabled(&methods_file(
        None,
        Some(sigstore.methods(GITHUB_ISSUER, SUBJECT)),
    ));
    let trust = repository.trust(&methods);
    let tokens = MintingSource {
        issuer: &issuer,
        repository_id: REPOSITORY_ID,
        issued_at: NOW - 60,
    };
    let signer = SigstoreKeylessSigner::acquire(&tokens, &sigstore).expect("signer");
    assert_eq!(signer.descriptor().suite().as_str(), "p256-sha256-v1");
    let signature = signer.sign_preimage(b"preimage").expect("signature");
    assert_eq!(signature.as_slice().len(), 64);
    assert!(
        signature.as_slice()[32] < 0x80,
        "the action signature is low-S"
    );

    let delegation = repository.grant(signer.principal());
    let raw = repository.sign(&commit("p256 log"), &signer, &delegation);
    let GitVerification::Verified(verified) = verify(&methods, &trust, &raw, NOW) else {
        panic!("not verified: {:?}", verify(&methods, &trust, &raw, NOW));
    };
    assert_eq!(verified.signer(), &signer.principal());

    sigstore.corrupt_entry.set(true);
    let signer = SigstoreKeylessSigner::acquire(&tokens, &sigstore).expect("signer");
    let tampered = repository.sign(&commit("tampered"), &signer, &delegation);
    assert_eq!(
        refusal(verify(&methods, &trust, &tampered, NOW)),
        "principal-method-mismatch"
    );
}

#[test]
fn tampered_entries_and_foreign_fulcio_roots_are_not_verified() {
    let repository = Signing::new();
    let issuer = FakeIssuer::new(0x43);
    let sigstore = FakeSigstore::new(0x44);
    // The same Rekor log, but certificates from a Fulcio root trust does
    // not pin.
    let foreign = FakeSigstore::with_keys(0x46, 0x45);
    let tokens = MintingSource {
        issuer: &issuer,
        repository_id: REPOSITORY_ID,
        issued_at: NOW - 60,
    };
    let pinned = enabled(&methods_file(
        None,
        Some(sigstore.methods(GITHUB_ISSUER, SUBJECT)),
    ));
    let trust = repository.trust(&pinned);

    sigstore.corrupt_entry.set(true);
    let signer = SigstoreKeylessSigner::acquire(&tokens, &sigstore).expect("signer");
    let delegation = repository.grant(signer.principal());
    let tampered = repository.sign(&commit("tampered"), &signer, &delegation);
    assert_eq!(
        refusal(verify(&pinned, &trust, &tampered, NOW)),
        "principal-method-mismatch"
    );

    let signer = SigstoreKeylessSigner::acquire(&tokens, &foreign).expect("signer");
    let raw = repository.sign(&commit("foreign"), &signer, &delegation);
    assert_eq!(
        refusal(verify(&pinned, &trust, &raw, NOW)),
        "principal-method-mismatch"
    );
}

/// One trust pinned to one `did:key` root, one registry set enabling
/// `did:key`, `oidc-workload`, and `sigstore-keyless`, and one verification
/// path for all three signers. The two workload signers share one grant,
/// because both methods name the same workload principal.
#[test]
fn one_verifier_accepts_three_principal_methods_under_one_root() {
    let repository = Signing::new();
    let issuer = FakeIssuer::new(0x51);
    let sigstore = FakeSigstore::new(0x52);
    let methods = enabled(&methods_file(
        Some(issuer.methods()),
        Some(sigstore.methods(GITHUB_ISSUER, SUBJECT)),
    ));
    let trust = repository.trust(&methods);
    let tokens = MintingSource {
        issuer: &issuer,
        repository_id: REPOSITORY_ID,
        issued_at: NOW - 60,
    };
    let oidc = OidcWorkloadSigner::acquire(&tokens).expect("oidc signer");
    let keyless = SigstoreKeylessSigner::acquire(&tokens, &sigstore).expect("sigstore signer");
    assert_eq!(oidc.principal(), keyless.principal());
    let workload_grant = repository.grant(oidc.principal());
    let agent_grant = repository.grant(repository.agent.principal());

    let objects = [
        (
            repository.sign(&commit("agent"), &repository.agent, &agent_grant),
            repository.agent.principal(),
            "did-key-v1",
        ),
        (
            repository.sign(&commit("oidc"), &oidc, &workload_grant),
            oidc.principal(),
            "oidc-workload-v1",
        ),
        (
            repository.sign(&commit("keyless"), &keyless, &workload_grant),
            keyless.principal(),
            "sigstore-keyless-v1",
        ),
    ];
    let results = methods
        .with_registries(|registries| {
            objects
                .iter()
                .map(|(raw, _, _)| verify_object(raw, &trust, registries, Timestamp::new(NOW)))
                .collect::<Vec<_>>()
        })
        .expect("registries");
    for ((raw, signer, method), result) in objects.iter().zip(results) {
        assert_eq!(signing_method(raw), *method);
        let GitVerification::Verified(verified) = result else {
            panic!("{method} did not verify: {result:?}");
        };
        assert_eq!(verified.signer(), signer);
        assert_eq!(verified.chain(), &[repository.root.principal()]);
    }
}
