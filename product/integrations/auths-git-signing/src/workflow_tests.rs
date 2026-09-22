//! The operator workflow through the library: custody keys, repository trust,
//! grant files, signing, verification, and revocation.

use crate::action::RepositoryId;
use crate::custody::SoftwareKey;
use crate::files::{decode_delegation, encode_delegation};
use crate::object::UnsignedPayload;
use crate::revoke::sign_revocation;
use crate::sign::{GitProofSigner, sign_payload};
use crate::trust::{GitCapability, issue_grant, repository_trust, window_from};
use crate::verify::{GitTrust, GitVerification, TrustError, verify_signature};
use auths_codec::{encode_verifier_context, grant_id};
use auths_did_key::{DID_KEY_V1, DidKeyMethod};
use auths_model::{PrincipalMethodId, Timestamp};
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_registries::ImmutableRegistries;
use auths_signature::Ed25519Suite;

const NOW: u64 = 1_790_000_000;
const COMMIT: &[u8] = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor Agent <a@example.invalid> 1790000000 +0000\ncommitter Agent <a@example.invalid> 1790000000 +0000\n\nagent commit\n";

struct Operator {
    _directory: tempfile::TempDir,
    root: SoftwareKey,
    agent: SoftwareKey,
    repository: RepositoryId,
    did_key: DidKeyMethod,
    suite: Ed25519Suite,
}

impl Operator {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = SoftwareKey::from_test_seed(0x51);
        let agent = SoftwareKey::from_test_seed(0x52);
        Self {
            _directory: directory,
            root,
            agent,
            repository: RepositoryId::parse("github.com/acme/app").expect("repository"),
            did_key: DidKeyMethod::new().expect("did:key"),
            suite: Ed25519Suite::new().expect("suite"),
        }
    }

    fn with_registries<R>(&self, check: impl FnOnce(&ImmutableRegistries<'_>) -> R) -> R {
        let methods = [&self.did_key as &dyn PrincipalMethod];
        let suites = [&self.suite as &dyn SignatureSuite];
        check(&ImmutableRegistries::new(&methods, &suites).expect("registries"))
    }

    fn trust_bytes(&self) -> Vec<u8> {
        let methods = [&self.did_key as &dyn PrincipalMethod];
        let suites = [&self.suite as &dyn SignatureSuite];
        let context = repository_trust(
            &self.root.principal(),
            &PrincipalMethodId::parse(DID_KEY_V1).expect("method"),
            &self.repository,
            &methods,
            &suites,
            &[],
            window_from(NOW - 60, 365 * 86_400).expect("window"),
        )
        .expect("trust");
        encode_verifier_context(&context).expect("encode")
    }

    fn trust(&self, revocations: &[Vec<u8>]) -> Result<GitTrust, TrustError> {
        let trust = GitTrust::decode(&self.trust_bytes())?;
        self.with_registries(|registries| trust.with_revocations(revocations, registries))
    }

    fn verify(
        &self,
        trust: &GitTrust,
        payload: &UnsignedPayload,
        signature: &[u8],
    ) -> GitVerification {
        self.with_registries(|registries| {
            verify_signature(payload, signature, trust, registries, Timestamp::new(NOW))
        })
    }
}

#[test]
fn a_grant_file_moves_from_root_to_agent_and_signs_commits() {
    let operator = Operator::new();
    let delegation = issue_grant(
        &operator.root,
        operator.agent.principal(),
        &operator.repository,
        &[GitCapability::SignCommit],
        window_from(NOW - 60, 86_400).expect("window"),
    )
    .expect("grant");
    let file = encode_delegation(&delegation).expect("encode");
    let installed = decode_delegation(&file).expect("decode");
    assert_eq!(encode_delegation(&installed).expect("re-encode"), file);

    let payload = UnsignedPayload::parse(COMMIT.to_vec()).expect("payload");
    let signature = sign_payload(
        &payload,
        &operator.repository,
        &operator.agent,
        &installed,
        NOW - 30,
    )
    .expect("sign")
    .to_armored();
    let trust = operator.trust(&[]).expect("trust");
    let GitVerification::Verified(verified) =
        operator.verify(&trust, &payload, signature.as_bytes())
    else {
        panic!("agent signature did not verify");
    };
    assert_eq!(verified.signer(), &operator.agent.principal());
    assert_eq!(verified.chain(), &[operator.root.principal()]);
}

#[test]
fn revocation_by_the_root_denies_the_revoked_grant() {
    let operator = Operator::new();
    let delegation = issue_grant(
        &operator.root,
        operator.agent.principal(),
        &operator.repository,
        &[GitCapability::SignCommit],
        window_from(NOW - 60, 86_400).expect("window"),
    )
    .expect("grant");
    let payload = UnsignedPayload::parse(COMMIT.to_vec()).expect("payload");
    let signature = sign_payload(
        &payload,
        &operator.repository,
        &operator.agent,
        &delegation,
        NOW - 30,
    )
    .expect("sign")
    .to_armored();
    let revoked = grant_id(delegation.terminal().expect("terminal").statement()).expect("id");
    let record = sign_revocation(&operator.repository, revoked, &operator.root, NOW - 1)
        .expect("revocation")
        .to_armored()
        .into_bytes();

    let trust = operator.trust(&[record]).expect("revocation verifies");
    assert_eq!(
        operator.verify(&trust, &payload, signature.as_bytes()),
        GitVerification::Denied("git.grant-revoked")
    );
}

#[test]
fn invalid_revocations_fail_the_trust_instead_of_being_ignored() {
    let operator = Operator::new();
    let delegation = issue_grant(
        &operator.root,
        operator.agent.principal(),
        &operator.repository,
        &[GitCapability::SignCommit],
        window_from(NOW - 60, 86_400).expect("window"),
    )
    .expect("grant");
    let revoked = grant_id(delegation.terminal().expect("terminal").statement()).expect("id");

    let by_agent = sign_revocation(&operator.repository, revoked, &operator.agent, NOW - 1)
        .expect("revocation")
        .to_armored()
        .into_bytes();
    let other_repository = sign_revocation(
        &RepositoryId::parse("github.com/acme/other").expect("repository"),
        revoked,
        &operator.root,
        NOW - 1,
    )
    .expect("revocation")
    .to_armored()
    .into_bytes();
    let mut damaged = sign_revocation(&operator.repository, revoked, &operator.root, NOW - 1)
        .expect("revocation")
        .to_armored()
        .into_bytes();
    let middle = damaged.len() / 2;
    damaged[middle] = if damaged[middle] == b'A' { b'B' } else { b'A' };

    for record in [by_agent, other_repository, damaged] {
        assert_eq!(
            operator.trust(&[record]).err(),
            Some(TrustError::RevocationInvalid)
        );
    }
}
