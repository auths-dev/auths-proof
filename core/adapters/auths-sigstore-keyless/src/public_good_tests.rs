//! The adapter's transparency and identity checks against real public-good
//! Sigstore data.
//!
//! Fixtures under `testdata/public-good/`, fetched 2026-09-22:
//!
//! - `rekor-entry-2910000001.json`: the unmodified response of
//!   `GET https://rekor.sigstore.dev/api/v1/log/entries?logIndex=2910000001`,
//!   a `hashedrekord` entry signed keyless by a GitHub Actions workflow;
//! - `rekor-public-key.pem`: `GET https://rekor.sigstore.dev/api/v1/log/publicKey`;
//! - `fulcio-trust-bundle.json`: `GET https://fulcio.sigstore.dev/api/v2/trustBundle`.
//!
//! All three are public. The log signs with DER ECDSA P-256; this entry's
//! own artifact signature has a high `s`, so both conversion directions are
//! exercised on real bytes.

use super::*;
use alloc::string::ToString as _;
use auths_path_webpki::WebPkiPathVerifier;
use auths_signature::P256Sha256Suite;
use base64ct::Base64;
use entry::EntryFields;
use identity::{FulcioGithubPolicy, FulcioWorkloadIdentity, RepositoryId, RepositoryOwnerId};

const ENTRY: &str = include_str!("../testdata/public-good/rekor-entry-2910000001.json");
const REKOR_KEY: &str = include_str!("../testdata/public-good/rekor-public-key.pem");
const TRUST_BUNDLE: &str = include_str!("../testdata/public-good/fulcio-trust-bundle.json");
const ORIGIN: &str = "rekor.sigstore.dev - 1193050959916656506";
const KEY_NAME: &str = "rekor.sigstore.dev";
const P256_ALGORITHM: [u8; 21] = [
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x03, 0x01, 0x07,
];

fn pem_body(pem: &str) -> Vec<u8> {
    let joined: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    Base64::decode_vec(&joined).unwrap()
}

fn p256_binding() -> AlgorithmBinding {
    AlgorithmBinding::Spki {
        algorithm: auths_ports::AlgorithmIdentifierDer::new(P256_ALGORITHM.to_vec()).unwrap(),
        suite: auths_model::SignatureSuiteId::parse(ecdsa_der::P256_SHA256_SUITE).unwrap(),
        key_form: KeyForm::Sec1Compressed,
    }
}

fn rekor_log(suite: &P256Sha256Suite) -> RekorLog {
    RekorLog::new(
        CheckpointOrigin::parse(ORIGIN).unwrap(),
        NoteName::parse(KEY_NAME).unwrap(),
        pem_body(REKOR_KEY),
        p256_binding(),
        LogKind::Rfc6962Sha256,
        &[suite as &dyn SignatureSuite],
    )
    .unwrap()
}

/// The recorded entry's fields, owned so tests can mutate them.
struct Recorded {
    body: Vec<u8>,
    checkpoint: String,
    hashes: Vec<Digest>,
    integrated_time: u64,
    log_id: [u8; 32],
    log_index: u64,
    proof_index: u64,
    set: Vec<u8>,
    tree_size: u64,
}

impl Recorded {
    fn load() -> Self {
        let response: serde_json::Value = serde_json::from_str(ENTRY).unwrap();
        let entry = response.as_object().unwrap().values().next().unwrap();
        let proof = &entry["verification"]["inclusionProof"];
        Self {
            body: Base64::decode_vec(entry["body"].as_str().unwrap()).unwrap(),
            checkpoint: proof["checkpoint"].as_str().unwrap().to_string(),
            hashes: proof["hashes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|hash| {
                    Digest::new(
                        hex::decode(hash.as_str().unwrap())
                            .unwrap()
                            .try_into()
                            .unwrap(),
                    )
                })
                .collect(),
            integrated_time: entry["integratedTime"].as_u64().unwrap(),
            log_id: hex::decode(entry["logID"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            log_index: entry["logIndex"].as_u64().unwrap(),
            proof_index: proof["logIndex"].as_u64().unwrap(),
            set: Base64::decode_vec(
                entry["verification"]["signedEntryTimestamp"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
            tree_size: proof["treeSize"].as_u64().unwrap(),
        }
    }

    fn entry(&self) -> RekorEntry {
        let bytes = entry::encode_entry(&EntryFields {
            body: &self.body,
            checkpoint: &self.checkpoint,
            hashes: &self.hashes,
            integrated_time: self.integrated_time,
            log_id: &self.log_id,
            log_index: self.log_index,
            proof_index: self.proof_index,
            signed_entry_timestamp: &self.set,
            tree_size: self.tree_size,
        })
        .unwrap();
        RekorEntry::parse(&bytes).unwrap()
    }
}

#[test]
fn the_pinned_rekor_key_derives_the_recorded_log_id_and_note_hint() {
    let suite = P256Sha256Suite::new().unwrap();
    let log = rekor_log(&suite);
    let recorded = Recorded::load();
    assert_eq!(log.id().bytes(), &recorded.log_id);
    let entry = recorded.entry();
    let note = &entry.checkpoint.signatures[0];
    assert_eq!(note.name.as_str(), KEY_NAME);
    assert_eq!(note.hint, log.note_key_hint);
    assert_eq!(log.note_key_hint, [0xc0, 0xd2, 0x3d, 0x6a]);
    // A sharded log: the proof index is local to the checkpoint's tree.
    assert_ne!(entry.log_index, entry.proof.index);
}

#[test]
fn a_real_signed_entry_timestamp_verifies_and_one_flipped_bit_does_not() {
    let suite = P256Sha256Suite::new().unwrap();
    let suites = [&suite as &dyn SignatureSuite];
    let log = rekor_log(&suite);
    let recorded = Recorded::load();
    assert_eq!(
        verify_signed_entry_timestamp(&suites, &log, &recorded.entry()),
        Ok(())
    );

    let mut signature = Recorded::load();
    let last = signature.set.len() - 1;
    signature.set[last] ^= 1;
    assert_eq!(
        verify_signed_entry_timestamp(&suites, &log, &signature.entry()),
        Err(SigstoreError::SignedEntryTimestamp)
    );
    let mut time = Recorded::load();
    time.integrated_time ^= 1;
    assert_eq!(
        verify_signed_entry_timestamp(&suites, &log, &time.entry()),
        Err(SigstoreError::SignedEntryTimestamp)
    );
    let mut index = Recorded::load();
    index.log_index ^= 1;
    assert_eq!(
        verify_signed_entry_timestamp(&suites, &log, &index.entry()),
        Err(SigstoreError::SignedEntryTimestamp)
    );
}

#[test]
fn a_real_inclusion_proof_and_checkpoint_verify_and_one_flipped_bit_does_not() {
    let suite = P256Sha256Suite::new().unwrap();
    let suites = [&suite as &dyn SignatureSuite];
    let log = rekor_log(&suite);
    assert_eq!(
        verify_inclusion(&suites, &log, &Recorded::load().entry()),
        Ok(())
    );

    let mut hash = Recorded::load();
    let mut bytes = *hash.hashes[3].as_bytes();
    bytes[0] ^= 1;
    hash.hashes[3] = Digest::new(bytes);
    assert_eq!(
        verify_inclusion(&suites, &log, &hash.entry()),
        Err(SigstoreError::Inclusion)
    );
    let mut index = Recorded::load();
    index.proof_index ^= 1;
    assert_eq!(
        verify_inclusion(&suites, &log, &index.entry()),
        Err(SigstoreError::Inclusion)
    );

    let mut note = Recorded::load();
    let (text, line) = note.checkpoint.split_once("\n\n").unwrap();
    let (name, encoded) = line.trim_end().rsplit_once(' ').unwrap();
    let mut decoded = Base64::decode_vec(encoded).unwrap();
    let last = decoded.len() - 1;
    decoded[last] ^= 1;
    note.checkpoint = alloc::format!("{text}\n\n{name} {}\n", Base64::encode_string(&decoded));
    assert_eq!(
        verify_inclusion(&suites, &log, &note.entry()),
        Err(SigstoreError::Checkpoint(CheckpointError::Signature))
    );
}

#[test]
fn a_real_der_entry_signature_is_compared_by_its_low_s_value() {
    let entry = Recorded::load().entry();
    let logged = entry.body.signature.as_slice();
    let fixed = ecdsa_der::low_s_fixed(logged).unwrap();
    assert!(fixed[32] < 0x80, "the fixed form is low-S");
    let suite = ecdsa_der::P256_SHA256_SUITE;
    assert!(entry_signature_matches(suite, logged, &fixed));

    // The recorded signature is high-S: its raw fixed-width form is the
    // other member of the pair and never matches.
    let high_s = &logged[logged.len() - 32..];
    let mut raw = fixed[..32].to_vec();
    raw.extend_from_slice(high_s);
    assert_ne!(raw.as_slice(), fixed.as_slice());
    assert!(!entry_signature_matches(suite, logged, &raw));

    let mut flipped = fixed;
    flipped[5] ^= 1;
    assert!(!entry_signature_matches(suite, logged, &flipped));
    assert!(!entry_signature_matches(suite, logged, logged));
    assert!(!entry_signature_matches("ed25519-v1", logged, &fixed));
}

#[test]
fn a_real_fulcio_github_leaf_yields_the_token_issuer_and_subject() {
    let entry = Recorded::load().entry();
    let bundle: serde_json::Value = serde_json::from_str(TRUST_BUNDLE).unwrap();
    let certificates = bundle["chains"][0]["certificates"].as_array().unwrap();
    let der = |index: usize| {
        auths_ports::CertificateDer::new(pem_body(certificates[index].as_str().unwrap())).unwrap()
    };
    let anchors = BoundedSet::new(vec![der(1)]).unwrap();
    let verified = WebPkiPathVerifier::new()
        .verify(PathInput {
            leaf: &entry.body.certificate,
            intermediates: &[der(0)],
            anchors: &anchors,
            at: entry.integrated,
            required_eku: &ExtendedKeyUsage::code_signing(),
        })
        .unwrap();
    let facts = FulcioFacts::extract(&verified).unwrap();
    assert_eq!(
        facts.issuer.as_str(),
        "https://token.actions.githubusercontent.com"
    );
    assert_eq!(
        facts.subject.as_str(),
        "repo:chainguard-dev/mono:ref:refs/heads/main"
    );

    let policies = BoundedSet::new(vec![FulcioGithubPolicy {
        repository_id: RepositoryId::parse("411469677").unwrap(),
        owner_id: RepositoryOwnerId::parse("87436699").unwrap(),
        workflow: None,
        git_ref: None,
        environment: None,
    }])
    .unwrap();
    let profile = FulcioIssuerProfile::GithubActions { policies };
    let identity = facts.into_identity(&profile).unwrap();
    let FulcioWorkloadIdentity::GithubActions(github) = &identity else {
        panic!("a GitHub identity");
    };
    assert_eq!(github.repository.as_str(), "chainguard-dev/mono");
    assert_eq!(github.git_ref.as_str(), "refs/heads/main");
    assert!(profile.admit(&identity).is_ok());

    let principal = alloc::format!(
        "oidc-workload:{}#{}",
        encode(github.issuer.as_str().as_bytes()),
        encode(github.subject.as_str().as_bytes())
    );
    assert_eq!(
        principal,
        "oidc-workload:https%3A%2F%2Ftoken.actions.githubusercontent.com#repo%3Achainguard-dev%2Fmono%3Aref%3Arefs%2Fheads%2Fmain"
    );
    assert!(parse_principal(&principal).is_ok());
}
