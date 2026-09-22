//! Deterministic, network-free stand-ins for an OIDC issuer, Fulcio, and
//! Rekor. Keys come from fixed seeds and times are fixed, so every run
//! produces the same verification outcomes.

use crate::methods::{ED25519_SPKI_PREFIX, METHODS_SCHEMA, P256_SPKI_PREFIX};
use crate::workload::{
    CertificateRequest, HashedRekordRequest, RekorEntryFields, SigstoreClient, TokenSource,
    WorkloadError,
};
use auths_oidc_workload::jws::CompactJws;
use auths_sigstore_keyless::merkle::leaf_hash;
use base64ct::{Base64, Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::SigningKey;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey};
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PublicKeyData, SanType,
    SignatureAlgorithm,
};
use sha2::{Digest as _, Sha256};
use std::cell::Cell;
use std::time::Duration;
use zeroize::Zeroizing;

/// 2026-09-22T00:00:00Z; every fixed time is an offset from it.
pub const BASE: u64 = 1_790_035_200;
/// The evaluation time of the workload tests.
pub const NOW: u64 = BASE + 1_800;
/// GitHub's issuer URL.
pub const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
/// The GitHub repository id the fake tokens carry.
pub const REPOSITORY_ID: &str = "7001";
/// The GitHub owner id the fake tokens carry.
pub const OWNER_ID: &str = "7002";
/// The workload `sub` claim the fake tokens and certificates carry.
pub const SUBJECT: &str = "repo:acme/app:ref:refs/heads/main";

const WORKFLOW_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

/// An OIDC issuer holding one Ed25519 signing key.
pub struct FakeIssuer {
    key: SigningKey,
    kid: &'static str,
}

impl FakeIssuer {
    pub fn new(seed: u8) -> Self {
        Self {
            key: SigningKey::from_bytes(&[seed; 32]),
            kid: "fake-issuer-key",
        }
    }

    /// The key as a JWKS entry.
    pub fn jwk(&self) -> serde_json::Value {
        serde_json::json!({
            "kid": self.kid,
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
            "x": Base64UrlUnpadded::encode_string(self.key.verifying_key().as_bytes()),
        })
    }

    /// Signs a GitHub-shaped token for `audience`.
    pub fn github_token(&self, audience: &str, repository_id: &str, issued_at: u64) -> String {
        let claims = serde_json::json!({
            "jti": "fake-jti",
            "sub": SUBJECT,
            "aud": audience,
            "ref": "refs/heads/main",
            "sha": WORKFLOW_SHA,
            "repository": "acme/app",
            "repository_owner": "acme",
            "repository_owner_id": OWNER_ID,
            "run_id": "1",
            "run_number": "1",
            "run_attempt": "1",
            "repository_visibility": "private",
            "repository_id": repository_id,
            "actor_id": "9",
            "actor": "octocat",
            "workflow": "git-signing",
            "head_ref": "",
            "base_ref": "",
            "event_name": "push",
            "ref_protected": "true",
            "ref_type": "branch",
            "workflow_ref": "acme/app/.github/workflows/git-signing.yml@refs/heads/main",
            "workflow_sha": WORKFLOW_SHA,
            "job_workflow_ref": "acme/app/.github/workflows/git-signing.yml@refs/heads/main",
            "job_workflow_sha": WORKFLOW_SHA,
            "runner_environment": "github-hosted",
            "iss": GITHUB_ISSUER,
            "nbf": issued_at,
            "iat": issued_at,
            "exp": issued_at + 300,
        });
        self.sign_claims(&claims)
    }

    fn sign_claims(&self, claims: &serde_json::Value) -> String {
        let header = serde_json::json!({"alg": "EdDSA", "kid": self.kid, "typ": "JWT"});
        let signing_input = format!(
            "{}.{}",
            Base64UrlUnpadded::encode_string(header.to_string().as_bytes()),
            Base64UrlUnpadded::encode_string(claims.to_string().as_bytes())
        );
        let signature = self.key.sign(signing_input.as_bytes()).to_bytes();
        format!(
            "{signing_input}.{}",
            Base64UrlUnpadded::encode_string(&signature)
        )
    }

    /// The `oidc_workload` section of `methods.json` pinning this issuer.
    pub fn methods(&self) -> serde_json::Value {
        serde_json::json!({"issuers": [{
            "issuer": GITHUB_ISSUER,
            "max_token_lifetime_seconds": 600,
            "keys": [self.jwk()],
            "profile": {"github_actions": [
                {"repository_id": REPOSITORY_ID, "owner_id": OWNER_ID, "ref": "refs/heads/main"}
            ]},
        }]})
    }
}

/// A token source minting GitHub-shaped tokens from a [`FakeIssuer`].
pub struct MintingSource<'a> {
    pub issuer: &'a FakeIssuer,
    pub repository_id: &'a str,
    pub issued_at: u64,
}

impl TokenSource for MintingSource<'_> {
    fn token(&self, audience: &str) -> Result<Zeroizing<String>, WorkloadError> {
        Ok(Zeroizing::new(self.issuer.github_token(
            audience,
            self.repository_id,
            self.issued_at,
        )))
    }
}

/// A P-256 public key as the uncompressed point rcgen embeds.
struct RawP256(Vec<u8>);

impl PublicKeyData for RawP256 {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

fn ed25519_pkcs8(seed: u8) -> Vec<u8> {
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(&[seed; 32]);
    der
}

fn utf8_string(value: &str) -> Vec<u8> {
    let length = u8::try_from(value.len()).expect("short extension value");
    let mut der = vec![0x0c, length];
    der.extend_from_slice(value.as_bytes());
    der
}

fn pem(der: &[u8]) -> String {
    let encoded = Base64::encode_string(der);
    let mut text = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in encoded.as_bytes().chunks(64) {
        text.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        text.push('\n');
    }
    text.push_str("-----END CERTIFICATE-----\n");
    text
}

/// Sets a certificate's validity to `[from, until)` in Unix seconds, both at
/// or after [`BASE`].
fn set_validity(params: &mut CertificateParams, from: u64, until: u64) {
    let base = rcgen::date_time_ymd(2026, 9, 22);
    assert_eq!(base.unix_timestamp(), i64::try_from(BASE).expect("base"));
    params.not_before = base + Duration::from_secs(from - BASE);
    params.not_after = base + Duration::from_secs(until - BASE);
}

/// The key a fake Rekor log signs with.
pub enum FakeLogKey {
    /// Raw Ed25519 signatures.
    Ed25519(SigningKey),
    /// DER ECDSA signatures, always the high-S member of their pair, as a
    /// real log may emit.
    P256(P256SigningKey),
}

impl FakeLogKey {
    fn spki(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(key) => {
                let mut spki = ED25519_SPKI_PREFIX.to_vec();
                spki.extend_from_slice(key.verifying_key().as_bytes());
                spki
            }
            Self::P256(key) => {
                let mut spki = P256_SPKI_PREFIX.to_vec();
                spki.extend_from_slice(key.verifying_key().to_encoded_point(false).as_bytes());
                spki
            }
        }
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Ed25519(key) => ed25519_dalek::Signer::sign(key, message)
                .to_bytes()
                .to_vec(),
            Self::P256(key) => {
                let signature: P256Signature = key.sign(message);
                let low = signature.normalize_s().unwrap_or(signature);
                let (r, s) = low.split_scalars();
                let high = P256Signature::from_scalars(r.to_bytes(), (-*s).to_bytes())
                    .expect("high-S pair");
                assert!(
                    high.normalize_s().is_some(),
                    "the emitted signature is high-S"
                );
                high.to_der().as_bytes().to_vec()
            }
        }
    }

    /// The signed-note key hint: Rekor's ECDSA key id for P-256, the key
    /// name and SPKI digest otherwise.
    fn hint(&self, name: &str) -> Vec<u8> {
        let digest = match self {
            Self::Ed25519(_) => {
                let mut input = name.as_bytes().to_vec();
                input.push(b'\n');
                input.extend(self.spki());
                Sha256::digest(&input)
            }
            Self::P256(_) => Sha256::digest(self.spki()),
        };
        digest[..4].to_vec()
    }

    fn methods_member(&self) -> &'static str {
        match self {
            Self::Ed25519(_) => "ed25519_spki",
            Self::P256(_) => "p256_spki",
        }
    }
}

/// The whole-log index the fake Rekor reports. It differs from the proof
/// index, as it does for a sharded log.
const FAKE_LOG_INDEX: u64 = 1_000;

/// Fulcio and Rekor. Fulcio issues P-256 leaves with the issuer and
/// subject extensions, a deprecated raw issuer extension as real Fulcio
/// still emits, and the code-signing usage; Rekor is a one-entry log.
pub struct FakeSigstore {
    ca_key: KeyPair,
    ca: rcgen::Certificate,
    log_key: FakeLogKey,
    origin: &'static str,
    key_name: &'static str,
    /// Leaf validity, `[from, until)`.
    pub leaf_window: (u64, u64),
    /// The integration time Rekor reports.
    pub integrated_time: u64,
    /// When set, Rekor returns an entry whose timestamp signature is broken.
    pub corrupt_entry: Cell<bool>,
}

impl FakeSigstore {
    pub fn new(seed: u8) -> Self {
        Self::with_keys(seed, seed.wrapping_add(1))
    }

    /// A Fulcio CA from `ca_seed` and an Ed25519 Rekor log key from
    /// `log_seed`.
    pub fn with_keys(ca_seed: u8, log_seed: u8) -> Self {
        Self::with_log(
            ca_seed,
            FakeLogKey::Ed25519(SigningKey::from_bytes(&[log_seed; 32])),
        )
    }

    /// A Fulcio CA from `ca_seed` and a P-256 Rekor log key from `log_seed`,
    /// like public-good Rekor.
    pub fn with_p256_log(ca_seed: u8, log_seed: u8) -> Self {
        let key = P256SigningKey::from_bytes(&[log_seed; 32].into()).expect("P-256 log key");
        Self::with_log(ca_seed, FakeLogKey::P256(key))
    }

    fn with_log(seed: u8, log_key: FakeLogKey) -> Self {
        let ca_key = KeyPair::try_from(ed25519_pkcs8(seed).as_slice()).expect("CA key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, format!("fake fulcio root {seed}"));
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        set_validity(&mut params, BASE, BASE + 365 * 86_400);
        let ca = params.self_signed(&ca_key).expect("CA certificate");
        Self {
            ca_key,
            ca,
            log_key,
            origin: "rekor.fake - 1",
            key_name: "rekor.fake",
            leaf_window: (NOW - 300, NOW + 300),
            integrated_time: NOW - 20,
            corrupt_entry: Cell::new(false),
        }
    }

    /// The `sigstore_keyless` section of `methods.json` pinning this CA and
    /// log, admitting `subject` from `issuer`.
    pub fn methods(&self, issuer: &str, subject: &str) -> serde_json::Value {
        let mut log = serde_json::json!({"origin": self.origin, "key_name": self.key_name});
        log[self.log_key.methods_member()] =
            serde_json::Value::String(Base64::encode_string(&self.log_key.spki()));
        serde_json::json!({
            "fulcio_roots": [Base64::encode_string(self.ca.der())],
            "rekor_logs": [log],
            "issuers": [{"issuer": issuer, "profile": {"generic": [subject]}}],
            "max_leaf_validity_seconds": 600,
        })
    }

    fn checkpoint(&self, root: &[u8]) -> String {
        let body = format!("{}\n1\n{}\n", self.origin, Base64::encode_string(root));
        let mut note = self.log_key.hint(self.key_name);
        note.extend(self.log_key.sign(body.as_bytes()));
        format!(
            "{body}\n\u{2014} {} {}\n",
            self.key_name,
            Base64::encode_string(&note)
        )
    }
}

impl SigstoreClient for FakeSigstore {
    fn issue_certificate(
        &self,
        request: &CertificateRequest<'_>,
    ) -> Result<Vec<Vec<u8>>, WorkloadError> {
        let refuse = |reason: &str| WorkloadError::Sigstore(reason.to_owned());
        let key = request
            .public_key_spki
            .strip_prefix(P256_SPKI_PREFIX.as_slice())
            .and_then(|point| VerifyingKey::from_sec1_bytes(point).ok())
            .ok_or_else(|| refuse("not a P-256 key"))?;
        let jws = CompactJws::parse(request.token.as_bytes()).map_err(|_| refuse("token"))?;
        let claims: serde_json::Value =
            serde_json::from_slice(&jws.payload).map_err(|_| refuse("claims"))?;
        let (Some(issuer), Some(subject)) = (claims["iss"].as_str(), claims["sub"].as_str()) else {
            return Err(refuse("claims"));
        };
        let proof = P256Signature::from_der(request.proof_of_possession)
            .map_err(|_| refuse("proof of possession"))?;
        key.verify(subject.as_bytes(), &proof)
            .map_err(|_| refuse("proof of possession"))?;

        let mut params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
        params.distinguished_name = DistinguishedName::new();
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
        params.subject_alt_names = vec![SanType::URI(
            "https://github.com/acme/app/.github/workflows/git-signing.yml@refs/heads/main"
                .try_into()
                .expect("SAN"),
        )];
        params.custom_extensions = vec![
            CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 57264, 1, 1],
                issuer.as_bytes().to_vec(),
            ),
            CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 57264, 1, 8],
                utf8_string(issuer),
            ),
            CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 57264, 1, 24],
                utf8_string(subject),
            ),
        ];
        set_validity(&mut params, self.leaf_window.0, self.leaf_window.1);
        let point = key.to_encoded_point(false).as_bytes().to_vec();
        let leaf = params
            .signed_by(&RawP256(point), &self.ca, &self.ca_key)
            .map_err(|_| refuse("leaf"))?;
        Ok(vec![leaf.der().to_vec()])
    }

    fn submit_hashed_rekord(
        &self,
        request: &HashedRekordRequest<'_>,
    ) -> Result<RekorEntryFields, WorkloadError> {
        let body = format!(
            "{{\"apiVersion\":\"0.0.1\",\"kind\":\"hashedrekord\",\"spec\":{{\"data\":{{\"hash\":{{\"algorithm\":\"sha256\",\"value\":\"{}\"}}}},\"signature\":{{\"content\":\"{}\",\"publicKey\":{{\"content\":\"{}\"}}}}}}}}",
            hex::encode(request.artifact_sha256),
            Base64::encode_string(request.signature),
            Base64::encode_string(pem(request.certificate_der).as_bytes()),
        )
        .into_bytes();
        let log_id: [u8; 32] = Sha256::digest(self.log_key.spki()).into();
        let root = leaf_hash(&body);
        let set_preimage = format!(
            "{{\"body\":\"{}\",\"integratedTime\":{},\"logID\":\"{}\",\"logIndex\":{FAKE_LOG_INDEX}}}",
            Base64::encode_string(&body),
            self.integrated_time,
            hex::encode(log_id),
        );
        let mut signed_entry_timestamp = self.log_key.sign(set_preimage.as_bytes());
        if self.corrupt_entry.get() {
            let last = signed_entry_timestamp.len() - 1;
            signed_entry_timestamp[last] ^= 1;
        }
        Ok(RekorEntryFields {
            checkpoint: self.checkpoint(root.as_bytes()),
            body,
            hashes: Vec::new(),
            integrated_time: self.integrated_time,
            log_id,
            log_index: FAKE_LOG_INDEX,
            proof_index: 0,
            signed_entry_timestamp,
            tree_size: 1,
        })
    }
}

/// A complete `methods.json` with the given sections.
pub fn methods_file(
    oidc: Option<serde_json::Value>,
    sigstore: Option<serde_json::Value>,
) -> Vec<u8> {
    let mut file = serde_json::json!({"schema": METHODS_SCHEMA});
    if let Some(oidc) = oidc {
        file["oidc_workload"] = oidc;
    }
    if let Some(sigstore) = sigstore {
        file["sigstore_keyless"] = sigstore;
    }
    file.to_string().into_bytes()
}
