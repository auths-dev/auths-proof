//! Signers for CI workloads, whose principal is the workload identity an
//! OIDC issuer attests, `oidc-workload:<issuer>#<subject>`.
//!
//! Both signers hold an ephemeral key that exists only in process memory and
//! is zeroized on drop — Ed25519 for the OIDC signer, P-256 for the Sigstore
//! signer, whose key Fulcio certifies and Rekor records. They differ in how
//! the key is bound to the workload identity:
//!
//! - [`OidcWorkloadSigner`] requests a token whose audience commits to the
//!   key descriptor, and presents the token and descriptor as evidence. A
//!   verifier needs the issuer keys current at verification time and accepts
//!   the token only inside its short validity window, so this method suits a
//!   live gate.
//! - [`SigstoreKeylessSigner`] obtains a short-lived certificate for the key
//!   and records the exact signature in a transparency log. It talks to
//!   Fulcio and Rekor through [`SigstoreClient`].
//!
//! Network acquisition happens here, in the signer, and never in the
//! verifier. Tokens are credentials: nothing here prints or logs them, and
//! errors never carry response bodies.

use crate::sign::{GitProofSigner, SignError};
use auths_author::address_evidence;
use auths_model::{
    Digest, EvidenceObject, EvidenceTypeId, MediaType, PrincipalId, PrincipalMethodId,
    SignatureBytes, SignatureDescriptor, SignatureSuiteId,
};
use auths_oidc_workload::identity::{IssuerUrl, Subject};
use auths_oidc_workload::jws::CompactJws;
use auths_oidc_workload::{OIDC_WORKLOAD_V1, TOKEN_MEDIA_TYPE, audience_commitment};
use auths_raw_key_core::{RAW_KEY_V2_MEDIA_TYPE, RawKeyDescriptorV2};
use auths_signature::{ED25519_V1, P256_SHA256_V1};
use auths_sigstore_keyless::chain::CertificateChain;
use auths_sigstore_keyless::entry::{EntryFields, encode_entry};
use auths_sigstore_keyless::{CHAIN_MEDIA_TYPE, ENTRY_MEDIA_TYPE, SIGSTORE_KEYLESS_V1};
use ed25519_dalek::{Signer as _, SigningKey};
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use sha2::{Digest as _, Sha256};
use std::cell::RefCell;
use std::io::Read as _;
use std::time::Duration;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::methods::P256_SPKI_PREFIX;

/// Audience Fulcio requires on the token it exchanges for a certificate.
pub const SIGSTORE_AUDIENCE: &str = "sigstore";
/// Maximum token response accepted from an issuer endpoint.
pub const MAX_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;
/// Timeout for one token request.
const TOKEN_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Why a workload signer could not be set up or could not sign.
#[derive(Debug, Error)]
pub enum WorkloadError {
    /// No token could be obtained.
    #[error("workload token unavailable: {0}")]
    TokenUnavailable(&'static str),
    /// The token is malformed or does not match the request.
    #[error("workload token rejected: {0}")]
    Token(&'static str),
    /// Fulcio or Rekor refused or failed.
    #[error("sigstore: {0}")]
    Sigstore(String),
    /// A key or identifier could not be created.
    #[error("could not create the workload key or identity")]
    Identity,
}

/// A source of OIDC identity tokens for the running workload.
pub trait TokenSource {
    /// Returns a compact JWS whose `aud` claim is exactly `audience`.
    ///
    /// # Errors
    ///
    /// Returns [`WorkloadError::TokenUnavailable`] when no token can be
    /// obtained.
    fn token(&self, audience: &str) -> Result<Zeroizing<String>, WorkloadError>;
}

/// Tokens from the GitHub Actions OIDC endpoint of the running job.
///
/// The job must grant `permissions: id-token: write`; GitHub then sets
/// `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN`.
pub struct GithubActionsTokenSource {
    url: String,
    bearer: Zeroizing<String>,
}

impl GithubActionsTokenSource {
    /// Reads the request endpoint from the job environment.
    ///
    /// # Errors
    ///
    /// Returns [`WorkloadError::TokenUnavailable`] when either variable is
    /// unset or the endpoint is not `https`.
    pub fn from_env() -> Result<Self, WorkloadError> {
        let url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").map_err(|_| {
            WorkloadError::TokenUnavailable(
                "ACTIONS_ID_TOKEN_REQUEST_URL is unset; grant the job `id-token: write`",
            )
        })?;
        let bearer = Zeroizing::new(std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").map_err(
            |_| {
                WorkloadError::TokenUnavailable(
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN is unset; grant the job `id-token: write`",
                )
            },
        )?);
        if !url.starts_with("https://") {
            return Err(WorkloadError::TokenUnavailable(
                "ACTIONS_ID_TOKEN_REQUEST_URL is not https",
            ));
        }
        Ok(Self { url, bearer })
    }
}

impl TokenSource for GithubActionsTokenSource {
    fn token(&self, audience: &str) -> Result<Zeroizing<String>, WorkloadError> {
        #[derive(serde::Deserialize)]
        struct TokenResponse {
            value: String,
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(TOKEN_REQUEST_TIMEOUT)
            .build()
            .map_err(|_| WorkloadError::TokenUnavailable("could not build an HTTP client"))?;
        let response = client
            .get(&self.url)
            .query(&[("audience", audience)])
            .bearer_auth(self.bearer.as_str())
            .send()
            .map_err(|_| WorkloadError::TokenUnavailable("the token request failed"))?;
        if !response.status().is_success() {
            return Err(WorkloadError::TokenUnavailable(
                "the token endpoint refused the request",
            ));
        }
        let mut body = Zeroizing::new(Vec::new());
        response
            .take(
                u64::try_from(MAX_TOKEN_RESPONSE_BYTES)
                    .map_or(u64::MAX, |limit| limit.saturating_add(1)),
            )
            .read_to_end(&mut body)
            .map_err(|_| WorkloadError::TokenUnavailable("could not read the token response"))?;
        if body.len() > MAX_TOKEN_RESPONSE_BYTES {
            return Err(WorkloadError::TokenUnavailable(
                "the token response exceeds its limit",
            ));
        }
        let parsed: TokenResponse = serde_json::from_slice(&body)
            .map_err(|_| WorkloadError::TokenUnavailable("the token response is malformed"))?;
        Ok(Zeroizing::new(parsed.value))
    }
}

/// The workload identity a token names, read without verifying it. The
/// verifier checks the token; the signer reads it only to name itself and
/// to fail early on a token issued for another key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenIdentity {
    /// The workload principal, `oidc-workload:<issuer>#<subject>`.
    pub principal: PrincipalId,
    /// The `sub` claim.
    pub subject: String,
}

impl TokenIdentity {
    /// Reads the issuer, subject, and audience of a compact JWS.
    ///
    /// # Errors
    ///
    /// Returns [`WorkloadError::Token`] for a malformed token, missing or
    /// invalid claims, or an audience other than `audience`.
    pub fn read(token: &[u8], audience: &str) -> Result<Self, WorkloadError> {
        #[derive(serde::Deserialize)]
        struct Claims {
            iss: String,
            sub: String,
            aud: serde_json::Value,
        }
        let jws =
            CompactJws::parse(token).map_err(|_| WorkloadError::Token("not a compact JWS"))?;
        let claims: Claims = serde_json::from_slice(&jws.payload)
            .map_err(|_| WorkloadError::Token("claims are malformed"))?;
        let audience_matches = match &claims.aud {
            serde_json::Value::String(value) => value == audience,
            serde_json::Value::Array(values) => {
                values.len() == 1 && values[0].as_str() == Some(audience)
            }
            _ => false,
        };
        if !audience_matches {
            return Err(WorkloadError::Token(
                "the audience does not commit to this key",
            ));
        }
        let issuer =
            IssuerUrl::parse(&claims.iss).map_err(|_| WorkloadError::Token("invalid issuer"))?;
        let subject =
            Subject::parse(&claims.sub).map_err(|_| WorkloadError::Token("invalid subject"))?;
        Ok(Self {
            principal: auths_oidc_workload::principal(&issuer, &subject)
                .map_err(|_| WorkloadError::Token("the workload principal is too long"))?,
            subject: claims.sub,
        })
    }
}

/// Generates an ephemeral Ed25519 key; the seed is zeroized after use and
/// the key zeroizes itself on drop.
fn ephemeral_key() -> Result<SigningKey, WorkloadError> {
    let mut seed = Zeroizing::new([0_u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|_| WorkloadError::Identity)?;
    Ok(SigningKey::from_bytes(&seed))
}

fn evidence(kind: &str, media: &str, bytes: Vec<u8>) -> Result<EvidenceObject, WorkloadError> {
    address_evidence(
        EvidenceTypeId::parse(kind).map_err(|_| WorkloadError::Identity)?,
        MediaType::parse(media).map_err(|_| WorkloadError::Identity)?,
        bytes,
    )
    .map_err(|_| WorkloadError::Identity)
}

fn descriptor(
    method: &str,
    verification_method: auths_model::VerificationMethod,
    suite: &str,
) -> Result<SignatureDescriptor, WorkloadError> {
    Ok(SignatureDescriptor::new(
        PrincipalMethodId::parse(method).map_err(|_| WorkloadError::Identity)?,
        verification_method,
        SignatureSuiteId::parse(suite).map_err(|_| WorkloadError::Identity)?,
    ))
}

/// Generates an ephemeral P-256 key. The scalar bytes are zeroized after
/// use and the key zeroizes itself on drop. A candidate outside the group
/// order, with probability about 2^-32, is drawn again.
fn ephemeral_p256_key() -> Result<P256SigningKey, WorkloadError> {
    for _ in 0..8 {
        let mut scalar = Zeroizing::new([0_u8; 32]);
        getrandom::fill(scalar.as_mut()).map_err(|_| WorkloadError::Identity)?;
        if let Ok(key) = P256SigningKey::from_bytes(&(*scalar).into()) {
            return Ok(key);
        }
    }
    Err(WorkloadError::Identity)
}

/// Signs with ECDSA P-256/SHA-256 and returns the signature in the low-S
/// form the kernel's P-256 suite accepts. `to_der` of the result is the
/// encoding Fulcio and Rekor take.
fn sign_p256(key: &P256SigningKey, message: &[u8]) -> P256Signature {
    let signature: P256Signature = p256::ecdsa::signature::Signer::sign(key, message);
    signature.normalize_s().unwrap_or(signature)
}

fn sign_ed25519(key: &SigningKey, preimage: &[u8]) -> Result<SignatureBytes, SignError> {
    SignatureBytes::new(key.sign(preimage).to_bytes().to_vec()).map_err(|_| SignError::Signer)
}

/// A workload signer whose control evidence is an OIDC token bound to an
/// ephemeral key.
pub struct OidcWorkloadSigner {
    key: SigningKey,
    principal: PrincipalId,
    descriptor: SignatureDescriptor,
    evidence: Vec<EvidenceObject>,
}

impl OidcWorkloadSigner {
    /// Creates an ephemeral key and obtains a token whose audience commits
    /// to it.
    ///
    /// # Errors
    ///
    /// Returns [`WorkloadError`] when no token is available, the token names
    /// another audience or an invalid identity, or evidence cannot be built.
    pub fn acquire(tokens: &dyn TokenSource) -> Result<Self, WorkloadError> {
        let key = ephemeral_key()?;
        let key_descriptor = RawKeyDescriptorV2::new(
            SignatureSuiteId::parse(ED25519_V1).map_err(|_| WorkloadError::Identity)?,
            key.verifying_key().to_bytes().to_vec(),
        )
        .map_err(|_| WorkloadError::Identity)?;
        let audience = audience_commitment(&key_descriptor);
        let token = tokens.token(&audience)?;
        let identity = TokenIdentity::read(token.as_bytes(), &audience)?;
        let method =
            auths_oidc_workload::verification_method(identity.principal.as_str(), token.as_bytes())
                .map_err(|_| WorkloadError::Identity)?;
        let evidence = vec![
            evidence(
                OIDC_WORKLOAD_V1,
                TOKEN_MEDIA_TYPE,
                token.as_bytes().to_vec(),
            )?,
            evidence(
                OIDC_WORKLOAD_V1,
                RAW_KEY_V2_MEDIA_TYPE,
                key_descriptor.encode(),
            )?,
        ];
        Ok(Self {
            key,
            principal: identity.principal,
            descriptor: descriptor(OIDC_WORKLOAD_V1, method, ED25519_V1)?,
            evidence,
        })
    }
}

impl GitProofSigner for OidcWorkloadSigner {
    fn principal(&self) -> PrincipalId {
        self.principal.clone()
    }

    fn descriptor(&self) -> SignatureDescriptor {
        self.descriptor.clone()
    }

    fn control_evidence(&self) -> Vec<EvidenceObject> {
        self.evidence.clone()
    }

    fn sign(&self, preimage: &[u8]) -> Result<SignatureBytes, SignError> {
        sign_ed25519(&self.key, preimage)
    }
}

/// A certificate request to Fulcio.
pub struct CertificateRequest<'a> {
    /// The OIDC token, with audience [`SIGSTORE_AUDIENCE`].
    pub token: &'a str,
    /// DER `SubjectPublicKeyInfo` of the ephemeral P-256 key.
    pub public_key_spki: &'a [u8],
    /// The ephemeral key's DER ECDSA signature over the token's `sub` claim.
    pub proof_of_possession: &'a [u8],
}

/// A `hashedrekord` submission to Rekor.
pub struct HashedRekordRequest<'a> {
    /// SHA-256 of the signed bytes.
    pub artifact_sha256: [u8; 32],
    /// The DER encoding of the exact low-S action signature.
    pub signature: &'a [u8],
    /// DER of the leaf certificate for the signing key.
    pub certificate_der: &'a [u8],
}

/// The Rekor entry fields the Sigstore keyless evidence encodes.
pub struct RekorEntryFields {
    /// The canonical entry body.
    pub body: Vec<u8>,
    /// The signed checkpoint note.
    pub checkpoint: String,
    /// The inclusion proof hashes.
    pub hashes: Vec<[u8; 32]>,
    /// The log's integration time, in Unix seconds.
    pub integrated_time: u64,
    /// SHA-256 of the log's public key.
    pub log_id: [u8; 32],
    /// The entry's index across the whole log.
    pub log_index: u64,
    /// The entry's leaf index in the tree the checkpoint names.
    pub proof_index: u64,
    /// The log's signature over the entry.
    pub signed_entry_timestamp: Vec<u8>,
    /// The tree size the proof and checkpoint refer to.
    pub tree_size: u64,
}

/// Fulcio and Rekor, as a port.
pub trait SigstoreClient {
    /// Obtains a certificate chain, leaf first, for the requested key.
    ///
    /// # Errors
    ///
    /// Returns [`WorkloadError::Sigstore`] when Fulcio refuses or fails.
    fn issue_certificate(
        &self,
        request: &CertificateRequest<'_>,
    ) -> Result<Vec<Vec<u8>>, WorkloadError>;

    /// Records a signature and returns the entry with its inclusion proof.
    ///
    /// # Errors
    ///
    /// Returns [`WorkloadError::Sigstore`] when Rekor refuses or fails.
    fn submit_hashed_rekord(
        &self,
        request: &HashedRekordRequest<'_>,
    ) -> Result<RekorEntryFields, WorkloadError>;
}

/// A workload signer whose control evidence is a Fulcio certificate chain
/// and the Rekor entry for the exact signature.
pub struct SigstoreKeylessSigner<'c> {
    key: P256SigningKey,
    principal: PrincipalId,
    descriptor: SignatureDescriptor,
    leaf: Vec<u8>,
    chain: EvidenceObject,
    entry: RefCell<Option<EvidenceObject>>,
    client: &'c dyn SigstoreClient,
}

impl<'c> SigstoreKeylessSigner<'c> {
    /// Creates an ephemeral P-256 key and obtains its certificate.
    ///
    /// # Errors
    ///
    /// Returns [`WorkloadError`] when no token is available, Fulcio fails,
    /// or evidence cannot be built.
    pub fn acquire(
        tokens: &dyn TokenSource,
        client: &'c dyn SigstoreClient,
    ) -> Result<Self, WorkloadError> {
        let key = ephemeral_p256_key()?;
        let mut spki = P256_SPKI_PREFIX.to_vec();
        spki.extend_from_slice(key.verifying_key().to_encoded_point(false).as_bytes());
        let token = tokens.token(SIGSTORE_AUDIENCE)?;
        let identity = TokenIdentity::read(token.as_bytes(), SIGSTORE_AUDIENCE)?;
        let proof = sign_p256(&key, identity.subject.as_bytes()).to_der();
        let chain = client.issue_certificate(&CertificateRequest {
            token: token.as_str(),
            public_key_spki: &spki,
            proof_of_possession: proof.as_bytes(),
        })?;
        let leaf = chain
            .first()
            .cloned()
            .ok_or_else(|| WorkloadError::Sigstore("Fulcio returned no certificate".to_owned()))?;
        let encoded = CertificateChain::encode(&chain).map_err(|_| {
            WorkloadError::Sigstore("the certificate chain exceeds its limits".to_owned())
        })?;
        let method =
            auths_sigstore_keyless::verification_method(identity.principal.as_str(), &leaf)
                .map_err(|_| WorkloadError::Identity)?;
        Ok(Self {
            key,
            descriptor: descriptor(SIGSTORE_KEYLESS_V1, method, P256_SHA256_V1)?,
            principal: identity.principal,
            leaf,
            chain: evidence(SIGSTORE_KEYLESS_V1, CHAIN_MEDIA_TYPE, encoded)?,
            entry: RefCell::new(None),
            client,
        })
    }
}

impl GitProofSigner for SigstoreKeylessSigner<'_> {
    fn principal(&self) -> PrincipalId {
        self.principal.clone()
    }

    fn descriptor(&self) -> SignatureDescriptor {
        self.descriptor.clone()
    }

    /// The certificate chain, and the Rekor entry once [`Self::sign`] has
    /// recorded a signature. Without an entry the evidence is incomplete and
    /// verification fails.
    fn control_evidence(&self) -> Vec<EvidenceObject> {
        let mut evidence = vec![self.chain.clone()];
        evidence.extend(self.entry.borrow().iter().cloned());
        evidence
    }

    /// Signs `preimage` and records the signature in Rekor. The action
    /// carries the fixed-width low-S signature; Rekor records its DER
    /// encoding, which the adapter compares by value.
    fn sign(&self, preimage: &[u8]) -> Result<SignatureBytes, SignError> {
        let signature = sign_p256(&self.key, preimage);
        let fields = self
            .client
            .submit_hashed_rekord(&HashedRekordRequest {
                artifact_sha256: Sha256::digest(preimage).into(),
                signature: signature.to_der().as_bytes(),
                certificate_der: &self.leaf,
            })
            .map_err(|_| SignError::Signer)?;
        let hashes: Vec<Digest> = fields.hashes.iter().copied().map(Digest::new).collect();
        let entry = encode_entry(&EntryFields {
            body: &fields.body,
            checkpoint: &fields.checkpoint,
            hashes: &hashes,
            integrated_time: fields.integrated_time,
            log_id: &fields.log_id,
            log_index: fields.log_index,
            proof_index: fields.proof_index,
            signed_entry_timestamp: &fields.signed_entry_timestamp,
            tree_size: fields.tree_size,
        })
        .map_err(|_| SignError::Signer)?;
        let entry = evidence(SIGSTORE_KEYLESS_V1, ENTRY_MEDIA_TYPE, entry)
            .map_err(|_| SignError::Signer)?;
        *self.entry.borrow_mut() = Some(entry);
        SignatureBytes::new(signature.to_bytes().to_vec()).map_err(|_| SignError::Signer)
    }
}
