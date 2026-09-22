//! The workload principal methods a repository's trust enables, read from
//! `methods.json` next to `trust.cbor`.
//!
//! The file is strict JSON: every object rejects unknown and duplicated
//! members, every string is parsed into the adapter's typed value, and every
//! collection is bounded by the adapter's own limits. A missing file enables
//! `did:key` only.
//!
//! ```json
//! {
//!   "schema": "auths.git-methods/1",
//!   "oidc_workload": {
//!     "issuers": [{
//!       "issuer": "https://token.actions.githubusercontent.com",
//!       "max_token_lifetime_seconds": 3600,
//!       "keys": [
//!         {"kid": "…", "kty": "RSA", "alg": "RS256", "n": "…", "e": "AQAB"},
//!         {"kid": "…", "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "x": "…"}
//!       ],
//!       "profile": {"github_actions": [
//!         {"repository_id": "123", "owner_id": "456", "ref": "refs/heads/main"}
//!       ]}
//!     }]
//!   },
//!   "sigstore_keyless": {
//!     "fulcio_roots": ["<base64 DER certificate>"],
//!     "rekor_logs": [
//!       {"origin": "…", "key_name": "…", "p256_spki": "<base64 DER SPKI>"}
//!     ],
//!     "issuers": [{"issuer": "…", "profile": {"generic": ["<subject>"]}}],
//!     "max_leaf_validity_seconds": 600
//!   }
//! }
//! ```
//!
//! A GitHub policy, for either method, takes a repository id, an owner id,
//! and optionally an exact `ref`, an `environment`, and a `workflow` pin:
//! `{"path": ".github/workflows/release.yml"}` for that workflow on any ref,
//! or with both `ref` and `commit` for one exact workflow revision. Both
//! adapters bind every one of these fields into their configuration
//! commitment, so trust commits to every rule it applies.
//!
//! Each Rekor log pins exactly one key, as `p256_spki` (public-good Rekor)
//! or `ed25519_spki`. A P-256 log's DER ECDSA signatures are converted to
//! the kernel suite's fixed-width low-S form by the adapter before they are
//! verified. Fulcio leaves must carry P-256 keys, the key type the Sigstore
//! keyless signer generates.

use auths_model::{BoundedSet, SignatureSuiteId};
use auths_oidc_workload::identity::{
    self as oidc_identity, GenericPolicy, GithubPolicy, IssuerProfile,
};
use auths_oidc_workload::jws::KeyId;
use auths_oidc_workload::window::TokenLifetime;
use auths_oidc_workload::{Issuer, PinnedIssuerKey};
use auths_ports::{
    AlgorithmBinding, AlgorithmBindingSet, AlgorithmIdentifierDer, CertificateDer,
    JwsAlgorithmName, KeyForm, SignatureSuite, TrustAnchorSet,
};
use auths_signature::{ED25519_V1, P256_SHA256_V1};
use auths_signature_rsa_pkcs1_sha256::RSA_PKCS1_SHA256_V1;
use auths_sigstore_keyless::checkpoint::{CheckpointOrigin, NoteName};
use auths_sigstore_keyless::identity::{
    self as fulcio_identity, FulcioGenericPolicy, FulcioGithubPolicy, FulcioIssuerProfile,
};
use auths_sigstore_keyless::{IssuerPolicy, LeafValidity, LogKind, RekorLog};
use base64ct::{Base64, Base64UrlUnpadded, Encoding as _};
use serde::Deserialize;
use thiserror::Error;

/// Method configuration file name inside the trust directory.
pub const METHODS_FILE: &str = "methods.json";
/// Schema of a method configuration file.
pub const METHODS_SCHEMA: &str = "auths.git-methods/1";
/// Maximum method configuration file size in bytes.
pub const MAX_METHODS_FILE_BYTES: usize = 256 * 1024;
/// Maximum decoded RSA modulus: 4096 bits.
const MAX_RSA_MODULUS_BYTES: usize = 512;
/// Maximum decoded RSA public exponent.
const MAX_RSA_EXPONENT_BYTES: usize = 8;
/// DER `AlgorithmIdentifier` of Ed25519 (RFC 8410).
pub const ED25519_ALGORITHM_IDENTIFIER: [u8; 7] = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
/// DER prefix of an Ed25519 `SubjectPublicKeyInfo`; the 32-byte key follows.
pub const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
/// DER `AlgorithmIdentifier` of an EC public key on P-256 (RFC 5480).
pub const P256_ALGORITHM_IDENTIFIER: [u8; 21] = [
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x03, 0x01, 0x07,
];
/// DER prefix of a P-256 `SubjectPublicKeyInfo`; the 65-byte uncompressed
/// point follows.
pub const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// Why a method configuration was rejected.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MethodConfigError {
    /// The file exceeds [`MAX_METHODS_FILE_BYTES`].
    #[error("methods.json exceeds its size limit")]
    TooLarge,
    /// The file is not JSON of the expected shape.
    #[error("methods.json is malformed: {0}")]
    Syntax(String),
    /// A field has an invalid or unsupported value.
    #[error("methods.json {field}: {reason}")]
    Invalid {
        /// The offending field.
        field: &'static str,
        /// Why it was rejected.
        reason: &'static str,
    },
}

fn invalid(field: &'static str, reason: &'static str) -> MethodConfigError {
    MethodConfigError::Invalid { field, reason }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MethodsFile {
    schema: String,
    oidc_workload: Option<OidcFile>,
    sigstore_keyless: Option<SigstoreFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OidcFile {
    issuers: Vec<OidcIssuerFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OidcIssuerFile {
    issuer: String,
    max_token_lifetime_seconds: u64,
    keys: Vec<JwkFile>,
    profile: OidcProfileFile,
}

/// A public JWK, as an issuer's JWKS publishes it, reduced to the members
/// needed to pin it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JwkFile {
    kid: String,
    kty: String,
    alg: String,
    #[serde(rename = "use")]
    key_use: Option<String>,
    n: Option<String>,
    e: Option<String>,
    crv: Option<String>,
    x: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum OidcProfileFile {
    Generic(Vec<String>),
    GithubActions(Vec<GithubPolicyFile>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GithubPolicyFile {
    repository_id: String,
    owner_id: String,
    #[serde(rename = "ref")]
    git_ref: Option<String>,
    environment: Option<String>,
    workflow: Option<WorkflowPinFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowPinFile {
    path: String,
    #[serde(rename = "ref")]
    git_ref: Option<String>,
    commit: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SigstoreFile {
    fulcio_roots: Vec<String>,
    rekor_logs: Vec<RekorLogFile>,
    issuers: Vec<SigstoreIssuerFile>,
    max_leaf_validity_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RekorLogFile {
    origin: String,
    key_name: String,
    ed25519_spki: Option<String>,
    p256_spki: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SigstoreIssuerFile {
    issuer: String,
    profile: SigstoreProfileFile,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum SigstoreProfileFile {
    Generic(Vec<String>),
    GithubActions(Vec<GithubPolicyFile>),
}

/// Validated Sigstore keyless configuration.
#[derive(Clone, Debug)]
pub struct SigstoreConfiguration {
    /// Pinned Fulcio roots.
    pub anchors: TrustAnchorSet,
    /// Accepted leaf key algorithms.
    pub key_bindings: AlgorithmBindingSet,
    /// Pinned Rekor logs.
    pub logs: Vec<RekorLog>,
    /// Accepted workload issuers and their policies.
    pub issuers: Vec<IssuerPolicy>,
    /// Maximum Fulcio leaf validity.
    pub leaf_validity: LeafValidity,
}

/// Validated workload method configuration.
#[derive(Clone, Debug, Default)]
pub struct MethodConfiguration {
    /// OIDC workload issuers, when that method is enabled.
    pub oidc_issuers: Option<Vec<Issuer>>,
    /// Sigstore keyless configuration, when that method is enabled.
    pub sigstore: Option<SigstoreConfiguration>,
    /// Whether any pinned key needs the RSA PKCS#1 SHA-256 suite.
    pub uses_rsa: bool,
}

impl MethodConfiguration {
    /// Parses and validates `methods.json`. `suites` must contain every
    /// suite the file may name (Ed25519, RSA PKCS#1 SHA-256, and P-256);
    /// they are used only to validate key material.
    ///
    /// # Errors
    ///
    /// Returns [`MethodConfigError`] for an oversized file, malformed JSON,
    /// unknown or duplicated members, or any invalid or unsupported value.
    pub fn parse(bytes: &[u8], suites: &[&dyn SignatureSuite]) -> Result<Self, MethodConfigError> {
        if bytes.len() > MAX_METHODS_FILE_BYTES {
            return Err(MethodConfigError::TooLarge);
        }
        let file: MethodsFile = serde_json::from_slice(bytes)
            .map_err(|error| MethodConfigError::Syntax(error.to_string()))?;
        if file.schema != METHODS_SCHEMA {
            return Err(invalid("schema", "must be auths.git-methods/1"));
        }
        let mut uses_rsa = false;
        let oidc_issuers = file
            .oidc_workload
            .map(|oidc| {
                if oidc.issuers.is_empty() {
                    return Err(invalid("oidc_workload.issuers", "must not be empty"));
                }
                oidc.issuers
                    .into_iter()
                    .map(|issuer| oidc_issuer(issuer, suites, &mut uses_rsa))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        let sigstore = file
            .sigstore_keyless
            .map(|sigstore| sigstore_configuration(sigstore, suites))
            .transpose()?;
        Ok(Self {
            oidc_issuers,
            sigstore,
            uses_rsa,
        })
    }
}

fn oidc_issuer(
    file: OidcIssuerFile,
    suites: &[&dyn SignatureSuite],
    uses_rsa: &mut bool,
) -> Result<Issuer, MethodConfigError> {
    let url = oidc_identity::IssuerUrl::parse(&file.issuer)
        .map_err(|_| invalid("oidc_workload.issuers.issuer", "not a canonical https URL"))?;
    let lifetime = TokenLifetime::new(file.max_token_lifetime_seconds).map_err(|_| {
        invalid(
            "oidc_workload.issuers.max_token_lifetime_seconds",
            "must be between 1 and 86400",
        )
    })?;
    if file.keys.is_empty() {
        return Err(invalid("oidc_workload.issuers.keys", "must not be empty"));
    }
    let keys = file
        .keys
        .into_iter()
        .map(|key| {
            let (pinned, rsa) = pinned_key(&key, suites)?;
            *uses_rsa |= rsa;
            Ok(pinned)
        })
        .collect::<Result<Vec<_>, MethodConfigError>>()?;
    let profile = match file.profile {
        OidcProfileFile::Generic(subjects) => IssuerProfile::Generic {
            policies: oidc_identity::generic_policy_set(
                subjects
                    .iter()
                    .map(|subject| {
                        Ok(GenericPolicy {
                            subject: oidc_identity::Subject::parse(subject).map_err(|_| {
                                invalid("oidc_workload.issuers.profile.generic", "invalid subject")
                            })?,
                        })
                    })
                    .collect::<Result<Vec<_>, MethodConfigError>>()?,
            )
            .map_err(|_| policy_set_error("oidc_workload.issuers.profile.generic"))?,
        },
        OidcProfileFile::GithubActions(policies) => IssuerProfile::GithubActions {
            policies: oidc_identity::github_policy_set(
                policies
                    .into_iter()
                    .map(oidc_github_policy)
                    .collect::<Result<Vec<_>, _>>()?,
            )
            .map_err(|_| policy_set_error("oidc_workload.issuers.profile.github_actions"))?,
        },
    };
    Issuer::new(url, keys, profile, lifetime).map_err(|_| {
        invalid(
            "oidc_workload.issuers.keys",
            "duplicate kid or too many keys",
        )
    })
}

const fn policy_set_error(field: &'static str) -> MethodConfigError {
    MethodConfigError::Invalid {
        field,
        reason: "must be non-empty, without duplicates, and at most 64 entries",
    }
}

fn oidc_github_policy(file: GithubPolicyFile) -> Result<GithubPolicy, MethodConfigError> {
    const FIELD: &str = "oidc_workload.issuers.profile.github_actions";
    let workflow = match file.workflow {
        None => None,
        Some(pin) => {
            let path = oidc_identity::WorkflowPath::parse(&pin.path)
                .map_err(|_| invalid(FIELD, "workflow.path must be a .github/workflows file"))?;
            Some(match (pin.git_ref, pin.commit) {
                (None, None) => oidc_identity::WorkflowPin::AnyRef { path },
                (Some(git_ref), Some(commit)) => oidc_identity::WorkflowPin::Exact {
                    path,
                    git_ref: oidc_identity::GitRef::parse(&git_ref)
                        .map_err(|_| invalid(FIELD, "workflow.ref must be a full Git ref"))?,
                    commit: oidc_identity::CommitSha::parse(&commit)
                        .map_err(|_| invalid(FIELD, "workflow.commit must be a commit id"))?,
                },
                _ => {
                    return Err(invalid(
                        FIELD,
                        "workflow needs both ref and commit, or neither",
                    ));
                }
            })
        }
    };
    Ok(GithubPolicy {
        repository_id: oidc_identity::RepositoryId::parse(&file.repository_id)
            .map_err(|_| invalid(FIELD, "repository_id must be a positive decimal id"))?,
        owner_id: oidc_identity::RepositoryOwnerId::parse(&file.owner_id)
            .map_err(|_| invalid(FIELD, "owner_id must be a positive decimal id"))?,
        workflow,
        git_ref: file
            .git_ref
            .map(|value| oidc_identity::GitRef::parse(&value))
            .transpose()
            .map_err(|_| invalid(FIELD, "ref must be a full Git ref"))?,
        environment: file
            .environment
            .map(|value| oidc_identity::Environment::parse(&value))
            .transpose()
            .map_err(|_| invalid(FIELD, "environment is invalid"))?,
    })
}

fn fulcio_github_policy(file: GithubPolicyFile) -> Result<FulcioGithubPolicy, MethodConfigError> {
    const FIELD: &str = "sigstore_keyless.issuers.profile.github_actions";
    let workflow = match file.workflow {
        None => None,
        Some(pin) => {
            let path = fulcio_identity::WorkflowPath::parse(&pin.path)
                .map_err(|_| invalid(FIELD, "workflow.path must be a .github/workflows file"))?;
            Some(match (pin.git_ref, pin.commit) {
                (None, None) => fulcio_identity::WorkflowPin::AnyRef { path },
                (Some(git_ref), Some(commit)) => fulcio_identity::WorkflowPin::Exact {
                    path,
                    git_ref: fulcio_identity::GitRef::parse(&git_ref)
                        .map_err(|_| invalid(FIELD, "workflow.ref must be a full Git ref"))?,
                    commit: fulcio_identity::CommitSha::parse(&commit)
                        .map_err(|_| invalid(FIELD, "workflow.commit must be a commit id"))?,
                },
                _ => {
                    return Err(invalid(
                        FIELD,
                        "workflow needs both ref and commit, or neither",
                    ));
                }
            })
        }
    };
    Ok(FulcioGithubPolicy {
        repository_id: fulcio_identity::RepositoryId::parse(&file.repository_id)
            .map_err(|_| invalid(FIELD, "invalid repository_id"))?,
        owner_id: fulcio_identity::RepositoryOwnerId::parse(&file.owner_id)
            .map_err(|_| invalid(FIELD, "invalid owner_id"))?,
        workflow,
        git_ref: file
            .git_ref
            .map(|value| fulcio_identity::GitRef::parse(&value))
            .transpose()
            .map_err(|_| invalid(FIELD, "ref must be a full Git ref"))?,
        environment: file
            .environment
            .map(|value| fulcio_identity::Environment::parse(&value))
            .transpose()
            .map_err(|_| invalid(FIELD, "environment is invalid"))?,
    })
}

/// Converts one JWK into a pinned issuer key. Returns whether it uses RSA.
fn pinned_key(
    jwk: &JwkFile,
    suites: &[&dyn SignatureSuite],
) -> Result<(PinnedIssuerKey, bool), MethodConfigError> {
    const FIELD: &str = "oidc_workload.issuers.keys";
    if jwk.key_use.as_deref().is_some_and(|value| value != "sig") {
        return Err(invalid(FIELD, "use must be \"sig\" when present"));
    }
    let kid = KeyId::parse(&jwk.kid).map_err(|_| invalid(FIELD, "invalid kid"))?;
    let (suite, material, rsa) = match (jwk.alg.as_str(), jwk.kty.as_str()) {
        ("RS256", "RSA") => {
            if jwk.crv.is_some() || jwk.x.is_some() {
                return Err(invalid(FIELD, "an RSA key must not carry crv or x"));
            }
            let (Some(n), Some(e)) = (jwk.n.as_deref(), jwk.e.as_deref()) else {
                return Err(invalid(FIELD, "an RSA key needs n and e"));
            };
            (RSA_PKCS1_SHA256_V1, rsa_public_key_der(n, e)?, true)
        }
        ("EdDSA", "OKP") => {
            if jwk.n.is_some() || jwk.e.is_some() {
                return Err(invalid(FIELD, "an OKP key must not carry n or e"));
            }
            if jwk.crv.as_deref() != Some("Ed25519") {
                return Err(invalid(FIELD, "only the Ed25519 curve is supported"));
            }
            let x = jwk
                .x
                .as_deref()
                .ok_or_else(|| invalid(FIELD, "an Ed25519 key needs x"))?;
            let key = Base64UrlUnpadded::decode_vec(x)
                .map_err(|_| invalid(FIELD, "x is not unpadded base64url"))?;
            (ED25519_V1, key, false)
        }
        _ => {
            return Err(invalid(
                FIELD,
                "only RS256 (kty RSA) and EdDSA (kty OKP, Ed25519) keys are supported",
            ));
        }
    };
    let binding = AlgorithmBinding::Jws {
        algorithm: JwsAlgorithmName::parse(&jwk.alg).map_err(|_| invalid(FIELD, "invalid alg"))?,
        suite: SignatureSuiteId::parse(suite).map_err(|_| invalid(FIELD, "invalid suite"))?,
    };
    let key = PinnedIssuerKey::new(kid, binding, material, suites)
        .map_err(|_| invalid(FIELD, "key material is not valid for its algorithm"))?;
    Ok((key, rsa))
}

/// Encodes a JWK RSA public key (base64url `n` and `e`) as the DER
/// PKCS#1 `RSAPublicKey` the RSA suite verifies with.
///
/// This is encoding, not cryptography: the suite validates the result.
///
/// # Errors
///
/// Returns [`MethodConfigError::Invalid`] for a value that is not unpadded
/// base64url, is empty or oversized, or has a leading zero byte.
pub fn rsa_public_key_der(n: &str, e: &str) -> Result<Vec<u8>, MethodConfigError> {
    const FIELD: &str = "oidc_workload.issuers.keys";
    // Base64url expands 3 bytes to 4 characters; reject before decoding.
    if n.len() > MAX_RSA_MODULUS_BYTES.div_ceil(3) * 4 || e.len() > 16 {
        return Err(invalid(FIELD, "RSA key is too large"));
    }
    let modulus = Base64UrlUnpadded::decode_vec(n)
        .map_err(|_| invalid(FIELD, "n is not unpadded base64url"))?;
    let exponent = Base64UrlUnpadded::decode_vec(e)
        .map_err(|_| invalid(FIELD, "e is not unpadded base64url"))?;
    for (value, maximum) in [
        (&modulus, MAX_RSA_MODULUS_BYTES),
        (&exponent, MAX_RSA_EXPONENT_BYTES),
    ] {
        if value.is_empty() || value.len() > maximum || value[0] == 0 {
            return Err(invalid(FIELD, "RSA n and e must be minimal and bounded"));
        }
    }
    let mut body = der_unsigned_integer(&modulus);
    body.extend(der_unsigned_integer(&exponent));
    Ok(der_element(0x30, &body))
}

fn der_unsigned_integer(magnitude: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(magnitude.len() + 1);
    if magnitude.first().is_some_and(|byte| byte & 0x80 != 0) {
        content.push(0);
    }
    content.extend_from_slice(magnitude);
    der_element(0x02, &content)
}

fn der_element(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    let length = content.len();
    if length < 0x80 {
        output.extend(u8::try_from(length));
    } else {
        let bytes = length.to_be_bytes();
        let significant: Vec<u8> = bytes
            .iter()
            .copied()
            .skip_while(|byte| *byte == 0)
            .collect();
        output.extend(u8::try_from(significant.len()).map(|count| 0x80 | count));
        output.extend(significant);
    }
    output.extend_from_slice(content);
    output
}

fn sigstore_configuration(
    file: SigstoreFile,
    suites: &[&dyn SignatureSuite],
) -> Result<SigstoreConfiguration, MethodConfigError> {
    let anchors = file
        .fulcio_roots
        .iter()
        .map(|root| {
            let der = Base64::decode_vec(root)
                .map_err(|_| invalid("sigstore_keyless.fulcio_roots", "not padded base64"))?;
            CertificateDer::new(der)
                .map_err(|_| invalid("sigstore_keyless.fulcio_roots", "not one DER certificate"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let anchors = BoundedSet::new(anchors).map_err(|_| {
        invalid(
            "sigstore_keyless.fulcio_roots",
            "must be non-empty, without duplicates, and at most 16 entries",
        )
    })?;
    if file.rekor_logs.is_empty() {
        return Err(invalid("sigstore_keyless.rekor_logs", "must not be empty"));
    }
    let logs = file
        .rekor_logs
        .into_iter()
        .map(|log| rekor_log(&log, suites))
        .collect::<Result<Vec<_>, _>>()?;
    if file.issuers.is_empty() {
        return Err(invalid("sigstore_keyless.issuers", "must not be empty"));
    }
    let issuers = file
        .issuers
        .into_iter()
        .map(sigstore_issuer)
        .collect::<Result<Vec<_>, _>>()?;
    let leaf_validity = LeafValidity::new(file.max_leaf_validity_seconds).map_err(|_| {
        invalid(
            "sigstore_keyless.max_leaf_validity_seconds",
            "must be between 1 and 3600",
        )
    })?;
    Ok(SigstoreConfiguration {
        anchors,
        key_bindings: p256_leaf_bindings(suites)?,
        logs,
        issuers,
        leaf_validity,
    })
}

/// The Sigstore keyless signer holds an ephemeral P-256 key, so a P-256
/// Fulcio leaf is the only accepted leaf key algorithm.
fn p256_leaf_bindings(
    suites: &[&dyn SignatureSuite],
) -> Result<AlgorithmBindingSet, MethodConfigError> {
    AlgorithmBindingSet::new(vec![p256_spki_binding()?], suites)
        .map_err(|_| invalid("sigstore_keyless", "the P-256 suite is not available"))
}

fn spki_binding(
    algorithm: &[u8],
    suite: &str,
    key_form: KeyForm,
) -> Result<AlgorithmBinding, MethodConfigError> {
    Ok(AlgorithmBinding::Spki {
        algorithm: AlgorithmIdentifierDer::new(algorithm.to_vec())
            .map_err(|_| invalid("sigstore_keyless", "invalid compiled algorithm identifier"))?,
        suite: SignatureSuiteId::parse(suite)
            .map_err(|_| invalid("sigstore_keyless", "invalid compiled suite"))?,
        key_form,
    })
}

fn ed25519_spki_binding() -> Result<AlgorithmBinding, MethodConfigError> {
    spki_binding(
        &ED25519_ALGORITHM_IDENTIFIER,
        ED25519_V1,
        KeyForm::BitStringContents,
    )
}

fn p256_spki_binding() -> Result<AlgorithmBinding, MethodConfigError> {
    spki_binding(
        &P256_ALGORITHM_IDENTIFIER,
        P256_SHA256_V1,
        KeyForm::Sec1Compressed,
    )
}

fn rekor_log(
    file: &RekorLogFile,
    suites: &[&dyn SignatureSuite],
) -> Result<RekorLog, MethodConfigError> {
    const FIELD: &str = "sigstore_keyless.rekor_logs";
    let (encoded, binding, reason) = match (&file.ed25519_spki, &file.p256_spki) {
        (Some(key), None) => (
            key,
            ed25519_spki_binding()?,
            "ed25519_spki is not an Ed25519 SubjectPublicKeyInfo",
        ),
        (None, Some(key)) => (
            key,
            p256_spki_binding()?,
            "p256_spki is not a P-256 SubjectPublicKeyInfo",
        ),
        _ => {
            return Err(invalid(
                FIELD,
                "each log needs exactly one of ed25519_spki and p256_spki",
            ));
        }
    };
    let spki = Base64::decode_vec(encoded)
        .map_err(|_| invalid(FIELD, "the log key is not padded base64"))?;
    RekorLog::new(
        CheckpointOrigin::parse(&file.origin).map_err(|_| invalid(FIELD, "invalid origin"))?,
        NoteName::parse(&file.key_name).map_err(|_| invalid(FIELD, "invalid key_name"))?,
        spki,
        binding,
        LogKind::Rfc6962Sha256,
        suites,
    )
    .map_err(|_| invalid(FIELD, reason))
}

fn sigstore_issuer(file: SigstoreIssuerFile) -> Result<IssuerPolicy, MethodConfigError> {
    const FIELD: &str = "sigstore_keyless.issuers";
    let url = fulcio_identity::IssuerUrl::parse(&file.issuer)
        .map_err(|_| invalid(FIELD, "issuer is not an https URL"))?;
    let profile = match file.profile {
        SigstoreProfileFile::Generic(subjects) => FulcioIssuerProfile::Generic {
            policies: BoundedSet::new(
                subjects
                    .iter()
                    .map(|subject| {
                        Ok(FulcioGenericPolicy {
                            subject: fulcio_identity::Subject::parse(subject)
                                .map_err(|_| invalid(FIELD, "invalid subject"))?,
                        })
                    })
                    .collect::<Result<Vec<_>, MethodConfigError>>()?,
            )
            .map_err(|_| policy_set_error(FIELD))?,
        },
        SigstoreProfileFile::GithubActions(policies) => FulcioIssuerProfile::GithubActions {
            policies: BoundedSet::new(
                policies
                    .into_iter()
                    .map(fulcio_github_policy)
                    .collect::<Result<Vec<_>, MethodConfigError>>()?,
            )
            .map_err(|_| policy_set_error(FIELD))?,
        },
    };
    Ok(IssuerPolicy::new(url, profile))
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_signature::{Ed25519Suite, P256Sha256Suite};
    use auths_signature_rsa_pkcs1_sha256::RsaPkcs1Sha256Suite;

    fn parse(json: &serde_json::Value) -> Result<MethodConfiguration, MethodConfigError> {
        let ed25519 = Ed25519Suite::new().expect("suite");
        let rsa = RsaPkcs1Sha256Suite::new().expect("suite");
        let p256 = P256Sha256Suite::new().expect("suite");
        MethodConfiguration::parse(
            json.to_string().as_bytes(),
            &[&ed25519 as &dyn SignatureSuite, &rsa, &p256],
        )
    }

    /// Public-good Rekor's key, from `GET /api/v1/log/publicKey`.
    const REKOR_P256_SPKI: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==";

    #[test]
    fn each_rekor_log_pins_exactly_one_key_of_its_named_type() {
        let edwards = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        let mut ed25519 = ED25519_SPKI_PREFIX.to_vec();
        ed25519.extend_from_slice(edwards.as_bytes());
        let ed25519 = Base64::encode_string(&ed25519);
        let file = |log: serde_json::Value| {
            serde_json::json!({
                "schema": METHODS_SCHEMA,
                "sigstore_keyless": {
                    "fulcio_roots": [Base64::encode_string(&[0x30, 0x03, 0x02, 0x01, 0x01])],
                    "rekor_logs": [log],
                    "issuers": [{"issuer": "https://token.actions.githubusercontent.com",
                                 "profile": {"github_actions": [{"repository_id": "1", "owner_id": "2"}]}}],
                    "max_leaf_validity_seconds": 600,
                },
            })
        };
        let origin = "rekor.sigstore.dev - 1193050959916656506";
        let name = "rekor.sigstore.dev";
        let public_good = parse(&file(
            serde_json::json!({"origin": origin, "key_name": name, "p256_spki": REKOR_P256_SPKI}),
        ))
        .expect("public-good Rekor")
        .sigstore
        .expect("sigstore");
        assert_eq!(
            hex::encode(public_good.logs[0].id().bytes()),
            "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"
        );
        assert!(
            parse(&file(
                serde_json::json!({"origin": origin, "key_name": name, "ed25519_spki": ed25519})
            ))
            .is_ok()
        );
        for log in [
            serde_json::json!({"origin": origin, "key_name": name}),
            serde_json::json!({"origin": origin, "key_name": name, "p256_spki": REKOR_P256_SPKI, "ed25519_spki": ed25519}),
            serde_json::json!({"origin": origin, "key_name": name, "p256_spki": ed25519}),
            serde_json::json!({"origin": origin, "key_name": name, "ed25519_spki": REKOR_P256_SPKI}),
            serde_json::json!({"origin": origin, "key_name": name, "p256_spki": REKOR_P256_SPKI, "extra": 1}),
        ] {
            assert!(parse(&file(log.clone())).is_err(), "accepted {log}");
        }
    }

    fn modulus() -> Vec<u8> {
        let mut modulus = vec![0xc5_u8; 256];
        modulus[255] = 0x01;
        modulus
    }

    #[test]
    fn rsa_jwk_members_encode_as_minimal_pkcs1_der() {
        let n = Base64UrlUnpadded::encode_string(&modulus());
        let der = rsa_public_key_der(&n, "AQAB").expect("der");
        // SEQUENCE, long-form length 0x010a, INTEGER 257 bytes with a sign
        // byte, then INTEGER 65537.
        assert_eq!(&der[..4], &[0x30, 0x82, 0x01, 0x0a]);
        assert_eq!(&der[4..9], &[0x02, 0x82, 0x01, 0x01, 0x00]);
        assert_eq!(&der[9..265], modulus().as_slice());
        assert_eq!(&der[265..], &[0x02, 0x03, 0x01, 0x00, 0x01]);
        RsaPkcs1Sha256Suite::new()
            .expect("suite")
            .validate_key(&der)
            .expect("the RSA suite accepts the encoding");

        let short = der_unsigned_integer(&[0x7f]);
        assert_eq!(short, vec![0x02, 0x01, 0x7f]);
        for (n, e) in [
            ("", "AQAB"),
            (n.as_str(), ""),
            (n.as_str(), "AAEAAQ"),
            ("AP8", "AQAB"),
            (n.as_str(), "AQAB="),
            (&"A".repeat(4096), "AQAB"),
        ] {
            assert!(rsa_public_key_der(n, e).is_err(), "accepted n={n:.8} e={e}");
        }
    }

    #[test]
    fn method_files_are_strict_and_typed() {
        let key = Base64UrlUnpadded::encode_string(&[7_u8; 32]);
        let edwards = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        let valid_x = Base64UrlUnpadded::encode_string(edwards.as_bytes());
        let issuer = |keys: serde_json::Value, profile: serde_json::Value| {
            serde_json::json!({
                "schema": METHODS_SCHEMA,
                "oidc_workload": {"issuers": [{
                    "issuer": "https://issuer.example",
                    "max_token_lifetime_seconds": 600,
                    "keys": keys,
                    "profile": profile,
                }]},
            })
        };
        let ed_key = serde_json::json!([{"kid": "k1", "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "x": valid_x, "use": "sig"}]);
        let github = serde_json::json!({"github_actions": [{"repository_id": "1", "owner_id": "2", "ref": "refs/heads/main"}]});
        let parsed = parse(&issuer(ed_key.clone(), github.clone())).expect("valid");
        let pinned = serde_json::json!({"github_actions": [{
            "repository_id": "1", "owner_id": "2", "ref": "refs/tags/v1", "environment": "release",
            "workflow": {"path": ".github/workflows/release.yml"}
        }]});
        assert!(parse(&issuer(ed_key.clone(), pinned)).is_ok());
        assert!(!parsed.uses_rsa);
        assert_eq!(parsed.oidc_issuers.as_ref().map(Vec::len), Some(1));
        assert!(parsed.sigstore.is_none());

        let rsa_key = serde_json::json!([{"kid": "r1", "kty": "RSA", "alg": "RS256", "n": Base64UrlUnpadded::encode_string(&modulus()), "e": "AQAB"}]);
        assert!(
            parse(&issuer(rsa_key, github.clone()))
                .expect("rsa")
                .uses_rsa
        );

        let rejected = [
            serde_json::json!({"schema": "other"}),
            serde_json::json!({"schema": METHODS_SCHEMA, "unknown": 1}),
            issuer(
                ed_key.clone(),
                serde_json::json!({"github_actions": [{"repository_id": "1", "owner_id": "2", "workflow": {"path": ".github/workflows/release.yml", "ref": "refs/heads/main"}}]}),
            ),
            issuer(
                ed_key.clone(),
                serde_json::json!({"github_actions": [{"repository_id": "1", "owner_id": "2", "workflow": {"path": "release.yml"}}]}),
            ),
            issuer(
                ed_key.clone(),
                serde_json::json!({"github_actions": [{"repository_id": "01", "owner_id": "2"}]}),
            ),
            issuer(ed_key.clone(), serde_json::json!({"generic": []})),
            issuer(serde_json::json!([]), github.clone()),
            issuer(
                serde_json::json!([{"kid": "k1", "kty": "EC", "crv": "P-256", "alg": "ES256", "x": key}]),
                github.clone(),
            ),
            issuer(
                serde_json::json!([{"kid": "k1", "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "x": key, "x5c": []}]),
                github.clone(),
            ),
            issuer(
                serde_json::json!([{"kid": "k1", "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "x": valid_x, "use": "enc"}]),
                github.clone(),
            ),
        ];
        for json in rejected {
            assert!(parse(&json).is_err(), "accepted {json}");
        }
        let duplicate =
            format!("{{\"schema\":\"{METHODS_SCHEMA}\",\"schema\":\"{METHODS_SCHEMA}\"}}");
        let ed25519 = Ed25519Suite::new().expect("suite");
        assert!(matches!(
            MethodConfiguration::parse(duplicate.as_bytes(), &[&ed25519 as &dyn SignatureSuite]),
            Err(MethodConfigError::Syntax(_))
        ));
        assert_eq!(
            MethodConfiguration::parse(&vec![b' '; MAX_METHODS_FILE_BYTES + 1], &[]).err(),
            Some(MethodConfigError::TooLarge)
        );
    }
}
