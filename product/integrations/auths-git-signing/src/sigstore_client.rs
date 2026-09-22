//! Fulcio and Rekor over HTTPS, behind [`SigstoreClient`].
//!
//! [`HttpSigstoreClient::public_good`] talks to the public-good instance:
//! Fulcio's `POST /api/v2/signingCert` and Rekor v1's
//! `POST /api/v1/log/entries` with a `hashedrekord` v0.0.1 entry. Every
//! request has a timeout and every response a size bound. The OIDC token is
//! sent only to Fulcio, only in the request body, and never appears in an
//! error: errors carry an HTTP status at most, never a response body.
//!
//! Nothing here is trusted. The certificate chain and log entry become
//! evidence that the offline adapter verifies against pinned Fulcio roots
//! and Rekor keys; this client only fetches them.

use crate::workload::{
    CertificateRequest, HashedRekordRequest, RekorEntryFields, SigstoreClient, WorkloadError,
};
use base64ct::{Base64, Encoding as _};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read as _;
use std::time::Duration;
use zeroize::Zeroizing;

/// The public-good Fulcio instance.
pub const PUBLIC_GOOD_FULCIO: &str = "https://fulcio.sigstore.dev";
/// The public-good Rekor v1 instance.
pub const PUBLIC_GOOD_REKOR: &str = "https://rekor.sigstore.dev";
/// Maximum response accepted from Fulcio or Rekor.
pub const MAX_SIGSTORE_RESPONSE_BYTES: usize = 256 * 1024;
/// Maximum certificates accepted in one Fulcio chain.
const MAX_CHAIN_CERTIFICATES: usize = auths_sigstore_keyless::chain::MAX_CHAIN_LENGTH;
/// Timeout for one request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Attempts to fetch an inclusion proof Rekor did not return at once.
const PROOF_ATTEMPTS: u32 = 10;
/// Delay between inclusion-proof attempts.
const PROOF_RETRY_DELAY: Duration = Duration::from_secs(1);
/// Rekor's path for one entry, followed by its hexadecimal UUID.
const ENTRY_PATH: &str = "/api/v1/log/entries/";

fn failure(reason: &str) -> WorkloadError {
    WorkloadError::Sigstore(reason.to_owned())
}

/// A Fulcio and Rekor client over HTTPS.
pub struct HttpSigstoreClient {
    fulcio: String,
    rekor: String,
    http: reqwest::blocking::Client,
}

impl HttpSigstoreClient {
    /// A client for the public-good Fulcio and Rekor instances.
    ///
    /// # Errors
    ///
    /// Returns [`WorkloadError::Sigstore`] if the HTTP client cannot be
    /// built.
    pub fn public_good() -> Result<Self, WorkloadError> {
        Self::new(PUBLIC_GOOD_FULCIO, PUBLIC_GOOD_REKOR)
    }

    /// A client for the Fulcio and Rekor instances at these base URLs.
    ///
    /// # Errors
    ///
    /// Returns [`WorkloadError::Sigstore`] for a URL that is not `https`, or
    /// if the HTTP client cannot be built.
    pub fn new(fulcio: &str, rekor: &str) -> Result<Self, WorkloadError> {
        if !fulcio.starts_with("https://") || !rekor.starts_with("https://") {
            return Err(failure("Fulcio and Rekor URLs must be https"));
        }
        let http = reqwest::blocking::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| failure("could not build an HTTP client"))?;
        Ok(Self {
            fulcio: fulcio.trim_end_matches('/').to_owned(),
            rekor: rekor.trim_end_matches('/').to_owned(),
            http,
        })
    }

    fn post(&self, url: &str, body: Vec<u8>) -> Result<Response, WorkloadError> {
        let response = self
            .http
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json")
            .body(body)
            .send()
            .map_err(|_| failure("the request failed"))?;
        Response::read(response)
    }

    fn get(&self, url: &str) -> Result<Response, WorkloadError> {
        let response = self
            .http
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .map_err(|_| failure("the request failed"))?;
        Response::read(response)
    }

    /// Fetches one entry by UUID until Rekor returns it with an inclusion
    /// proof.
    fn entry_with_proof(&self, uuid: &str) -> Result<RekorEntryFields, WorkloadError> {
        let url = format!("{}{ENTRY_PATH}{uuid}", self.rekor);
        for attempt in 0..PROOF_ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(PROOF_RETRY_DELAY);
            }
            let response = self.get(&url)?;
            if !response.status.is_success() {
                return Err(WorkloadError::Sigstore(format!(
                    "Rekor could not return entry {uuid} (HTTP {})",
                    response.status.as_u16()
                )));
            }
            if let Some(fields) = parse_log_entry(&response.body)?.1 {
                return Ok(fields);
            }
        }
        Err(failure("Rekor did not return an inclusion proof in time"))
    }
}

/// A status, an optional `Location`, and a bounded body.
struct Response {
    status: reqwest::StatusCode,
    location: Option<String>,
    body: Vec<u8>,
}

impl Response {
    fn read(response: reqwest::blocking::Response) -> Result<Self, WorkloadError> {
        let status = response.status();
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let mut body = Vec::new();
        response
            .take(
                u64::try_from(MAX_SIGSTORE_RESPONSE_BYTES)
                    .map_or(u64::MAX, |limit| limit.saturating_add(1)),
            )
            .read_to_end(&mut body)
            .map_err(|_| failure("could not read the response"))?;
        if body.len() > MAX_SIGSTORE_RESPONSE_BYTES {
            return Err(failure("the response exceeds its limit"));
        }
        Ok(Self {
            status,
            location,
            body,
        })
    }
}

impl SigstoreClient for HttpSigstoreClient {
    fn issue_certificate(
        &self,
        request: &CertificateRequest<'_>,
    ) -> Result<Vec<Vec<u8>>, WorkloadError> {
        // The body holds the token. It moves into the request once, and the
        // emptied buffer is zeroized on drop.
        let mut body = signing_certificate_request(request)?;
        let response = self.post(
            &format!("{}/api/v2/signingCert", self.fulcio),
            std::mem::take(&mut *body),
        )?;
        if !response.status.is_success() {
            return Err(WorkloadError::Sigstore(format!(
                "Fulcio refused the certificate request (HTTP {})",
                response.status.as_u16()
            )));
        }
        parse_certificate_chain(&response.body)
    }

    fn submit_hashed_rekord(
        &self,
        request: &HashedRekordRequest<'_>,
    ) -> Result<RekorEntryFields, WorkloadError> {
        let response = self.post(
            &format!("{}/api/v1/log/entries", self.rekor),
            hashed_rekord_request(request)?,
        )?;
        let uuid = match response.status.as_u16() {
            201 => {
                let (uuid, fields) = parse_log_entry(&response.body)?;
                if let Some(fields) = fields {
                    return Ok(fields);
                }
                uuid
            }
            // The entry exists already; Rekor names it in `Location`.
            409 => conflict_uuid(response.location.as_deref(), &self.rekor)?,
            status => {
                return Err(WorkloadError::Sigstore(format!(
                    "Rekor refused the entry (HTTP {status})"
                )));
            }
        };
        self.entry_with_proof(&uuid)
    }
}

#[derive(Serialize)]
struct SigningCertificateRequest<'a> {
    credentials: Credentials<'a>,
    #[serde(rename = "publicKeyRequest")]
    public_key_request: PublicKeyRequest<'a>,
}

#[derive(Serialize)]
struct Credentials<'a> {
    #[serde(rename = "oidcIdentityToken")]
    oidc_identity_token: &'a str,
}

#[derive(Serialize)]
struct PublicKeyRequest<'a> {
    #[serde(rename = "publicKey")]
    public_key: PublicKey<'a>,
    #[serde(rename = "proofOfPossession")]
    proof_of_possession: String,
}

#[derive(Serialize)]
struct PublicKey<'a> {
    algorithm: &'a str,
    content: String,
}

/// The Fulcio v2 `signingCert` request body. It holds the token, so it is
/// zeroized when dropped.
fn signing_certificate_request(
    request: &CertificateRequest<'_>,
) -> Result<Zeroizing<Vec<u8>>, WorkloadError> {
    let body = SigningCertificateRequest {
        credentials: Credentials {
            oidc_identity_token: request.token,
        },
        public_key_request: PublicKeyRequest {
            public_key: PublicKey {
                algorithm: "ECDSA",
                content: pem("PUBLIC KEY", request.public_key_spki),
            },
            proof_of_possession: Base64::encode_string(request.proof_of_possession),
        },
    };
    serde_json::to_vec(&body)
        .map(Zeroizing::new)
        .map_err(|_| failure("could not encode the certificate request"))
}

#[derive(Deserialize)]
struct SigningCertificateResponse {
    #[serde(rename = "signedCertificateEmbeddedSct")]
    embedded: Option<SignedCertificate>,
    #[serde(rename = "signedCertificateDetachedSct")]
    detached: Option<SignedCertificate>,
}

#[derive(Deserialize)]
struct SignedCertificate {
    chain: CertificateList,
}

#[derive(Deserialize)]
struct CertificateList {
    certificates: Vec<String>,
}

/// Reads Fulcio's chain, leaf first, as DER certificates.
fn parse_certificate_chain(body: &[u8]) -> Result<Vec<Vec<u8>>, WorkloadError> {
    let response: SigningCertificateResponse =
        serde_json::from_slice(body).map_err(|_| failure("Fulcio's response is malformed"))?;
    let chain = match (response.embedded, response.detached) {
        (Some(chain), None) | (None, Some(chain)) => chain.chain.certificates,
        _ => return Err(failure("Fulcio's response carries no single chain")),
    };
    if chain.is_empty() || chain.len() > MAX_CHAIN_CERTIFICATES {
        return Err(failure("Fulcio's chain length is out of bounds"));
    }
    chain
        .iter()
        .map(|certificate| pem_decode(certificate, "CERTIFICATE"))
        .collect()
}

#[derive(Serialize)]
struct HashedRekord<'a> {
    #[serde(rename = "apiVersion")]
    api_version: &'a str,
    kind: &'a str,
    spec: HashedRekordSpec,
}

#[derive(Serialize)]
struct HashedRekordSpec {
    data: HashedRekordData,
    signature: HashedRekordSignature,
}

#[derive(Serialize)]
struct HashedRekordData {
    hash: HashedRekordHash,
}

#[derive(Serialize)]
struct HashedRekordHash {
    algorithm: &'static str,
    value: String,
}

#[derive(Serialize)]
struct HashedRekordSignature {
    content: String,
    #[serde(rename = "publicKey")]
    public_key: HashedRekordKey,
}

#[derive(Serialize)]
struct HashedRekordKey {
    content: String,
}

/// The Rekor `hashedrekord` v0.0.1 proposed entry.
fn hashed_rekord_request(request: &HashedRekordRequest<'_>) -> Result<Vec<u8>, WorkloadError> {
    serde_json::to_vec(&HashedRekord {
        api_version: "0.0.1",
        kind: "hashedrekord",
        spec: HashedRekordSpec {
            data: HashedRekordData {
                hash: HashedRekordHash {
                    algorithm: "sha256",
                    value: hex::encode(request.artifact_sha256),
                },
            },
            signature: HashedRekordSignature {
                content: Base64::encode_string(request.signature),
                public_key: HashedRekordKey {
                    content: Base64::encode_string(
                        pem("CERTIFICATE", request.certificate_der).as_bytes(),
                    ),
                },
            },
        },
    })
    .map_err(|_| failure("could not encode the Rekor entry"))
}

#[derive(Deserialize)]
struct LogEntry {
    body: String,
    #[serde(rename = "integratedTime")]
    integrated_time: u64,
    #[serde(rename = "logID")]
    log_id: String,
    #[serde(rename = "logIndex")]
    log_index: u64,
    verification: Option<Verification>,
}

#[derive(Deserialize)]
struct Verification {
    #[serde(rename = "inclusionProof")]
    inclusion_proof: Option<InclusionProof>,
    #[serde(rename = "signedEntryTimestamp")]
    signed_entry_timestamp: Option<String>,
}

#[derive(Deserialize)]
struct InclusionProof {
    checkpoint: String,
    hashes: Vec<String>,
    #[serde(rename = "logIndex")]
    log_index: u64,
    #[serde(rename = "treeSize")]
    tree_size: u64,
}

/// Reads a Rekor v1 response holding exactly one entry. Returns its UUID,
/// and its fields once it carries both an inclusion proof and a Signed
/// Entry Timestamp.
pub(crate) fn parse_log_entry(
    body: &[u8],
) -> Result<(String, Option<RekorEntryFields>), WorkloadError> {
    let entries: BTreeMap<String, LogEntry> =
        serde_json::from_slice(body).map_err(|_| failure("Rekor's response is malformed"))?;
    let mut entries = entries.into_iter();
    let (Some((uuid, entry)), None) = (entries.next(), entries.next()) else {
        return Err(failure("Rekor's response does not hold exactly one entry"));
    };
    if !is_entry_uuid(&uuid) {
        return Err(failure("Rekor returned an invalid entry UUID"));
    }
    let Some(Verification {
        inclusion_proof: Some(proof),
        signed_entry_timestamp: Some(set),
    }) = entry.verification
    else {
        return Ok((uuid, None));
    };
    let malformed = |_| failure("Rekor's entry is malformed");
    let hashes = proof
        .hashes
        .iter()
        .map(|hash| {
            hex::decode(hash)
                .map_err(|_| failure("Rekor's entry is malformed"))?
                .try_into()
                .map_err(|_| failure("Rekor's entry is malformed"))
        })
        .collect::<Result<Vec<[u8; 32]>, _>>()?;
    let fields = RekorEntryFields {
        body: Base64::decode_vec(&entry.body).map_err(malformed)?,
        checkpoint: proof.checkpoint,
        hashes,
        integrated_time: entry.integrated_time,
        log_id: hex::decode(&entry.log_id)
            .map_err(|_| failure("Rekor's entry is malformed"))?
            .try_into()
            .map_err(|_| failure("Rekor's entry is malformed"))?,
        log_index: entry.log_index,
        proof_index: proof.log_index,
        signed_entry_timestamp: Base64::decode_vec(&set).map_err(malformed)?,
        tree_size: proof.tree_size,
    };
    Ok((uuid, Some(fields)))
}

/// The UUID a 409 response names in `Location`, relative to Rekor or
/// absolute under the same base URL.
fn conflict_uuid(location: Option<&str>, rekor: &str) -> Result<String, WorkloadError> {
    let location =
        location.ok_or_else(|| failure("Rekor reported a conflict without a location"))?;
    let path = location.strip_prefix(rekor).unwrap_or(location);
    path.strip_prefix(ENTRY_PATH)
        .filter(|uuid| is_entry_uuid(uuid))
        .map(str::to_owned)
        .ok_or_else(|| failure("Rekor reported a conflict at an unexpected location"))
}

/// A Rekor entry UUID: lowercase hexadecimal, a leaf hash optionally
/// prefixed by a tree id.
fn is_entry_uuid(value: &str) -> bool {
    (64..=96).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// PEM with 64-character lines, as Fulcio and Rekor emit it.
fn pem(label: &str, der: &[u8]) -> String {
    let encoded = Base64::encode_string(der);
    let mut text = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        text.push_str(&String::from_utf8_lossy(line));
        text.push('\n');
    }
    text.push_str("-----END ");
    text.push_str(label);
    text.push_str("-----\n");
    text
}

/// Decodes exactly one PEM block with `label`.
fn pem_decode(text: &str, label: &str) -> Result<Vec<u8>, WorkloadError> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let inner = text
        .trim()
        .strip_prefix(&begin)
        .and_then(|rest| rest.strip_suffix(&end))
        .filter(|inner| !inner.contains("-----"))
        .ok_or_else(|| failure("Fulcio returned a malformed certificate"))?;
    let compact: String = inner.split_whitespace().collect();
    Base64::decode_vec(&compact).map_err(|_| failure("Fulcio returned a malformed certificate"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_model::Digest;
    use auths_sigstore_keyless::entry::{EntryFields, RekorEntry, encode_entry};

    /// A real public-good Rekor v1 response, recorded for the adapter's
    /// tests; see that package's `testdata/public-good`.
    const RECORDED: &str = include_str!(
        "../../../../core/adapters/auths-sigstore-keyless/testdata/public-good/rekor-entry-2910000001.json"
    );

    #[test]
    fn a_recorded_rekor_response_maps_to_evidence_the_adapter_parses() {
        let (uuid, fields) = parse_log_entry(RECORDED.as_bytes()).expect("entry");
        let fields = fields.expect("the recorded entry carries its proof");
        assert!(is_entry_uuid(&uuid));
        assert_eq!(fields.log_index, 2_910_000_001);
        assert_eq!(fields.proof_index, 2_788_095_739);
        let hashes: Vec<Digest> = fields.hashes.iter().copied().map(Digest::new).collect();
        let encoded = encode_entry(&EntryFields {
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
        .expect("encoded");
        let entry = RekorEntry::parse(&encoded).expect("the adapter parses it");
        assert_eq!(entry.log_index, 2_910_000_001);
        assert_eq!(entry.proof.index, 2_788_095_739);
    }

    #[test]
    fn a_response_without_a_proof_yields_only_its_uuid() {
        let uuid = "ab".repeat(40);
        let body = format!(
            r#"{{"{uuid}":{{"body":"e30=","integratedTime":1,"logID":"00","logIndex":2,"verification":{{"signedEntryTimestamp":"AA=="}}}}}}"#
        );
        let (parsed, fields) = parse_log_entry(body.as_bytes()).expect("entry");
        assert_eq!(parsed, uuid);
        assert!(fields.is_none());
        for rejected in [
            "{}".to_owned(),
            format!(r#"{{"{uuid}":{{}}}}"#),
            r#"{"../x":{"body":"","integratedTime":1,"logID":"","logIndex":2}}"#.to_owned(),
        ] {
            assert!(parse_log_entry(rejected.as_bytes()).is_err(), "{rejected}");
        }
    }

    #[test]
    fn conflicts_resolve_only_to_entry_paths_under_rekor() {
        let uuid = "0f".repeat(40);
        let rekor = PUBLIC_GOOD_REKOR;
        assert_eq!(
            conflict_uuid(Some(&format!("{ENTRY_PATH}{uuid}")), rekor).expect("relative"),
            uuid
        );
        assert_eq!(
            conflict_uuid(Some(&format!("{rekor}{ENTRY_PATH}{uuid}")), rekor).expect("absolute"),
            uuid
        );
        for location in [
            None,
            Some(format!("https://evil.example{ENTRY_PATH}{uuid}")),
            Some(format!("{ENTRY_PATH}{uuid}/../x")),
            Some(format!("{ENTRY_PATH}{}", uuid.to_uppercase())),
        ] {
            assert!(conflict_uuid(location.as_deref(), rekor).is_err());
        }
    }

    #[test]
    fn fulcio_chains_decode_leaf_first_and_requests_carry_pem_and_der() {
        let certificate = rcgen::CertificateParams::new(Vec::<String>::new())
            .expect("params")
            .self_signed(&rcgen::KeyPair::generate().expect("key"))
            .expect("certificate");
        let text = pem("CERTIFICATE", certificate.der());
        let response = serde_json::json!({"signedCertificateEmbeddedSct": {"chain": {"certificates": [text, text]}}});
        let chain =
            parse_certificate_chain(response.to_string().as_bytes()).expect("embedded chain");
        assert_eq!(chain, vec![certificate.der().to_vec(); 2]);
        let both = serde_json::json!({
            "signedCertificateEmbeddedSct": {"chain": {"certificates": [text]}},
            "signedCertificateDetachedSct": {"chain": {"certificates": [text]}},
        });
        assert!(parse_certificate_chain(both.to_string().as_bytes()).is_err());
        let empty =
            serde_json::json!({"signedCertificateDetachedSct": {"chain": {"certificates": []}}});
        assert!(parse_certificate_chain(empty.to_string().as_bytes()).is_err());

        let request = hashed_rekord_request(&HashedRekordRequest {
            artifact_sha256: [0xab; 32],
            signature: &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
            certificate_der: certificate.der(),
        })
        .expect("request");
        let request: serde_json::Value = serde_json::from_slice(&request).expect("json");
        assert_eq!(request["kind"], "hashedrekord");
        assert_eq!(request["spec"]["data"]["hash"]["value"], "ab".repeat(32));
        assert_eq!(request["spec"]["signature"]["content"], "MAYCAQECAQE=");
        let key = Base64::decode_vec(
            request["spec"]["signature"]["publicKey"]["content"]
                .as_str()
                .expect("content"),
        )
        .expect("base64");
        assert_eq!(
            pem_decode(std::str::from_utf8(&key).expect("pem"), "CERTIFICATE").expect("der"),
            certificate.der().to_vec()
        );
    }
}
