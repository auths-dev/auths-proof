//! Pure certificate-path verification backed by `rustls-webpki`.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use auths_model::{AdapterConfigurationId, Timestamp};
use auths_ports::{
    AlgorithmIdentifierDer, CertificatePathVerifier, PathError, PathInput, PathVerifierId,
    VerifiedLeaf, configuration_id,
};
use core::time::Duration;
use rustls_pki_types::{CertificateDer as WebPkiCertificateDer, UnixTime};
use x509_parser::parse_x509_certificate;

const IMPLEMENTATION_ID: &str = "webpki-v1";
const WEBPKI_VERSION: &[u8] = b"rustls-webpki-0.103.13";
const BACKEND: &[u8] = b"ring";
const ENABLED_ALGORITHMS: &[u8] = b"rustls-webpki-all-verification-algs";
const CLIENT_AUTH_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
const CODE_SIGNING_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];

/// Stateless `rustls-webpki` certificate-path verifier.
#[derive(Debug, Eq, PartialEq)]
pub struct WebPkiPathVerifier {
    id: PathVerifierId,
    configuration_id: AdapterConfigurationId,
}

impl WebPkiPathVerifier {
    /// Constructs the fixed `webpki-v1` implementation.
    #[must_use]
    pub fn new() -> Self {
        let id = PathVerifierId::parse(IMPLEMENTATION_ID)
            .expect("the built-in path-verifier identifier is valid");
        let configuration_id = configuration_id(
            b"auths-path-webpki-v1",
            [
                IMPLEMENTATION_ID.as_bytes(),
                WEBPKI_VERSION,
                BACKEND,
                ENABLED_ALGORITHMS,
            ],
        );
        Self {
            id,
            configuration_id,
        }
    }
}

impl Default for WebPkiPathVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl CertificatePathVerifier for WebPkiPathVerifier {
    fn id(&self) -> &PathVerifierId {
        &self.id
    }

    fn configuration_id(&self) -> AdapterConfigurationId {
        self.configuration_id
    }

    fn maximum_work_units(&self, chain_length: usize) -> u64 {
        u64::try_from(chain_length)
            .unwrap_or(u64::MAX)
            .saturating_mul(100)
            .saturating_add(100)
    }

    fn verify(&self, input: PathInput<'_>) -> Result<VerifiedLeaf, PathError> {
        let leaf_der = WebPkiCertificateDer::from(input.leaf.as_bytes());
        let leaf = webpki::EndEntityCert::try_from(&leaf_der).map_err(map_webpki_error)?;
        let intermediates: Vec<_> = input
            .intermediates
            .iter()
            .map(|certificate| WebPkiCertificateDer::from(certificate.as_bytes()))
            .collect();
        let root_der: Vec<_> = input
            .anchors
            .as_slice()
            .iter()
            .map(|anchor| WebPkiCertificateDer::from(anchor.as_bytes()))
            .collect();
        let anchors = root_der
            .iter()
            .map(webpki::anchor_from_trusted_cert)
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_webpki_error)?;
        let key_usage = required_key_usage(input.required_eku.as_der_content())?;

        leaf.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &intermediates,
            UnixTime::since_unix_epoch(Duration::from_secs(input.at.get())),
            key_usage,
            None,
            None,
        )
        .map_err(map_webpki_error)?;

        let (remainder, certificate) =
            parse_x509_certificate(input.leaf.as_bytes()).map_err(|_| PathError::Malformed)?;
        if !remainder.is_empty() {
            return Err(PathError::Malformed);
        }
        let spki = certificate.public_key().raw;
        let algorithm = spki_algorithm_identifier(spki)?;
        let not_before = timestamp(certificate.validity().not_before.timestamp())?;
        let not_after = timestamp(certificate.validity().not_after.timestamp())?;
        VerifiedLeaf::from_path_input(
            &input,
            not_before,
            not_after,
            AlgorithmIdentifierDer::new(algorithm.to_vec()).map_err(|_| PathError::Malformed)?,
            spki.to_vec(),
        )
    }
}

fn required_key_usage(oid: &[u8]) -> Result<webpki::KeyUsage, PathError> {
    match oid {
        CLIENT_AUTH_OID => Ok(webpki::KeyUsage::required(CLIENT_AUTH_OID)),
        CODE_SIGNING_OID => Ok(webpki::KeyUsage::required(CODE_SIGNING_OID)),
        _ => Err(PathError::UnsupportedAlgorithm),
    }
}

fn timestamp(value: i64) -> Result<Timestamp, PathError> {
    u64::try_from(value)
        .map(Timestamp::new)
        .map_err(|_| PathError::Malformed)
}

fn spki_algorithm_identifier(spki: &[u8]) -> Result<&[u8], PathError> {
    let (outer_header, outer_length) = der_tlv(spki, 0x30)?;
    if outer_header.checked_add(outer_length) != Some(spki.len()) {
        return Err(PathError::Malformed);
    }
    let body = &spki[outer_header..];
    let (algorithm_header, algorithm_length) = der_tlv(body, 0x30)?;
    let end = algorithm_header
        .checked_add(algorithm_length)
        .ok_or(PathError::LimitExceeded)?;
    Ok(&body[..end])
}

fn der_tlv(bytes: &[u8], expected_tag: u8) -> Result<(usize, usize), PathError> {
    if bytes.first().copied() != Some(expected_tag) {
        return Err(PathError::Malformed);
    }
    let length_byte = *bytes.get(1).ok_or(PathError::Malformed)?;
    if length_byte & 0x80 == 0 {
        let length = usize::from(length_byte);
        if bytes.len() < 2 + length {
            return Err(PathError::Malformed);
        }
        return Ok((2, length));
    }
    let count = usize::from(length_byte & 0x7f);
    if count == 0 || count > core::mem::size_of::<usize>() || bytes.len() < 2 + count {
        return Err(PathError::Malformed);
    }
    if bytes[2] == 0 {
        return Err(PathError::Malformed);
    }
    let mut length = 0usize;
    for byte in &bytes[2..2 + count] {
        length = length
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*byte)))
            .ok_or(PathError::LimitExceeded)?;
    }
    if length < 128 || bytes.len() < 2 + count + length {
        return Err(PathError::Malformed);
    }
    Ok((2 + count, length))
}

#[allow(deprecated)]
fn map_webpki_error(error: webpki::Error) -> PathError {
    match error {
        webpki::Error::CertExpired { .. } => PathError::Expired,
        webpki::Error::CertNotValidYet { .. } => PathError::NotYetValid,
        webpki::Error::CaUsedAsEndEntity => PathError::NotEndEntity,
        webpki::Error::EmptyEkuExtension
        | webpki::Error::RequiredEkuNotFound
        | webpki::Error::RequiredEkuNotFoundContext(_) => PathError::MissingEku,
        webpki::Error::NameConstraintViolation | webpki::Error::MalformedNameConstraint => {
            PathError::NameConstraint
        }
        webpki::Error::UnknownIssuer => PathError::UntrustedAnchor,
        webpki::Error::InvalidSignatureForPublicKey => PathError::InvalidSignature,
        webpki::Error::UnsupportedSignatureAlgorithm
        | webpki::Error::UnsupportedSignatureAlgorithmContext(_)
        | webpki::Error::UnsupportedSignatureAlgorithmForPublicKey
        | webpki::Error::UnsupportedSignatureAlgorithmForPublicKeyContext(_) => {
            PathError::UnsupportedAlgorithm
        }
        webpki::Error::MaximumNameConstraintComparisonsExceeded
        | webpki::Error::MaximumPathBuildCallsExceeded
        | webpki::Error::MaximumPathDepthExceeded
        | webpki::Error::MaximumSignatureChecksExceeded => PathError::LimitExceeded,
        _ => PathError::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_and_work_are_stable() {
        let verifier = WebPkiPathVerifier::new();
        assert_eq!(verifier.id().as_str(), IMPLEMENTATION_ID);
        assert_eq!(verifier.maximum_work_units(3), 400);
        assert_eq!(verifier, WebPkiPathVerifier::default());
    }
}
