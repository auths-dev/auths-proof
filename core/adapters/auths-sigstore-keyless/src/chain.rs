extern crate alloc;

use alloc::vec::Vec;
use auths_model::Timestamp;
use auths_ports::{AlgorithmIdentifierDer, CertificateDer};
use minicbor::{Decoder, Encoder};
use x509_parser::parse_x509_certificate;

use crate::ChainError;

pub const MAX_CHAIN_LENGTH: usize = 4;
pub const MAX_CERTIFICATE_BYTES: usize = 8192;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeafCertificate {
    der: CertificateDer,
    not_before: Timestamp,
    not_after: Timestamp,
    spki_algorithm: AlgorithmIdentifierDer,
    spki: Vec<u8>,
}
impl LeafCertificate {
    fn parse(bytes: Vec<u8>, maximum_validity: u64) -> Result<Self, ChainError> {
        if bytes.len() > MAX_CERTIFICATE_BYTES {
            return Err(ChainError::Limit);
        }
        let der = CertificateDer::new(bytes).map_err(|_| ChainError::Malformed)?;
        let (remainder, certificate) =
            parse_x509_certificate(der.as_bytes()).map_err(|_| ChainError::Malformed)?;
        if !remainder.is_empty() {
            return Err(ChainError::Malformed);
        }
        let before = u64::try_from(certificate.validity().not_before.timestamp())
            .map_err(|_| ChainError::Malformed)?;
        let after = u64::try_from(certificate.validity().not_after.timestamp())
            .map_err(|_| ChainError::Malformed)?;
        if before >= after
            || after
                .checked_sub(before)
                .is_none_or(|value| value > maximum_validity)
        {
            return Err(ChainError::Validity);
        }
        let spki = certificate.public_key().raw.to_vec();
        let algorithm = spki_algorithm_identifier(&spki)
            .map_err(|_| ChainError::Malformed)?
            .to_vec();
        Ok(Self {
            der,
            not_before: Timestamp::new(before),
            not_after: Timestamp::new(after),
            spki_algorithm: AlgorithmIdentifierDer::new(algorithm)
                .map_err(|_| ChainError::Malformed)?,
            spki,
        })
    }
    #[must_use]
    pub const fn der(&self) -> &CertificateDer {
        &self.der
    }
    #[must_use]
    pub const fn not_before(&self) -> Timestamp {
        self.not_before
    }
    #[must_use]
    pub const fn not_after(&self) -> Timestamp {
        self.not_after
    }
    #[must_use]
    pub const fn spki_algorithm(&self) -> &AlgorithmIdentifierDer {
        &self.spki_algorithm
    }
    #[must_use]
    pub fn spki(&self) -> &[u8] {
        &self.spki
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateChain {
    leaf: LeafCertificate,
    intermediates: Vec<CertificateDer>,
}
impl CertificateChain {
    pub fn parse(bytes: &[u8], maximum_validity: u64) -> Result<Self, ChainError> {
        let mut decoder = Decoder::new(bytes);
        let count = decoder
            .array()
            .map_err(|_| ChainError::Malformed)?
            .ok_or(ChainError::Malformed)?;
        let count = usize::try_from(count).map_err(|_| ChainError::Limit)?;
        if count == 0 || count > MAX_CHAIN_LENGTH {
            return Err(ChainError::Limit);
        }
        let mut certificates = Vec::with_capacity(count);
        for _ in 0..count {
            let value = decoder.bytes().map_err(|_| ChainError::Malformed)?;
            if value.is_empty() || value.len() > MAX_CERTIFICATE_BYTES {
                return Err(ChainError::Limit);
            }
            certificates.push(value.to_vec());
        }
        if decoder.position() != bytes.len() {
            return Err(ChainError::Malformed);
        }
        let canonical = encode_certificates(&certificates)?;
        if canonical != bytes {
            return Err(ChainError::NonCanonical);
        }
        let leaf = LeafCertificate::parse(certificates.remove(0), maximum_validity)?;
        let intermediates = certificates
            .into_iter()
            .map(CertificateDer::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ChainError::Malformed)?;
        Ok(Self {
            leaf,
            intermediates,
        })
    }
    pub fn encode(certificates: &[Vec<u8>]) -> Result<Vec<u8>, ChainError> {
        encode_certificates(certificates)
    }
    #[must_use]
    pub const fn leaf(&self) -> &LeafCertificate {
        &self.leaf
    }
    #[must_use]
    pub fn intermediates(&self) -> &[CertificateDer] {
        &self.intermediates
    }
}

fn encode_certificates(certificates: &[Vec<u8>]) -> Result<Vec<u8>, ChainError> {
    if certificates.is_empty() || certificates.len() > MAX_CHAIN_LENGTH {
        return Err(ChainError::Limit);
    }
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(u64::try_from(certificates.len()).map_err(|_| ChainError::Limit)?)
        .map_err(|_| ChainError::Malformed)?;
    for certificate in certificates {
        encoder
            .bytes(certificate)
            .map_err(|_| ChainError::Malformed)?;
    }
    Ok(encoder.into_writer())
}

pub(crate) fn spki_algorithm_identifier(spki: &[u8]) -> Result<&[u8], ()> {
    let (outer_header, outer_length) = der_tlv(spki, 0x30)?;
    if outer_header.checked_add(outer_length) != Some(spki.len()) {
        return Err(());
    }
    let body = &spki[outer_header..];
    let (header, length) = der_tlv(body, 0x30)?;
    let end = header.checked_add(length).ok_or(())?;
    Ok(&body[..end])
}

pub(crate) fn spki_bit_string(spki: &[u8]) -> Result<&[u8], ()> {
    let (outer_header, _) = der_tlv(spki, 0x30)?;
    let body = &spki[outer_header..];
    let (algorithm_header, algorithm_length) = der_tlv(body, 0x30)?;
    let offset = algorithm_header.checked_add(algorithm_length).ok_or(())?;
    let bit = &body[offset..];
    let (header, length) = der_tlv(bit, 0x03)?;
    let contents = bit.get(header..header + length).ok_or(())?;
    if contents.first() != Some(&0) {
        return Err(());
    }
    Ok(&contents[1..])
}

fn der_tlv(bytes: &[u8], tag: u8) -> Result<(usize, usize), ()> {
    if bytes.first() != Some(&tag) {
        return Err(());
    }
    let first = *bytes.get(1).ok_or(())?;
    if first & 0x80 == 0 {
        let length = usize::from(first);
        if bytes.len() < 2 + length {
            return Err(());
        }
        return Ok((2, length));
    }
    let count = usize::from(first & 0x7f);
    if count == 0
        || count > core::mem::size_of::<usize>()
        || bytes.len() < 2 + count
        || bytes[2] == 0
    {
        return Err(());
    }
    let mut length = 0usize;
    for byte in &bytes[2..2 + count] {
        length = length
            .checked_mul(256)
            .and_then(|v| v.checked_add(usize::from(*byte)))
            .ok_or(())?;
    }
    if length < 128 || bytes.len() < 2 + count + length {
        return Err(());
    }
    Ok((2 + count, length))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};
    #[test]
    fn chain_cbor_is_canonical_and_leaf_first() {
        let certificate = CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .self_signed(&KeyPair::generate().unwrap())
            .unwrap();
        let encoded = CertificateChain::encode(&[certificate.der().to_vec()]).unwrap();
        let parsed = CertificateChain::parse(&encoded, u64::MAX).unwrap();
        assert_eq!(parsed.leaf().der().as_bytes(), certificate.der().as_ref());
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            CertificateChain::parse(&trailing, u64::MAX),
            Err(ChainError::Malformed)
        );
    }
}
