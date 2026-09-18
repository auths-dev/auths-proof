extern crate alloc;

use alloc::{format, string::String, vec::Vec};
use auths_model::{BoundedBytes, Digest, Timestamp};
use auths_ports::CertificateDer;
use base64ct::{Base64, Encoding as _};
use minicbor::{Decoder, Encoder};

use crate::{EntryError, checkpoint::Checkpoint, merkle};

pub const MAX_ENTRY_BODY_BYTES: usize = 16_384;
pub const MAX_ENTRY_SIGNATURE_BYTES: usize = 16_384;
pub const MAX_PROOF_HASHES: usize = 64;
pub const MAX_SET_BYTES: usize = 2048;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LogId([u8; 32]);
impl LogId {
    #[must_use]
    pub const fn new(value: [u8; 32]) -> Self {
        Self(value)
    }
    #[must_use]
    pub const fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HashedRekordBody {
    pub raw: Vec<u8>,
    pub artifact_digest: Digest,
    pub signature: BoundedBytes<MAX_ENTRY_SIGNATURE_BYTES>,
    pub certificate: CertificateDer,
}
impl HashedRekordBody {
    fn parse(raw: Vec<u8>) -> Result<Self, EntryError> {
        if raw.is_empty() || raw.len() > MAX_ENTRY_BODY_BYTES {
            return Err(EntryError::Limit);
        }
        let text = core::str::from_utf8(&raw).map_err(|_| EntryError::Body)?;
        const PREFIX: &str = "{\"apiVersion\":\"0.0.1\",\"kind\":\"hashedrekord\",\"spec\":{\"data\":{\"hash\":{\"algorithm\":\"sha256\",\"value\":\"";
        const MIDDLE: &str = "\"}},\"signature\":{\"content\":\"";
        const PUBLIC: &str = "\",\"publicKey\":{\"content\":\"";
        const SUFFIX: &str = "\"}}}}";
        let remainder = text.strip_prefix(PREFIX).ok_or(EntryError::Body)?;
        let (digest, remainder) = remainder.split_once(MIDDLE).ok_or(EntryError::Body)?;
        let (signature, remainder) = remainder.split_once(PUBLIC).ok_or(EntryError::Body)?;
        let certificate = remainder.strip_suffix(SUFFIX).ok_or(EntryError::Body)?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(EntryError::Body);
        }
        let artifact_digest = Digest::new(hex32(digest)?);
        let signature = Base64::decode_vec(signature).map_err(|_| EntryError::Body)?;
        let signature = BoundedBytes::new(signature).map_err(|_| EntryError::Limit)?;
        let pem = Base64::decode_vec(certificate).map_err(|_| EntryError::Body)?;
        let certificate = pem_certificate(&pem)?;
        Ok(Self {
            raw,
            artifact_digest,
            signature,
            certificate,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InclusionProof {
    pub index: u64,
    pub tree_size: u64,
    pub hashes: Vec<Digest>,
}
impl InclusionProof {
    fn new(index: u64, tree_size: u64, hashes: Vec<Digest>) -> Result<Self, EntryError> {
        if hashes.len() > MAX_PROOF_HASHES
            || merkle::path_length(index, tree_size).ok() != Some(hashes.len())
        {
            return Err(EntryError::Proof);
        }
        Ok(Self {
            index,
            tree_size,
            hashes,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RekorEntry {
    pub log: LogId,
    pub body: HashedRekordBody,
    pub proof: InclusionProof,
    pub checkpoint: Checkpoint,
    pub integrated: Timestamp,
    pub signed_entry_timestamp: BoundedBytes<MAX_SET_BYTES>,
}
impl RekorEntry {
    pub fn parse(bytes: &[u8]) -> Result<Self, EntryError> {
        let mut decoder = Decoder::new(bytes);
        let count = decoder
            .map()
            .map_err(|_| EntryError::Cbor)?
            .ok_or(EntryError::Cbor)?;
        if count != 8 {
            return Err(EntryError::Cbor);
        }
        let mut body = None;
        let mut checkpoint = None;
        let mut hashes = None;
        let mut integrated = None;
        let mut log_id = None;
        let mut log_index = None;
        let mut set = None;
        let mut tree_size = None;
        for _ in 0..count {
            let key = decoder.str().map_err(|_| EntryError::Cbor)?;
            match key {
                "body" => body = Some(decoder.bytes().map_err(|_| EntryError::Cbor)?.to_vec()),
                "checkpoint" => {
                    checkpoint = Some(
                        decoder
                            .str()
                            .map_err(|_| EntryError::Cbor)?
                            .as_bytes()
                            .to_vec(),
                    )
                }
                "hashes" => {
                    let length = decoder
                        .array()
                        .map_err(|_| EntryError::Cbor)?
                        .ok_or(EntryError::Cbor)?;
                    if length > MAX_PROOF_HASHES as u64 {
                        return Err(EntryError::Limit);
                    }
                    let mut values = Vec::new();
                    for _ in 0..length {
                        values.push(Digest::new(
                            decoder
                                .bytes()
                                .map_err(|_| EntryError::Cbor)?
                                .try_into()
                                .map_err(|_| EntryError::Cbor)?,
                        ));
                    }
                    hashes = Some(values);
                }
                "integrated_time" => {
                    integrated = Some(decoder.u64().map_err(|_| EntryError::Cbor)?)
                }
                "log_id" => {
                    log_id = Some(
                        decoder
                            .bytes()
                            .map_err(|_| EntryError::Cbor)?
                            .try_into()
                            .map_err(|_| EntryError::Cbor)?,
                    )
                }
                "log_index" => log_index = Some(decoder.u64().map_err(|_| EntryError::Cbor)?),
                "signed_entry_timestamp" => {
                    set = Some(decoder.bytes().map_err(|_| EntryError::Cbor)?.to_vec())
                }
                "tree_size" => tree_size = Some(decoder.u64().map_err(|_| EntryError::Cbor)?),
                _ => return Err(EntryError::Cbor),
            }
        }
        if decoder.position() != bytes.len() {
            return Err(EntryError::Cbor);
        }
        let body = body.ok_or(EntryError::Cbor)?;
        let checkpoint_bytes = checkpoint.ok_or(EntryError::Cbor)?;
        let hashes = hashes.ok_or(EntryError::Cbor)?;
        let integrated = integrated.ok_or(EntryError::Cbor)?;
        let log_id = log_id.ok_or(EntryError::Cbor)?;
        let log_index = log_index.ok_or(EntryError::Cbor)?;
        let set = set.ok_or(EntryError::Cbor)?;
        let tree_size = tree_size.ok_or(EntryError::Cbor)?;
        let canonical = encode_fields(
            &body,
            core::str::from_utf8(&checkpoint_bytes).map_err(|_| EntryError::Cbor)?,
            &hashes,
            integrated,
            &log_id,
            log_index,
            &set,
            tree_size,
        )?;
        if canonical != bytes {
            return Err(EntryError::NonCanonical);
        }
        let checkpoint = Checkpoint::parse(&checkpoint_bytes).map_err(EntryError::Checkpoint)?;
        if checkpoint.tree_size != tree_size {
            return Err(EntryError::Proof);
        }
        Ok(Self {
            log: LogId(log_id),
            body: HashedRekordBody::parse(body)?,
            proof: InclusionProof::new(log_index, tree_size, hashes)?,
            checkpoint,
            integrated: Timestamp::new(integrated),
            signed_entry_timestamp: BoundedBytes::new(set).map_err(|_| EntryError::Limit)?,
        })
    }

    #[must_use]
    pub fn set_preimage(&self) -> Vec<u8> {
        let body = Base64::encode_string(&self.body.raw);
        let log = lower_hex(self.log.bytes());
        format!(
            "{{\"body\":\"{body}\",\"integratedTime\":{},\"logID\":\"{log}\",\"logIndex\":{}}}",
            self.integrated.get(),
            self.proof.index
        )
        .into_bytes()
    }
}

pub fn encode_fields(
    body: &[u8],
    checkpoint: &str,
    hashes: &[Digest],
    integrated: u64,
    log_id: &[u8; 32],
    log_index: u64,
    set: &[u8],
    tree_size: u64,
) -> Result<Vec<u8>, EntryError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(8).map_err(|_| EntryError::Cbor)?;
    encoder
        .str("body")
        .and_then(|e| e.bytes(body))
        .map_err(|_| EntryError::Cbor)?;
    encoder
        .str("hashes")
        .and_then(|e| e.array(hashes.len() as u64))
        .map_err(|_| EntryError::Cbor)?;
    for hash in hashes {
        encoder
            .bytes(hash.as_bytes())
            .map_err(|_| EntryError::Cbor)?;
    }
    encoder
        .str("log_id")
        .and_then(|e| e.bytes(log_id))
        .map_err(|_| EntryError::Cbor)?;
    encoder
        .str("log_index")
        .and_then(|e| e.u64(log_index))
        .map_err(|_| EntryError::Cbor)?;
    encoder
        .str("tree_size")
        .and_then(|e| e.u64(tree_size))
        .map_err(|_| EntryError::Cbor)?;
    encoder
        .str("checkpoint")
        .and_then(|e| e.str(checkpoint))
        .map_err(|_| EntryError::Cbor)?;
    encoder
        .str("integrated_time")
        .and_then(|e| e.u64(integrated))
        .map_err(|_| EntryError::Cbor)?;
    encoder
        .str("signed_entry_timestamp")
        .and_then(|e| e.bytes(set))
        .map_err(|_| EntryError::Cbor)?;
    Ok(encoder.into_writer())
}

fn pem_certificate(pem: &[u8]) -> Result<CertificateDer, EntryError> {
    let text = core::str::from_utf8(pem).map_err(|_| EntryError::Body)?;
    let inner = text
        .strip_prefix("-----BEGIN CERTIFICATE-----\n")
        .and_then(|v| {
            v.strip_suffix("-----END CERTIFICATE-----\n")
                .or_else(|| v.strip_suffix("-----END CERTIFICATE-----"))
        })
        .ok_or(EntryError::Body)?;
    if inner.contains("-----") {
        return Err(EntryError::Body);
    }
    let compact: String = inner.lines().collect();
    let der = Base64::decode_vec(&compact).map_err(|_| EntryError::Body)?;
    CertificateDer::new(der).map_err(|_| EntryError::Body)
}
fn hex32(value: &str) -> Result<[u8; 32], EntryError> {
    let mut output = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex(pair[0])? << 4) | hex(pair[1])?;
    }
    Ok(output)
}
fn hex(byte: u8) -> Result<u8, EntryError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(EntryError::Body),
    }
}
fn lower_hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::new();
    for b in bytes {
        s.push(char::from(H[usize::from(b >> 4)]));
        s.push(char::from(H[usize::from(b & 15)]));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};
    #[test]
    fn hashedrekord_body_is_closed_and_exact() {
        let certificate = CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .self_signed(&KeyPair::generate().unwrap())
            .unwrap();
        let der = Base64::encode_string(certificate.der());
        let pem = alloc::format!("-----BEGIN CERTIFICATE-----\n{der}\n-----END CERTIFICATE-----\n");
        let cert = Base64::encode_string(pem.as_bytes());
        let signature = Base64::encode_string(&[1, 2, 3]);
        let body = alloc::format!(
            "{{\"apiVersion\":\"0.0.1\",\"kind\":\"hashedrekord\",\"spec\":{{\"data\":{{\"hash\":{{\"algorithm\":\"sha256\",\"value\":\"{}\"}}}},\"signature\":{{\"content\":\"{signature}\",\"publicKey\":{{\"content\":\"{cert}\"}}}}}}}}",
            "00".repeat(32)
        );
        let parsed = HashedRekordBody::parse(body.into_bytes()).unwrap();
        assert_eq!(parsed.certificate.as_bytes(), certificate.der().as_ref());
    }
}
