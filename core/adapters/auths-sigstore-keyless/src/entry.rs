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
const HASHED_REKORD_PREFIX: &str = "{\"apiVersion\":\"0.0.1\",\"kind\":\"hashedrekord\",\"spec\":{\"data\":{\"hash\":{\"algorithm\":\"sha256\",\"value\":\"";
const HASHED_REKORD_MIDDLE: &str = "\"}},\"signature\":{\"content\":\"";
const HASHED_REKORD_PUBLIC_KEY: &str = "\",\"publicKey\":{\"content\":\"";
const HASHED_REKORD_SUFFIX: &str = "\"}}}}";

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
        let remainder = text
            .strip_prefix(HASHED_REKORD_PREFIX)
            .ok_or(EntryError::Body)?;
        let (digest, remainder) = remainder
            .split_once(HASHED_REKORD_MIDDLE)
            .ok_or(EntryError::Body)?;
        let (signature, remainder) = remainder
            .split_once(HASHED_REKORD_PUBLIC_KEY)
            .ok_or(EntryError::Body)?;
        let certificate = remainder
            .strip_suffix(HASHED_REKORD_SUFFIX)
            .ok_or(EntryError::Body)?;
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
    /// The entry's index across the whole log, as the Signed Entry
    /// Timestamp signs it.
    pub log_index: u64,
    pub body: HashedRekordBody,
    /// The inclusion proof, whose index is the leaf position in the tree the
    /// checkpoint names. A sharded log numbers these per tree, so it differs
    /// from `log_index` for every entry outside the first shard.
    pub proof: InclusionProof,
    pub checkpoint: Checkpoint,
    pub integrated: Timestamp,
    pub signed_entry_timestamp: BoundedBytes<MAX_SET_BYTES>,
}
impl RekorEntry {
    /// Parses one canonical bounded Rekor entry evidence object.
    ///
    /// # Errors
    ///
    /// Returns [`EntryError`] when the entry is malformed, non-canonical,
    /// exceeds a bound, or contains inconsistent checkpoint/proof fields.
    pub fn parse(bytes: &[u8]) -> Result<Self, EntryError> {
        let mut decoder = Decoder::new(bytes);
        let count = decoder
            .map()
            .map_err(|_| EntryError::Cbor)?
            .ok_or(EntryError::Cbor)?;
        if count != ENTRY_FIELDS {
            return Err(EntryError::Cbor);
        }
        let mut raw = RawEntry::default();
        for _ in 0..count {
            raw.decode_field(&mut decoder)?;
        }
        if decoder.position() != bytes.len() {
            return Err(EntryError::Cbor);
        }
        let fields = raw.complete()?;
        if encode_entry(&fields)? != bytes {
            return Err(EntryError::NonCanonical);
        }
        let checkpoint =
            Checkpoint::parse(fields.checkpoint.as_bytes()).map_err(EntryError::Checkpoint)?;
        if checkpoint.tree_size != fields.tree_size {
            return Err(EntryError::Proof);
        }
        Ok(Self {
            log: LogId(*fields.log_id),
            log_index: fields.log_index,
            body: HashedRekordBody::parse(fields.body.to_vec())?,
            proof: InclusionProof::new(
                fields.proof_index,
                fields.tree_size,
                fields.hashes.to_vec(),
            )?,
            checkpoint,
            integrated: Timestamp::new(fields.integrated_time),
            signed_entry_timestamp: BoundedBytes::new(fields.signed_entry_timestamp.to_vec())
                .map_err(|_| EntryError::Limit)?,
        })
    }

    /// The exact bytes the Signed Entry Timestamp signs: the RFC 8785
    /// canonical JSON of the entry's body, integration time, log id, and
    /// whole-log index.
    #[must_use]
    pub fn set_preimage(&self) -> Vec<u8> {
        let body = Base64::encode_string(&self.body.raw);
        let log = lower_hex(self.log.bytes());
        format!(
            "{{\"body\":\"{body}\",\"integratedTime\":{},\"logID\":\"{log}\",\"logIndex\":{}}}",
            self.integrated.get(),
            self.log_index
        )
        .into_bytes()
    }
}

/// Number of keys in the canonical entry map.
const ENTRY_FIELDS: u64 = 9;

/// The fields of one Rekor entry evidence object.
#[derive(Clone, Copy, Debug)]
pub struct EntryFields<'a> {
    /// The canonical `hashedrekord` body, exactly as the log returned it.
    pub body: &'a [u8],
    /// The signed checkpoint note.
    pub checkpoint: &'a str,
    /// The inclusion proof hashes, leaf to root.
    pub hashes: &'a [Digest],
    /// The integration time the Signed Entry Timestamp signs.
    pub integrated_time: u64,
    /// SHA-256 of the log's DER public key.
    pub log_id: &'a [u8; 32],
    /// The entry's index across the whole log.
    pub log_index: u64,
    /// The entry's leaf index in the tree the checkpoint names.
    pub proof_index: u64,
    /// The log's signature over the entry metadata.
    pub signed_entry_timestamp: &'a [u8],
    /// The size of the tree the checkpoint names.
    pub tree_size: u64,
}

/// Owned fields while decoding, each present at most once.
#[derive(Default)]
struct RawEntry {
    body: Option<Vec<u8>>,
    checkpoint: Option<String>,
    hashes: Option<Vec<Digest>>,
    integrated: Option<u64>,
    log_id: Option<[u8; 32]>,
    log_index: Option<u64>,
    proof_index: Option<u64>,
    set: Option<Vec<u8>>,
    tree_size: Option<u64>,
}
impl RawEntry {
    fn decode_field(&mut self, decoder: &mut Decoder<'_>) -> Result<(), EntryError> {
        let cbor = |_| EntryError::Cbor;
        match decoder.str().map_err(cbor)? {
            "body" => self.body = Some(decoder.bytes().map_err(cbor)?.to_vec()),
            "checkpoint" => self.checkpoint = Some(decoder.str().map_err(cbor)?.into()),
            "hashes" => self.hashes = Some(decode_hashes(decoder)?),
            "integrated_time" => self.integrated = Some(decoder.u64().map_err(cbor)?),
            "log_id" => {
                self.log_id = Some(
                    decoder
                        .bytes()
                        .map_err(cbor)?
                        .try_into()
                        .map_err(|_| EntryError::Cbor)?,
                );
            }
            "log_index" => self.log_index = Some(decoder.u64().map_err(cbor)?),
            "proof_index" => self.proof_index = Some(decoder.u64().map_err(cbor)?),
            "signed_entry_timestamp" => self.set = Some(decoder.bytes().map_err(cbor)?.to_vec()),
            "tree_size" => self.tree_size = Some(decoder.u64().map_err(cbor)?),
            _ => return Err(EntryError::Cbor),
        }
        Ok(())
    }

    fn complete(&self) -> Result<EntryFields<'_>, EntryError> {
        Ok(EntryFields {
            body: self.body.as_deref().ok_or(EntryError::Cbor)?,
            checkpoint: self.checkpoint.as_deref().ok_or(EntryError::Cbor)?,
            hashes: self.hashes.as_deref().ok_or(EntryError::Cbor)?,
            integrated_time: self.integrated.ok_or(EntryError::Cbor)?,
            log_id: self.log_id.as_ref().ok_or(EntryError::Cbor)?,
            log_index: self.log_index.ok_or(EntryError::Cbor)?,
            proof_index: self.proof_index.ok_or(EntryError::Cbor)?,
            signed_entry_timestamp: self.set.as_deref().ok_or(EntryError::Cbor)?,
            tree_size: self.tree_size.ok_or(EntryError::Cbor)?,
        })
    }
}

fn decode_hashes(decoder: &mut Decoder<'_>) -> Result<Vec<Digest>, EntryError> {
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
    Ok(values)
}

/// Encodes the canonical bounded field map for one Rekor entry.
///
/// # Errors
///
/// Returns [`EntryError`] if a field count or value cannot be represented by
/// the canonical CBOR encoder.
pub fn encode_entry(fields: &EntryFields<'_>) -> Result<Vec<u8>, EntryError> {
    let cbor = |_| EntryError::Cbor;
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(ENTRY_FIELDS).map_err(cbor)?;
    encoder
        .str("body")
        .and_then(|e| e.bytes(fields.body))
        .map_err(cbor)?;
    encoder
        .str("hashes")
        .and_then(|e| e.array(fields.hashes.len() as u64))
        .map_err(cbor)?;
    for hash in fields.hashes {
        encoder.bytes(hash.as_bytes()).map_err(cbor)?;
    }
    encoder
        .str("log_id")
        .and_then(|e| e.bytes(fields.log_id))
        .map_err(cbor)?;
    encoder
        .str("log_index")
        .and_then(|e| e.u64(fields.log_index))
        .map_err(cbor)?;
    encoder
        .str("tree_size")
        .and_then(|e| e.u64(fields.tree_size))
        .map_err(cbor)?;
    encoder
        .str("checkpoint")
        .and_then(|e| e.str(fields.checkpoint))
        .map_err(cbor)?;
    encoder
        .str("proof_index")
        .and_then(|e| e.u64(fields.proof_index))
        .map_err(cbor)?;
    encoder
        .str("integrated_time")
        .and_then(|e| e.u64(fields.integrated_time))
        .map_err(cbor)?;
    encoder
        .str("signed_entry_timestamp")
        .and_then(|e| e.bytes(fields.signed_entry_timestamp))
        .map_err(cbor)?;
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
