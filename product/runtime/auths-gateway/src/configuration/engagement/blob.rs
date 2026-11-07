//! Immutable private audit bytes, staged before publishing a configuration
//! reference. No record in this module authorizes an operation or control change.
use super::{
    EngagementConfigurationError as Error, GatewayAttemptKey, GatewayAttemptStore, GatewayInsert,
    GatewayRecordEntry, GatewayRecordKind,
};
use base64ct::{Base64, Encoding as _};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize as _, Zeroizing};

const SCHEMA: &str = "auths.engagement-audit-blob/1";
const CHUNK_BYTES: usize = 160 * 1024;
pub(super) const MAX_BYTES: usize = auths_model::HARD_MAX_CONTEXT_BYTES;

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reference {
    commitment: [u8; 32],
    bytes: usize,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    reference: Reference,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Chunk {
    schema: String,
    reference: Reference,
    index: usize,
    data_b64: String,
}
impl Drop for Chunk {
    fn drop(&mut self) {
        self.data_b64.zeroize();
    }
}

fn digest(domain: &str, bytes: &[u8]) -> Result<[u8; 32], Error> {
    auths_codec::domain_commitment(domain, bytes)
        .map(|digest| *digest.as_bytes())
        .map_err(|_| Error::Corrupt)
}
fn canonical<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>, Error> {
    serde_json_canonicalizer::to_vec(value)
        .map(Zeroizing::new)
        .map_err(|_| Error::Corrupt)
}

impl Reference {
    pub(super) fn new(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(Error::EvidenceLimit);
        }
        Ok(Self {
            commitment: digest("auths.engagement-audit-blob/1", bytes)?,
            bytes: bytes.len(),
        })
    }
    pub(super) fn valid(&self) -> bool {
        (1..=MAX_BYTES).contains(&self.bytes)
    }
    pub(super) const fn bytes(&self) -> usize {
        self.bytes
    }
    pub(super) fn matches(&self, bytes: &[u8]) -> Result<(), Error> {
        if &Self::new(bytes)? != self {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
    fn key(&self, index: Option<usize>) -> Result<GatewayAttemptKey, Error> {
        let bytes = canonical(&(self, index))?;
        Ok(GatewayAttemptKey::from_bytes(digest(
            "auths.engagement-audit-record-key/1",
            &bytes,
        )?))
    }
    pub(super) fn manifest(&self) -> Result<GatewayRecordEntry, Error> {
        Ok(GatewayRecordEntry {
            kind: GatewayRecordKind::EffectConfiguration,
            key: self.key(None)?,
            record: canonical(&Manifest {
                schema: SCHEMA.into(),
                reference: self.clone(),
            })?
            .to_vec(),
            expires_at: None,
        })
    }
    fn chunk(&self, bytes: &[u8], index: usize) -> Result<GatewayRecordEntry, Error> {
        Ok(GatewayRecordEntry {
            kind: GatewayRecordKind::EffectConfiguration,
            key: self.key(Some(index))?,
            record: canonical(&Chunk {
                schema: SCHEMA.into(),
                reference: self.clone(),
                index,
                data_b64: Base64::encode_string(bytes),
            })?
            .to_vec(),
            expires_at: None,
        })
    }
    pub(super) fn load(
        &self,
        store: &dyn GatewayAttemptStore,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if !self.valid() {
            return Err(Error::Corrupt);
        }
        let manifest = self.manifest()?;
        if store.load(manifest.kind, &manifest.key)?.as_deref() != Some(manifest.record.as_slice())
        {
            return Err(Error::MissingEvidence);
        }
        let mut result = Zeroizing::new(Vec::with_capacity(self.bytes));
        for index in 0..self.bytes.div_ceil(CHUNK_BYTES) {
            let bytes = Zeroizing::new(
                store
                    .load(
                        GatewayRecordKind::EffectConfiguration,
                        &self.key(Some(index))?,
                    )?
                    .ok_or(Error::MissingEvidence)?,
            );
            let chunk: Chunk = serde_json::from_slice(&bytes).map_err(|_| Error::Corrupt)?;
            if chunk.schema != SCHEMA
                || chunk.reference != *self
                || chunk.index != index
                || canonical(&chunk)?.as_slice() != bytes.as_slice()
                || chunk.data_b64.len() > CHUNK_BYTES.div_ceil(3) * 4
            {
                return Err(Error::Corrupt);
            }
            let data =
                Zeroizing::new(Base64::decode_vec(&chunk.data_b64).map_err(|_| Error::Corrupt)?);
            let expected = (self.bytes - index * CHUNK_BYTES).min(CHUNK_BYTES);
            if data.len() != expected || Base64::encode_string(&data) != chunk.data_b64 {
                return Err(Error::Corrupt);
            }
            result.extend_from_slice(&data);
        }
        self.matches(&result)?;
        Ok(result)
    }
}

fn insert_exact(
    store: &dyn GatewayAttemptStore,
    entries: &[GatewayRecordEntry],
) -> Result<(), Error> {
    match store.insert_all(entries)? {
        GatewayInsert::Inserted => Ok(()),
        GatewayInsert::Exists { .. } => {
            // Fixed chunk groups are inserted all-or-none. Partial/mutated
            // retained groups are corruption, never silently filled or repaired.
            for entry in entries {
                if store.load(entry.kind, &entry.key)?.as_deref() != Some(entry.record.as_slice()) {
                    return Err(Error::MissingEvidence);
                }
            }
            Ok(())
        }
    }
}

pub(super) fn stage(store: &dyn GatewayAttemptStore, bytes: &[u8]) -> Result<Reference, Error> {
    let reference = Reference::new(bytes)?;
    let entries = bytes
        .chunks(CHUNK_BYTES)
        .enumerate()
        .map(|(index, bytes)| reference.chunk(bytes, index))
        .collect::<Result<Vec<_>, _>>()?;
    for group in entries.chunks(auths_stores::MAX_GATEWAY_BATCH_ENTRIES) {
        insert_exact(store, group)?;
    }
    // Every chunk's durable acknowledgement precedes the immutable manifest.
    // A failed/ambiguous acknowledgement stops before reference publication.
    // Protected permanent rows cannot be deleted/replaced by this owner. An
    // interrupted stage may leave inert orphan chunks, never live authority.
    insert_exact(store, &[reference.manifest()?])?;
    reference.load(store)?;
    Ok(reference)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store_testkit::{Backend, TestAttempts, postgres_configured};
    fn multiple_batches(backend: Backend) {
        let db = TestAttempts::open(backend);
        let data = Zeroizing::new(vec![b'S'; CHUNK_BYTES * 64 + 1]);
        let reference = stage(&*db.raw(), &data).unwrap();
        assert_eq!(reference.bytes.div_ceil(CHUNK_BYTES), 65);
        assert_eq!(
            reference.load(&*db.raw()).unwrap().as_slice(),
            data.as_slice()
        );
        assert!(stage(&*db.reopen().store(), &data).unwrap() == reference);
        assert!(db.raw().attempt_keys(16).unwrap().is_empty());
    }
    #[test]
    fn file_private_blob_spans_atomic_groups_without_creating_authority() {
        multiple_batches(Backend::File);
    }
    #[test]
    #[ignore = "requires the TLS PostgreSQL fixture"]
    fn postgres_private_blob_spans_atomic_groups_without_creating_authority() {
        assert!(postgres_configured(), "TLS PostgreSQL fixture is required");
        multiple_batches(Backend::Postgres);
    }
}
