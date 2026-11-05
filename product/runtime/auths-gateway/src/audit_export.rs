//! Bounded data assembly for operator-private audit exports. No admission or I/O.
use super::{
    BundleSource, MAX_AUDIT_BUNDLE_BYTES, MAX_AUDIT_PRE_ENTRY_OBSERVATIONS, bundle_source, decode,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::Deserialize;
use std::collections::BTreeMap;
use zeroize::{Zeroize as _, Zeroizing};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateEvidence {
    schema: String,
    operation_id: String,
    outcome_b64: String,
    #[serde(deserialize_with = "observations")]
    pre_entry_b64: Vec<String>,
}

/// Operator-only assembly of a public submission bundle and protected native
/// evidence. This does not verify authority or manufacture an outcome: the
/// resulting bundle still requires the independent offline auditor and pins.
/// Its contents must remain in operator-private storage.
pub struct PrivateAuditBundle {
    source: BundleSource,
    entries: BTreeMap<String, usize>,
    encoded_bound: usize,
}

impl std::fmt::Debug for PrivateAuditBundle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrivateAuditBundle")
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl PrivateAuditBundle {
    /// Decode the current bounded bundle schema. Discard every supplied outcome
    /// and pre-entry value before collecting fresh operator-private evidence.
    ///
    /// # Errors
    /// Refuses malformed/obsolete/oversized bundles, duplicate operation IDs,
    /// invalid IDs or noncanonical/oversized proof and action encodings.
    pub fn new(bytes: &[u8]) -> Result<Self, &'static str> {
        let mut source = bundle_source(bytes)?;
        let mut entries = BTreeMap::new();
        for (index, entry) in source.entries.iter_mut().enumerate() {
            crate::LogicalOperationId::parse(&entry.operation_id)
                .map_err(|_| "audit.entry-malformed")?;
            if entries.insert(entry.operation_id.clone(), index).is_some()
                || !canonical_base64(&entry.proof_b64, super::MAX_PROOF_BYTES)
                || !canonical_base64(&entry.action_b64, super::MAX_ACTION_BYTES)
            {
                return Err("audit.entry-malformed");
            }
            entry.outcome_b64 = None;
            entry.pre_entry_b64 = None;
        }
        Ok(Self {
            source,
            entries,
            encoded_bound: bytes.len(),
        })
    }

    /// The finite native operation inventory, in deterministic sorted order.
    #[must_use]
    pub fn operations(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    /// Attach a current native operator export for the named operation. `None`
    /// records only the absence of a protected record, never non-entry or refund.
    /// The caller must authenticate the operator socket before obtaining bytes.
    ///
    /// # Errors
    /// Refuses unknown/mismatched operations, obsolete or ambiguous objects,
    /// noncanonical/oversized observations and aggregate output over 64 MiB.
    pub fn record(&mut self, operation: &str, bytes: Option<&[u8]>) -> Result<(), &'static str> {
        let index = *self
            .entries
            .get(operation)
            .ok_or("audit.operation-mismatch")?;
        let Some(bytes) = bytes else {
            self.source.entries[index].outcome_b64 = None;
            self.source.entries[index].pre_entry_b64 = None;
            return Ok(());
        };
        let observation_limit = auths_model::MAX_OBSERVATION_BYTES;
        // Five signed observations plus JSON keys fit this deliberately finite
        // wire bound. The native pre-entry contract permits at most four.
        let maximum =
            (observation_limit.div_ceil(3) * 4 + 256) * (MAX_AUDIT_PRE_ENTRY_OBSERVATIONS + 1);
        if bytes.len() > maximum {
            return Err("audit.bundle-invalid-size");
        }
        let mut evidence: PrivateEvidence =
            serde_json::from_slice(bytes).map_err(|_| "audit.outcome-invalid")?;
        if evidence.schema != "auths.gateway-private-audit/1"
            || evidence.operation_id != operation
            || evidence.pre_entry_b64.len() > MAX_AUDIT_PRE_ENTRY_OBSERVATIONS
            || !canonical_base64(&evidence.outcome_b64, observation_limit)
            || !evidence
                .pre_entry_b64
                .iter()
                .all(|value| canonical_base64(value, observation_limit))
        {
            return Err("audit.outcome-invalid");
        }
        let bound = self
            .encoded_bound
            .checked_add(bytes.len())
            .ok_or("audit.bundle-invalid-size")?;
        if bound > MAX_AUDIT_BUNDLE_BYTES {
            return Err("audit.bundle-invalid-size");
        }
        self.encoded_bound = bound;
        self.source.entries[index].outcome_b64 = Some(std::mem::take(&mut evidence.outcome_b64));
        self.source.entries[index].pre_entry_b64 =
            Some(std::mem::take(&mut evidence.pre_entry_b64));
        Ok(())
    }

    /// Serialize the protected bundle. This grants no verified audit status.
    ///
    /// # Errors
    /// Refuses serialization failure or output beyond the shared bundle limit.
    pub fn finish(self) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        let bytes =
            Zeroizing::new(serde_json::to_vec(&self.source).map_err(|_| "audit.bundle-malformed")?);
        if bytes.len() > MAX_AUDIT_BUNDLE_BYTES {
            return Err("audit.bundle-invalid-size");
        }
        Ok(bytes)
    }
}

fn canonical_base64(text: &str, limit: usize) -> bool {
    decode(text, limit).is_some_and(|bytes| Base64UrlUnpadded::encode_string(&bytes) == text)
}

impl Drop for PrivateEvidence {
    fn drop(&mut self) {
        self.outcome_b64.zeroize();
        for item in &mut self.pre_entry_b64 {
            item.zeroize();
        }
    }
}

impl Drop for PrivateAuditBundle {
    fn drop(&mut self) {
        for entry in &mut self.source.entries {
            entry.proof_b64.zeroize();
            entry.action_b64.zeroize();
            if let Some(outcome) = &mut entry.outcome_b64 {
                outcome.zeroize();
            }
            if let Some(items) = &mut entry.pre_entry_b64 {
                for item in items {
                    item.zeroize();
                }
            }
        }
    }
}

pub(super) fn entries<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Vec<super::EntrySource>, D::Error> {
    bounded(d, super::MAX_AUDIT_ENTRIES)
}

pub(super) fn responses<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Vec<super::ResponseSource>, D::Error> {
    bounded(d, super::MAX_AUDIT_APPROVAL_RESPONSES)
}

fn observations<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    bounded(d, MAX_AUDIT_PRE_ENTRY_OBSERVATIONS)
}

fn bounded<'de, T: Deserialize<'de>, D: serde::Deserializer<'de>>(
    d: D,
    limit: usize,
) -> Result<Vec<T>, D::Error> {
    struct Items<T>(usize, std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Items<T> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("bounded audit items")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            if seq.size_hint().is_some_and(|size| size > self.0) {
                return Err(serde::de::Error::custom("audit item limit exceeded"));
            }
            let mut values = Vec::new();
            loop {
                if values.len() == self.0 {
                    if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                        return Err(serde::de::Error::custom("audit item limit exceeded"));
                    }
                    break;
                }
                let Some(value) = seq.next_element()? else {
                    break;
                };
                values.push(value);
            }
            Ok(values)
        }
    }
    d.deserialize_seq(Items::<T>(limit, std::marker::PhantomData))
}
