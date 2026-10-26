//! Keyed, context-bound evidence for private provider content. This module
//! creates commitments only; it does not authorize or deliver a read.

use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"auths.agent-release-commitment/1\0";
const MAX_CONTEXT_FIELD_BYTES: usize = 512;

type HmacSha256 = Hmac<Sha256>;

/// A custody-held audit key. Callers must load it from a protected key store;
/// the constructor does not create or persist key material.
pub struct ReleaseCommitmentKey {
    version: u32,
    material: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for ReleaseCommitmentKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReleaseCommitmentKey")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// The exact logical context committed with the private content bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseCommitmentContext<'a> {
    task_id: &'a str,
    resource_handle: &'a str,
    operation_id: &'a str,
    receipt_kind: &'a str,
}

/// A redacted content commitment. Its digest is safe to export only while
/// the custody-held audit key remains private.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseCommitment {
    key_version: u32,
    mac: [u8; 32],
}

/// Invalid audit-key or receipt context.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ReleaseCommitmentError {
    /// Key versions are positive and key material must not be all zeroes.
    #[error("invalid release commitment key")]
    Key,
    /// A context field is missing, oversized or contains a control character.
    #[error("invalid release commitment context")]
    Context,
}

impl ReleaseCommitmentKey {
    /// Wrap one protected, 256-bit audit key version. The material is zeroized
    /// when this object is dropped.
    ///
    /// # Errors
    /// Rejects an absent version or trivially empty key.
    pub fn new(
        version: u32,
        material: Zeroizing<[u8; 32]>,
    ) -> Result<Self, ReleaseCommitmentError> {
        if version == 0 || material.iter().all(|byte| *byte == 0) {
            return Err(ReleaseCommitmentError::Key);
        }
        Ok(Self { version, material })
    }

    /// Commit to exact private bytes under one validated receipt context.
    ///
    /// # Panics
    /// The fixed 32-byte HMAC key and validated context lengths are always
    /// accepted by their encoders; failure would violate those invariants.
    #[must_use]
    pub fn commit(
        &self,
        scope: &ReleaseCommitmentContext<'_>,
        content: &[u8],
    ) -> ReleaseCommitment {
        let mut mac = HmacSha256::new_from_slice(&*self.material)
            .expect("fixed-size HMAC-SHA-256 key is accepted");
        mac.update(DOMAIN);
        mac.update(&self.version.to_be_bytes());
        for field in [
            scope.task_id,
            scope.resource_handle,
            scope.operation_id,
            scope.receipt_kind,
        ] {
            let bytes = field.as_bytes();
            let length = u32::try_from(bytes.len()).expect("context fields are at most 512 bytes");
            mac.update(&length.to_be_bytes());
            mac.update(bytes);
        }
        mac.update(&(content.len() as u64).to_be_bytes());
        mac.update(content);
        ReleaseCommitment {
            key_version: self.version,
            mac: mac.finalize().into_bytes().into(),
        }
    }

    /// Privately compare a retained receipt with independently obtained bytes.
    #[must_use]
    pub fn verify(
        &self,
        scope: &ReleaseCommitmentContext<'_>,
        content: &[u8],
        receipt: &ReleaseCommitment,
    ) -> bool {
        self.version == receipt.key_version
            && bool::from(self.commit(scope, content).mac.ct_eq(&receipt.mac))
    }
}

impl<'a> ReleaseCommitmentContext<'a> {
    /// Bind the content to a task, resource, operation and receipt meaning.
    ///
    /// # Errors
    /// Refuses missing, oversized or control-bearing identifiers.
    pub fn new(
        task_id: &'a str,
        resource_handle: &'a str,
        operation_id: &'a str,
        receipt_kind: &'a str,
    ) -> Result<Self, ReleaseCommitmentError> {
        for field in [task_id, resource_handle, operation_id, receipt_kind] {
            if field.is_empty()
                || field.len() > MAX_CONTEXT_FIELD_BYTES
                || field.chars().any(char::is_control)
            {
                return Err(ReleaseCommitmentError::Context);
            }
        }
        Ok(Self {
            task_id,
            resource_handle,
            operation_id,
            receipt_kind,
        })
    }
}

impl ReleaseCommitment {
    /// The audit-key version needed for later private verification.
    #[must_use]
    pub const fn key_version(&self) -> u32 {
        self.key_version
    }

    /// Hex encoding for a public redacted receipt. Never publish the key.
    #[must_use]
    pub fn hex(&self) -> String {
        hex::encode(self.mac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};

    #[test]
    fn short_private_values_are_keyed_and_context_separated() {
        let key = ReleaseCommitmentKey::new(3, Zeroizing::new([0x93; 32])).expect("audit key");
        let context = ReleaseCommitmentContext::new("task-1", "record-1", "read-1", "released")
            .expect("context");
        let first = key.commit(&context, b"Yes");
        assert_eq!(first.key_version(), 3);
        assert_ne!(first.hex(), hex::encode(Sha256::digest(b"Yes")));
        assert!(key.verify(&context, b"Yes", &first));
        assert!(!key.verify(&context, b"No", &first));
        let other_operation =
            ReleaseCommitmentContext::new("task-1", "record-1", "read-2", "released")
                .expect("context");
        assert_ne!(first, key.commit(&other_operation, b"Yes"));
        assert!(!key.verify(&other_operation, b"Yes", &first));
        let other_resource =
            ReleaseCommitmentContext::new("task-1", "record-2", "read-1", "released")
                .expect("context");
        assert_ne!(first, key.commit(&other_resource, b"Yes"));
        let other_kind = ReleaseCommitmentContext::new("task-1", "record-1", "read-1", "source")
            .expect("context");
        assert_ne!(first, key.commit(&other_kind, b"Yes"));
    }

    #[test]
    fn key_versions_and_contexts_fail_closed() {
        assert_eq!(
            ReleaseCommitmentKey::new(0, Zeroizing::new([1; 32])).err(),
            Some(ReleaseCommitmentError::Key)
        );
        assert_eq!(
            ReleaseCommitmentKey::new(1, Zeroizing::new([0; 32])).err(),
            Some(ReleaseCommitmentError::Key)
        );
        assert_eq!(
            ReleaseCommitmentContext::new("task", "", "op", "released"),
            Err(ReleaseCommitmentError::Context)
        );
        let context =
            ReleaseCommitmentContext::new("task", "resource", "op", "released").expect("context");
        let first = ReleaseCommitmentKey::new(1, Zeroizing::new([1; 32])).expect("key");
        let rotated = ReleaseCommitmentKey::new(2, Zeroizing::new([2; 32])).expect("key");
        let receipt = first.commit(&context, b"Approved");
        assert!(!rotated.verify(&context, b"Approved", &receipt));
        assert!(first.verify(&context, b"Approved", &receipt));
    }
}
