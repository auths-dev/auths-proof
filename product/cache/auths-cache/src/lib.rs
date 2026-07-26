//! Context-keyed bounded cache around the pure verifier.

#![forbid(unsafe_code)]

use auths_model::{CanonicalAction, ContextDigest, Digest, RegistryManifestId};
use auths_verifier::VerificationOutcome;
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    sync::Mutex,
};

/// Complete cache key. Evaluation time, status snapshots, assurance, trust,
/// and profile policy are committed by `context`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct VerificationCacheKey {
    proof: Digest,
    action: Digest,
    context: ContextDigest,
    registry_manifest: RegistryManifestId,
}

impl VerificationCacheKey {
    #[must_use]
    pub const fn new(
        proof: Digest,
        action: Digest,
        context: ContextDigest,
        registry_manifest: RegistryManifestId,
    ) -> Self {
        Self {
            proof,
            action,
            context,
            registry_manifest,
        }
    }
}

/// Computes the complete cache fingerprint of a profile-canonical action.
///
/// The fingerprint binds profile/version, media type, body, derived
/// permission, and optional stateful budget. It is intentionally distinct
/// from the body digest recorded by the proof.
#[must_use]
pub fn canonical_action_fingerprint(action: &CanonicalAction) -> Digest {
    let mut digest = Sha256::new();
    digest.update(b"AUTHS-APPS-CANONICAL-ACTION\x00\x01");
    hash_field(&mut digest, action.profile().id().as_str().as_bytes());
    digest.update(action.profile().version().to_be_bytes());
    hash_field(&mut digest, action.media_type().as_str().as_bytes());
    hash_field(&mut digest, action.body());
    hash_field(
        &mut digest,
        action.permission().capability().as_str().as_bytes(),
    );
    hash_field(
        &mut digest,
        action.permission().resource().as_str().as_bytes(),
    );
    if let Some(budget) = action.requested_budget() {
        digest.update([1]);
        hash_field(&mut digest, budget.algebra().as_str().as_bytes());
        digest.update(budget.value().to_be_bytes());
    } else {
        digest.update([0]);
    }
    Digest::new(digest.finalize().into())
}

fn hash_field(digest: &mut Sha256, bytes: &[u8]) {
    digest.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(bytes);
}

struct State {
    values: BTreeMap<VerificationCacheKey, VerificationOutcome>,
    order: VecDeque<VerificationCacheKey>,
}

/// Bounded deterministic FIFO verification cache.
pub struct VerificationCache {
    capacity: usize,
    state: Mutex<State>,
}

impl VerificationCache {
    /// Constructs a bounded cache.
    ///
    /// # Errors
    ///
    /// Returns a configuration error for zero or excessive capacity.
    pub fn new(capacity: usize) -> Result<Self, CacheError> {
        if capacity == 0 || capacity > 1_000_000 {
            return Err(CacheError);
        }
        Ok(Self {
            capacity,
            state: Mutex::new(State {
                values: BTreeMap::new(),
                order: VecDeque::new(),
            }),
        })
    }

    /// Returns a cloned sealed result for an exact complete key.
    #[must_use]
    pub fn get(&self, key: VerificationCacheKey) -> Option<VerificationOutcome> {
        self.state.lock().ok()?.values.get(&key).cloned()
    }

    /// Inserts or idempotently replaces an exact complete key.
    ///
    /// # Errors
    ///
    /// Returns an error if cache state is unavailable.
    pub fn insert(
        &self,
        key: VerificationCacheKey,
        outcome: VerificationOutcome,
    ) -> Result<(), CacheError> {
        let mut state = self.state.lock().map_err(|_| CacheError)?;
        if !state.values.contains_key(&key) {
            if state.values.len() == self.capacity {
                let oldest = state.order.pop_front().ok_or(CacheError)?;
                state.values.remove(&oldest);
            }
            state.order.push_back(key);
        }
        state.values.insert(key, outcome);
        Ok(())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.state.lock().map_or(0, |state| state.values.len())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Cache configuration or state failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheError;

impl fmt::Display for CacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Auths verification cache unavailable")
    }
}

impl std::error::Error for CacheError {}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_model::DenialReason;

    fn key(byte: u8) -> VerificationCacheKey {
        VerificationCacheKey::new(
            Digest::new([byte; 32]),
            Digest::new([byte.wrapping_add(1); 32]),
            ContextDigest::new([byte; 32]),
            RegistryManifestId::new([byte; 32]),
        )
    }

    #[test]
    fn complete_key_and_capacity_prevent_context_aliasing() {
        let cache = VerificationCache::new(1).unwrap();
        cache
            .insert(
                key(1),
                VerificationOutcome::Denied(DenialReason::AudienceMismatch),
            )
            .unwrap();
        assert!(cache.get(key(1)).is_some());
        assert!(cache.get(key(2)).is_none());
        cache
            .insert(
                key(2),
                VerificationOutcome::Denied(DenialReason::ChallengeMismatch),
            )
            .unwrap();
        assert!(cache.get(key(1)).is_none());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn byte_distinct_actions_never_alias() {
        let cache = VerificationCache::new(2).unwrap();
        let first = VerificationCacheKey::new(
            Digest::new([1; 32]),
            Digest::new([2; 32]),
            ContextDigest::new([3; 32]),
            RegistryManifestId::new([4; 32]),
        );
        let second = VerificationCacheKey::new(
            Digest::new([1; 32]),
            Digest::new([9; 32]),
            ContextDigest::new([3; 32]),
            RegistryManifestId::new([4; 32]),
        );
        cache
            .insert(
                first,
                VerificationOutcome::Denied(DenialReason::AudienceMismatch),
            )
            .unwrap();
        assert!(cache.get(second).is_none());
    }
}
