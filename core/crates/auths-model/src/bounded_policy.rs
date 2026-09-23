//! Bounded-policy commitments carried by grants.
//!
//! A grant may carry the `bounded-policy-commitment-v1` critical extension:
//! a commitment to one closed product-layer policy and evaluator, the
//! canonical policy bytes it opens to, and, when the grant narrows a parent
//! grant's bound, the digest of that parent's extension bytes. Core validates
//! only the shape and the parent link; what the policy means, and whether a
//! child policy is tighter than its parent's, is the registered product
//! evaluator's question.

use crate::{Digest, ModelError, byte_slices_equal};
use alloc::string::String;
use alloc::vec::Vec;

/// Maximum canonical policy bytes carried in one commitment.
pub const MAX_BOUNDED_POLICY_BYTES: usize = 4_096;
/// Maximum bytes of a policy type or evaluator semantic identifier.
pub const MAX_POLICY_IDENTIFIER_BYTES: usize = 128;
/// Maximum bytes of a policy canonicalization identifier.
pub const MAX_POLICY_CANONICALIZATION_BYTES: usize = 64;
/// Commitment domain of the policy digest over the carried policy bytes.
pub const BOUNDED_POLICY_DIGEST_DOMAIN: &str = "auths.bounded-policy.v1";
/// Commitment domain of a child's link to its parent's extension bytes.
pub const BOUNDED_POLICY_LINK_DOMAIN: &str = "auths.bounded-policy-commitment.v1";

/// A closed-vocabulary ASCII identifier: letters, digits, and `. / : _ -`.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PolicyIdentifier(String);

impl PolicyIdentifier {
    /// Parses one identifier of at most `maximum` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidBoundedPolicy`] for an empty or oversized
    /// value or a byte outside the closed vocabulary.
    pub fn parse(value: &str, maximum: usize) -> Result<Self, ModelError> {
        if value.is_empty()
            || value.len() > maximum
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b':' | b'_' | b'-')
            })
        {
            return Err(ModelError::InvalidBoundedPolicy);
        }
        Ok(Self(String::from(value)))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Immutable commitment to one closed policy and its evaluator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyCommitment {
    policy_type: PolicyIdentifier,
    policy_version: u16,
    canonicalization_id: PolicyIdentifier,
    policy_digest: Digest,
    evaluator_semantic_id: PolicyIdentifier,
}

impl PolicyCommitment {
    /// Constructs a commitment.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidBoundedPolicy`] for version zero or an
    /// identifier over its bound.
    pub fn new(
        policy_type: PolicyIdentifier,
        policy_version: u16,
        canonicalization_id: PolicyIdentifier,
        policy_digest: Digest,
        evaluator_semantic_id: PolicyIdentifier,
    ) -> Result<Self, ModelError> {
        if policy_version == 0
            || policy_type.0.len() > MAX_POLICY_IDENTIFIER_BYTES
            || canonicalization_id.0.len() > MAX_POLICY_CANONICALIZATION_BYTES
            || evaluator_semantic_id.0.len() > MAX_POLICY_IDENTIFIER_BYTES
        {
            return Err(ModelError::InvalidBoundedPolicy);
        }
        Ok(Self {
            policy_type,
            policy_version,
            canonicalization_id,
            policy_digest,
            evaluator_semantic_id,
        })
    }

    #[must_use]
    pub const fn policy_type(&self) -> &PolicyIdentifier {
        &self.policy_type
    }

    #[must_use]
    pub const fn policy_version(&self) -> u16 {
        self.policy_version
    }

    #[must_use]
    pub const fn canonicalization_id(&self) -> &PolicyIdentifier {
        &self.canonicalization_id
    }

    #[must_use]
    pub const fn policy_digest(&self) -> Digest {
        self.policy_digest
    }

    #[must_use]
    pub const fn evaluator_semantic_id(&self) -> &PolicyIdentifier {
        &self.evaluator_semantic_id
    }
}

/// The body of one `bounded-policy-commitment-v1` extension.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedPolicyCommitment {
    commitment: PolicyCommitment,
    policy: Vec<u8>,
    parent: Option<Digest>,
}

impl BoundedPolicyCommitment {
    /// Constructs a body. The caller opens `policy` against the commitment's
    /// digest; the codec does so for every decoded body.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidBoundedPolicy`] for empty policy bytes and
    /// [`ModelError::CollectionLimitExceeded`] above
    /// [`MAX_BOUNDED_POLICY_BYTES`].
    pub fn new(
        commitment: PolicyCommitment,
        policy: Vec<u8>,
        parent: Option<Digest>,
    ) -> Result<Self, ModelError> {
        if policy.is_empty() {
            return Err(ModelError::InvalidBoundedPolicy);
        }
        if policy.len() > MAX_BOUNDED_POLICY_BYTES {
            return Err(ModelError::CollectionLimitExceeded);
        }
        Ok(Self {
            commitment,
            policy,
            parent,
        })
    }

    #[must_use]
    pub const fn commitment(&self) -> &PolicyCommitment {
        &self.commitment
    }

    #[must_use]
    pub fn policy(&self) -> &[u8] {
        &self.policy
    }

    /// The digest of the parent grant's extension bytes, when this bound
    /// narrows a parent's.
    #[must_use]
    pub const fn parent(&self) -> Option<&Digest> {
        self.parent.as_ref()
    }
}

/// Exact digest equality used by production and extraction.
#[doc(hidden)]
#[must_use]
pub fn digest_equal(left: &Digest, right: &Digest) -> bool {
    byte_slices_equal(left.as_bytes(), right.as_bytes())
}

/// The kernel's bounded-policy link law. `child_link` is the parent digest the
/// child body carries; `parent_digest` is the digest of the parent's
/// extension bytes when the parent carries the extension. A child that keeps
/// the extension must link exactly its parent's bytes; a child that adds the
/// extension to an unbounded parent must carry no link.
#[doc(hidden)]
#[must_use]
pub fn bounded_policy_link_accepts(
    child_link: Option<&Digest>,
    parent_digest: Option<&Digest>,
) -> bool {
    match child_link {
        Some(child_link) => match parent_digest {
            Some(parent_digest) => digest_equal(child_link, parent_digest),
            None => false,
        },
        None => parent_digest.is_none(),
    }
}
