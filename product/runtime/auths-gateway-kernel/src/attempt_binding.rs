//! Exact installation/request and durable-claim/request identity binding.
//! These comparisons grant no verification, approval, backend acknowledgement
//! or execution authority. Their callers retain the native typed capabilities.

use crate::construct::field_name_equal;
use crate::recipe_binding::schema_digest_matches;
use crate::transition::Stage;

/// The original immutable identity columns of a durable attempt record.
#[derive(Clone, Copy, Debug)]
pub struct StoredClaim<'a> {
    /// Exact stored namespace bytes.
    pub namespace: &'a [u8],
    /// Exact stored logical operation bytes.
    pub operation: &'a [u8],
    /// Canonical lowercase spelling of the mapping digest.
    pub recipe_hex: &'a [u8],
    /// Canonical lowercase spelling of the verified action commitment.
    pub action_hex: &'a [u8],
    /// Original native verification timestamp retained by the claim.
    pub evaluated_at: u64,
}

/// Identity from one immutable closed request and its captured verification.
#[derive(Clone, Copy, Debug)]
pub struct RequestClaim<'a> {
    /// Namespace from this request.
    pub namespace: &'a [u8],
    /// Logical operation from this request.
    pub operation: &'a [u8],
    /// The recipe digest retained by this request's compiler constructor.
    pub recipe_digest: &'a [u8; 32],
    /// The exact action commitment from the same request.
    pub action_commitment: &'a [u8; 32],
    /// Timestamp captured with this request's verified command.
    pub evaluated_at: u64,
}

/// Compares a request's own mapping and namespace with the pinned installation.
/// All components are public identity bytes; no normalization or hash
/// collision assumption is used by this equality check.
#[must_use]
pub fn installation_matches(
    namespace: &[u8], recipe_digest: &[u8; 32],
    installed_namespace: &[u8], installed_digest: &[u8; 32],
) -> bool {
    field_name_equal(namespace, installed_namespace)
        && field_name_equal(recipe_digest, installed_digest)
}

/// Checks every request/verification identity field of an entry-capable claim.
/// Other durable stages, substituted names, mapping/action commitments or
/// verification times refuse. The native caller must additionally retain the
/// acknowledged owning handle and exact backend context; record equality is
/// not proof of a winning claim or atomic counter reservation.
#[must_use]
pub fn claim_matches(stage: Stage, stored: StoredClaim<'_>, request: RequestClaim<'_>) -> bool {
    match stage {
        Stage::Attempting => {
            stored.evaluated_at == request.evaluated_at
                && field_name_equal(stored.namespace, request.namespace)
                && field_name_equal(stored.operation, request.operation)
                && schema_digest_matches(stored.recipe_hex, request.recipe_digest)
                && schema_digest_matches(stored.action_hex, request.action_commitment)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, string::String};

    fn hex(bytes: &[u8; 32]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }

    #[test]
    fn installed_recipe_and_namespace_are_compared_in_full() {
        let digest = [7; 32];
        assert!(installation_matches(b"operator", &digest, b"operator", &digest));
        for namespace in [b"".as_slice(), b"Operator", b"operator-suffix", b"operato"] {
            assert!(!installation_matches(namespace, &digest, b"operator", &digest));
        }
        for position in 0..32 {
            for byte in 0_u8..=255 {
                let mut supplied = digest;
                supplied[position] = byte;
                assert_eq!(installation_matches(b"operator", &supplied, b"operator", &digest), byte == 7);
            }
        }
    }

    #[test]
    fn every_claim_identity_component_and_stage_binds_to_the_same_request() {
        let recipe = [8; 32];
        let action = [9; 32];
        let recipe_hex = hex(&recipe);
        let action_hex = hex(&action);
        let request = RequestClaim { namespace: b"operator", operation: b"operation", recipe_digest: &recipe,
            action_commitment: &action, evaluated_at: 42 };
        let stored = StoredClaim { namespace: b"operator", operation: b"operation", recipe_hex: recipe_hex.as_bytes(),
            action_hex: action_hex.as_bytes(), evaluated_at: 42 };
        assert!(claim_matches(Stage::Attempting, stored, request));
        for stage in [Stage::NotEntered, Stage::Unknown, Stage::ResponseRecorded, Stage::Observed, Stage::ObservedByProvider] {
            assert!(!claim_matches(stage, stored, request));
        }
        for changed in [
            StoredClaim { namespace: b"operator-suffix", ..stored },
            StoredClaim { operation: b"operation-suffix", ..stored },
            StoredClaim { recipe_hex: b"", ..stored },
            StoredClaim { action_hex: b"", ..stored },
            StoredClaim { evaluated_at: 0, ..stored },
            StoredClaim { evaluated_at: u64::MAX, ..stored },
        ] { assert!(!claim_matches(Stage::Attempting, changed, request)); }
        for position in 0..32 {
            for byte in 0_u8..=255 {
                let mut changed = recipe;
                changed[position] = byte;
                assert_eq!(claim_matches(Stage::Attempting, stored, RequestClaim { recipe_digest: &changed, ..request }), byte == 8);
                let mut changed = action;
                changed[position] = byte;
                assert_eq!(claim_matches(Stage::Attempting, stored, RequestClaim { action_commitment: &changed, ..request }), byte == 9);
            }
        }
        assert!(!claim_matches(Stage::Attempting, StoredClaim { recipe_hex: b"080808080808080808080808080808080808080808080808080808080808080A", ..stored }, request));
        assert!(!claim_matches(Stage::Attempting, stored, RequestClaim { evaluated_at: 43, ..request }));
    }
}
