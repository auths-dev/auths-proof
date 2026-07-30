//! Shared Stripe-local commitments that always include the exact profile.

use serde::Serialize;

use super::{
    MerchantValidationError, PAYMENT_AUTHORIZE_PROFILE, PAYMENT_CAPTURE_PROFILE,
    PAYMENT_COLLECT_PROFILE, PAYMENT_STATEMENT_DESCRIPTOR, valid_local_id, valid_workflow_id,
};
use crate::{
    canonical::{canonical_digest, sha256},
    types::DigestHex,
};

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_field_names,
    reason = "field names must exactly match the fixed auths_* Stripe metadata keys"
)]
struct FixedMerchantMetadata<'a> {
    auths_profile: &'a str,
    auths_order_scope: &'a str,
    auths_policy: &'a DigestHex,
    auths_workflow: &'a str,
}

/// Computes fixed provider metadata for one exact profile and workflow.
///
/// # Errors
///
/// Rejects malformed workflow, profile, order, or canonicalization.
pub fn fixed_merchant_metadata_commitment(
    workflow_id: &str,
    profile: &str,
    order_scope: &str,
    policy_digest: &DigestHex,
) -> Result<DigestHex, MerchantValidationError> {
    if !valid_workflow_id(workflow_id)
        || !matches!(
            profile,
            PAYMENT_COLLECT_PROFILE | PAYMENT_AUTHORIZE_PROFILE | PAYMENT_CAPTURE_PROFILE
        )
        || !valid_local_id(order_scope)
    {
        return Err(MerchantValidationError::InvalidAction);
    }
    canonical_digest(&FixedMerchantMetadata {
        auths_profile: profile,
        auths_order_scope: order_scope,
        auths_policy: policy_digest,
        auths_workflow: workflow_id,
    })
    .map_err(|_| MerchantValidationError::Canonicalization)
}

/// Exact protected statement-descriptor commitment.
#[must_use]
pub fn merchant_statement_descriptor_commitment() -> DigestHex {
    sha256(PAYMENT_STATEMENT_DESCRIPTOR.as_bytes())
}
