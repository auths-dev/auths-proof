//! Deterministic CBOR, domain separation, and content identifiers for Auths
//! Proof Protocol V1.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod decode;
mod encode;
mod error;
mod hash;

pub use decode::{
    decode_action_envelope, decode_bundle, decode_canonical_action, decode_grant_statement,
    decode_grant_status_statement, decode_principal_status_statement, decode_verification_result,
    decode_verifier_context,
};
pub use encode::{
    encode_action_envelope, encode_action_signing_input, encode_authorization_plan, encode_bundle,
    encode_canonical_action, encode_grant_signing_input, encode_grant_statement,
    encode_grant_status_signing_input, encode_grant_status_statement,
    encode_principal_status_signing_input, encode_principal_status_statement, encode_signed_action,
    encode_signed_grant, encode_signed_grant_status, encode_signed_principal_status,
    encode_verification_result, encode_verifier_context,
};
pub use error::CodecError;
pub use hash::{
    action_id, action_signing_preimage, attachment_digest, body_digest, context_digest,
    evidence_id, grant_id, grant_signing_preimage, grant_status_id, grant_status_signing_preimage,
    plan_id, principal_status_id, principal_status_signing_preimage, proof_digest,
    verification_result_digest,
};
