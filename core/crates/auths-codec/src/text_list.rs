//! Typed identifier-list codecs used by the canonical object codecs.
//!
//! Each expansion is an ordinary source function with a concrete model parser.
//! No function pointer or caller-supplied parser enters the production decoder.
//! The loop consumes at most the checked array length and stops at the first
//! text/model error, preserving that error and the decoder's exact cursor.

use crate::{
    CodecError,
    decode::{V1Decoder, array, text},
    encode::{V1Encoder, array as encode_array, text as encode_text},
};
use alloc::vec::Vec;

macro_rules! identifier_lists {
    ($($name:ident => $kind:ident),+ $(,)?) => {$ (
        pub(crate) fn $name(
            decoder: &mut V1Decoder<'_>,
            maximum: usize,
        ) -> Result<Vec<auths_model::$kind>, CodecError> {
            let length = array(decoder, maximum)?;
            let mut values = Vec::with_capacity(length);
            let mut remaining = length;
            let mut failure = None;
            while remaining > 0 && failure.is_none() {
                match text(decoder) {
                    Ok(value) => match auths_model::$kind::parse(value) {
                        Ok(value) => values.push(value),
                        Err(error) => failure = Some(CodecError::from(error)),
                    },
                    Err(error) => failure = Some(error),
                }
                remaining -= 1;
            }
            match failure {
                Some(error) => Err(error),
                None => Ok(values),
            }
        }
    )+};
}

identifier_lists! {
    principal_ids => PrincipalId,
    principal_methods => PrincipalMethodId,
    resource_ids => ResourceId,
    signature_suites => SignatureSuiteId,
    evidence_types => EvidenceTypeId,
    status_methods => StatusMethodId,
    assurance_claims => AssuranceClaimId,
    assurance_implications => AssuranceImplicationId,
    resource_matchers => ResourceMatcherId,
    budget_algebras => BudgetAlgebraId,
    extension_ids => ExtensionId,
    profile_policies => ProfilePolicyId,
    observation_schemas => ObservationSchemaId,
    audiences => Audience,
}

// These are concrete source functions rather than a string-projection
// callback. Array order, shortest encoding and first-error precedence remain
// owned by the same primitive writer used by the surrounding object.
macro_rules! identifier_list_writers {
    ($($name:ident => $kind:ident),+ $(,)?) => {$ (
        pub(crate) fn $name(
            encoder: &mut V1Encoder,
            values: &[auths_model::$kind],
        ) -> Result<(), CodecError> {
            encode_array(encoder, values.len())?;
            let mut position = 0;
            let mut failure = None;
            while position < values.len() && failure.is_none() {
                if let Err(error) = encode_text(encoder, values[position].as_str()) {
                    failure = Some(error);
                }
                position += 1;
            }
            match failure {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }
    )+};
}

identifier_list_writers! {
    encode_principal_ids => PrincipalId,
    encode_principal_methods => PrincipalMethodId,
    encode_resource_ids => ResourceId,
    encode_signature_suites => SignatureSuiteId,
    encode_evidence_types => EvidenceTypeId,
    encode_status_methods => StatusMethodId,
    encode_assurance_claims => AssuranceClaimId,
    encode_assurance_implications => AssuranceImplicationId,
    encode_resource_matchers => ResourceMatcherId,
    encode_budget_algebras => BudgetAlgebraId,
    encode_extension_ids => ExtensionId,
    encode_profile_policies => ProfilePolicyId,
    encode_observation_schemas => ObservationSchemaId,
    encode_audiences => Audience,
    encode_trust_anchor_ids => TrustAnchorId,
}

#[cfg(test)]
#[path = "text_list_tests.rs"]
mod tests;
