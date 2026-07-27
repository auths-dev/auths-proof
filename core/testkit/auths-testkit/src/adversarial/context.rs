use crate::adversarial::{ByteMutation, Mutation};
use auths_codec::{decode_verifier_context, encode_verifier_context};

/// Verifies the target V1 canonical round-trip invariant.
///
/// # Errors
///
/// Returns the codec's stable string projection when decoding or re-encoding
/// fails, or when the accepted bytes are not canonical.
pub fn assert_canonical_context(bytes: &[u8]) -> Result<(), String> {
    let decoded = decode_verifier_context(bytes).map_err(|error| error.to_string())?;
    let encoded = encode_verifier_context(&decoded).map_err(|error| error.to_string())?;
    if encoded == bytes {
        Ok(())
    } else {
        Err("accepted verifier context was not canonical".to_owned())
    }
}

/// Produces one deterministic single-bit mutation for every input byte.
///
/// # Panics
///
/// Panics only if an internally generated mutation identifier or in-bounds
/// offset violates the mutation constructor's invariant.
#[must_use]
pub fn context_bit_mutations(bytes: &[u8]) -> Vec<Vec<u8>> {
    let seed = bytes.to_vec();
    (0..bytes.len())
        .map(|offset| {
            ByteMutation::new(format!("bitflip-{offset}"), offset, 1)
                .expect("generated identifier and mask are valid")
                .apply(&seed)
                .expect("generated offset is in range")
        })
        .collect()
}
