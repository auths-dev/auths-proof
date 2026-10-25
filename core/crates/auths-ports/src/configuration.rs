//! Canonical adapter-configuration framing and its one-shot SHA-256 boundary.

use alloc::vec::Vec;
use auths_model::AdapterConfigurationId;
use sha2::{Digest as _, Sha256};

const PREFIX: &[u8] = b"auths-proof-adapter-configuration-v1";

/// Computes a domain-separated commitment to ordered immutable components.
/// Iterator callers are buffered as slice references and use the same framing
/// and hash operation as [`configuration_id_from_parts`].
#[must_use]
pub fn configuration_id<'a>(domain: &[u8], components: impl IntoIterator<Item = &'a [u8]>) -> AdapterConfigurationId {
    let parts: Vec<_> = components.into_iter().collect();
    configuration_id_from_parts(domain, &parts)
}

/// Computes the configuration commitment from explicit ordered byte slices.
///
/// The frame is the fixed V1 domain, the domain length/value, then each component
/// length/value. Lengths are big-endian u64 and empty components remain present.
/// The declared production components are bounded; allocation, compiler and
/// primitive SHA-256 contracts remain explicit assurance boundaries.
#[must_use]
pub fn configuration_id_from_parts(domain: &[u8], components: &[&[u8]]) -> AdapterConfigurationId {
    let bytes = preimage(domain, components);
    AdapterConfigurationId::new(Sha256::digest(bytes.as_slice()).into())
}

pub(crate) fn preimage(domain: &[u8], components: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(PREFIX);
    append_component(&mut output, domain);
    let mut position = 0;
    while position < components.len() {
        append_component(&mut output, components[position]);
        position += 1;
    }
    output
}
fn append_component(output: &mut Vec<u8>, component: &[u8]) {
    output.extend_from_slice(&u64::try_from(component.len()).unwrap_or(u64::MAX).to_be_bytes());
    output.extend_from_slice(component);
}

#[cfg(test)]
#[path = "configuration_reference.rs"]
mod reference;
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn one_shot_frame_matches_the_complete_original_stream() {
        for domain_length in [0, 1, 23, 24, 127, 128, 255, 256, 1024] {
            let domain = vec![b'd'; domain_length];
            for first in [0, 1, 31, 32, 255, 256] {
                for second in [0, 1, 32, 257] {
                    let a = vec![b'a'; first];
                    let b = vec![b'b'; second];
                    for parts in [vec![], vec![a.as_slice()], vec![a.as_slice(), b.as_slice()]] {
                        let expected = reference::configuration_id(&domain, parts.iter().copied());
                        assert_eq!(configuration_id_from_parts(&domain, &parts), expected);
                        assert_eq!(configuration_id(&domain, parts.iter().copied()), expected);
                    }
                }
            }
        }
    }

    #[test]
    fn empty_components_order_and_boundaries_are_retained() {
        assert_ne!(preimage(b"adapter", &[]), preimage(b"adapter", &[b""]));
        assert_ne!(preimage(b"adapter", &[b"a", b"bc"]), preimage(b"adapter", &[b"ab", b"c"]));
        assert_ne!(preimage(b"adapter", &[b"a", b"b"]), preimage(b"adapter", &[b"b", b"a"]));
        let frame = preimage(b"x", &[b"yz"]);
        let mut expected = PREFIX.to_vec();
        expected.extend_from_slice(&1u64.to_be_bytes());
        expected.extend_from_slice(b"x");
        expected.extend_from_slice(&2u64.to_be_bytes());
        expected.extend_from_slice(b"yz");
        assert_eq!(frame, expected);
    }
}
