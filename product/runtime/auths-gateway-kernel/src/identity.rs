//! Bounded logical-operation token validation and exact replay-key preimages.
//! Hashing remains a separately specified primitive; these leaves contain no
//! credential, challenge, actor, recipe, case-version or process input.
use crate::construct::{append_bytes, copy_bytes, is_alphanumeric};
use alloc::vec::Vec;

/// Validates the canonical ASCII token grammar used by operator namespaces
/// and logical operation IDs: an initial alphanumeric byte followed by
/// alphanumerics, dots, underscores or hyphens, within the supplied byte bound.
#[must_use]
pub fn valid_token(value: &[u8], maximum: usize) -> bool {
    if value.is_empty() || value.len() > maximum {
        return false;
    }
    let mut position = 0;
    let mut valid = true;
    while position < value.len() && valid {
        let byte = value[position];
        valid = is_alphanumeric(byte)
            || (position > 0 && (byte == b'.' || byte == b'_' || byte == b'-'));
        position += 1;
    }
    valid
}

/// The precise bytes hashed for a logical operation. The shipping caller
/// supplies validated 1–64-byte and 1–128-byte tokens, respectively; their
/// NUL-free grammar makes the separator unambiguous.
#[must_use]
pub fn logical_operation_preimage(namespace: &[u8], operation: &[u8]) -> Vec<u8> {
    let mut output = copy_bytes(b"auths.gateway-logical-operation/1\0");
    output = append_bytes(output, namespace);
    output.push(0);
    append_bytes(output, operation)
}

/// Exact domain-separated bytes hashed for a gateway connection key.
/// The shipping caller supplies validated provider and alias tokens of at most
/// 64 bytes each. Their NUL-free grammar makes the separator unambiguous.
#[must_use]
pub fn connection_record_preimage(provider: &[u8], alias: &[u8]) -> Vec<u8> {
    let mut output = copy_bytes(b"auths.gateway-connection/1\0");
    output = append_bytes(output, provider);
    output.push(0);
    append_bytes(output, alias)
}

#[cfg(test)]
mod tests {
    use super::{connection_record_preimage, logical_operation_preimage, valid_token};
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn exact_frozen_preimage_for_binary_components() {
        for first in 0..=u8::MAX {
            for second in 0..=u8::MAX {
                let provider = [first, second];
                let alias = [second, first];
                for p_len in 0..=2 {
                    for a_len in 0..=2 {
                        let mut expected = Vec::from(b"auths.gateway-connection/1\0".as_slice());
                        expected.extend_from_slice(&provider[..p_len]);
                        expected.push(0);
                        expected.extend_from_slice(&alias[..a_len]);
                        assert_eq!(
                            connection_record_preimage(&provider[..p_len], &alias[..a_len]),
                            expected
                        );
                    }
                }
            }
        }
    }

    fn reference(value: &[u8], maximum: usize) -> bool {
        !value.is_empty()
            && value.len() <= maximum
            && value.is_ascii()
            && value.iter().enumerate().all(|(index, byte)| {
                byte.is_ascii_alphanumeric() || (index > 0 && matches!(*byte, b'.' | b'_' | b'-'))
            })
    }

    #[test]
    fn token_validation_matches_the_independent_ascii_oracle() {
        for first in 0_u8..=255 {
            for second in 0_u8..=255 {
                for maximum in [0, 1, 2, 64, 128] {
                    assert_eq!(
                        valid_token(&[first, second], maximum),
                        reference(&[first, second], maximum)
                    );
                }
            }
            assert_eq!(valid_token(&[first], 1), reference(&[first], 1));
        }
        for length in [0, 1, 63, 64, 65, 127, 128, 129, 512] {
            let bytes = vec![b'a'; length];
            for maximum in [0, 64, 128] {
                assert_eq!(valid_token(&bytes, maximum), reference(&bytes, maximum));
            }
        }
    }

    #[test]
    fn operation_preimage_preserves_the_existing_framing() {
        let mut expected = Vec::from(b"auths.gateway-logical-operation/1\0".as_slice());
        expected.extend_from_slice(b"operator");
        expected.push(0);
        expected.extend_from_slice(b"payment-1");
        assert_eq!(
            logical_operation_preimage(b"operator", b"payment-1"),
            expected
        );
    }
}
