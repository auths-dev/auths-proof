//! Exact echo/idempotency preimages and lowercase hexadecimal token bytes.
//! SHA-256 remains the native caller's separately specified primitive. An
//! echo binds the action commitment; idempotency intentionally binds only the
//! operator namespace and logical operation, so a new proof cannot mint a key.

use alloc::vec::Vec;
use crate::construct::{append_bytes, copy_bytes, hex_lower};

/// Exact bytes hashed for a gateway echo. Native callers supply validated
/// 1–64-byte and 1–128-byte NUL-free namespace/operation tokens. The final
/// commitment is always 32 bytes; no challenge or credential is substituted.
#[must_use]
pub fn echo_preimage(namespace: &[u8], operation: &[u8], commitment: &[u8; 32]) -> Vec<u8> {
    let mut output = copy_bytes(b"auths.gateway-echo/1\0");
    output = append_bytes(output, namespace);
    output.push(0);
    output = append_bytes(output, operation);
    output.push(0);
    append_bytes(output, commitment)
}

/// Exact bytes hashed for a provider idempotency key. Only the validated
/// namespace and logical operation enter this preimage.
#[must_use]
pub fn idempotency_preimage(namespace: &[u8], operation: &[u8]) -> Vec<u8> {
    let mut output = copy_bytes(b"auths.gateway-idempotency-key/1\0");
    output = append_bytes(output, namespace);
    output.push(0);
    append_bytes(output, operation)
}

/// Appends the exact 64-byte lowercase hexadecimal spelling of a digest.
/// All byte inputs are admitted; there is no locale or formatter dependency.
#[must_use]
pub fn append_digest_hex(mut output: Vec<u8>, digest: &[u8; 32]) -> Vec<u8> {
    let mut position = 0;
    while position < digest.len() {
        let byte = digest[position];
        output.push(hex_lower(byte / 16));
        output.push(hex_lower(byte % 16));
        position += 1;
    }
    output
}

/// The exact 73 ASCII bytes `auths-e1-` followed by the digest's lowercase hex.
#[must_use]
pub fn echo_token_bytes(digest: &[u8; 32]) -> Vec<u8> {
    append_digest_hex(copy_bytes(b"auths-e1-"), digest)
}

/// The exact 73 ASCII bytes `auths-i1-` followed by the digest's lowercase hex.
#[must_use]
pub fn idempotency_token_bytes(digest: &[u8; 32]) -> Vec<u8> {
    append_digest_hex(copy_bytes(b"auths-i1-"), digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::String;

    fn reference_hex(digest: &[u8; 32]) -> String {
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn every_byte_in_every_digest_position_matches_the_independent_formatter() {
        for position in 0..32 {
            for byte in 0_u8..=255 {
                let mut digest = [0; 32];
                digest[position] = byte;
                let hex = reference_hex(&digest);
                let echo = echo_token_bytes(&digest);
                let idempotency = idempotency_token_bytes(&digest);
                assert_eq!(echo, format!("auths-e1-{hex}").into_bytes());
                assert_eq!(idempotency, format!("auths-i1-{hex}").into_bytes());
                assert_eq!(echo.len(), 73);
                assert_eq!(idempotency.len(), 73);
                assert!(echo.is_ascii());
                assert_ne!(echo, idempotency);
            }
        }
    }

    #[test]
    fn frozen_preimages_keep_every_separator_and_commitment_byte() {
        for namespace in [b"".as_slice(), b"operator", b"a\0b"] {
            for operation in [b"".as_slice(), b"operation-1", b"x\0y"] {
                for byte in [0, 1, 127, 255] {
                    let commitment = [byte; 32];
                    let mut echo = b"auths.gateway-echo/1\0".to_vec();
                    echo.extend_from_slice(namespace);
                    echo.push(0);
                    echo.extend_from_slice(operation);
                    echo.push(0);
                    echo.extend_from_slice(&commitment);
                    assert_eq!(echo_preimage(namespace, operation, &commitment), echo);
                    let mut idempotency = b"auths.gateway-idempotency-key/1\0".to_vec();
                    idempotency.extend_from_slice(namespace);
                    idempotency.push(0);
                    idempotency.extend_from_slice(operation);
                    assert_eq!(idempotency_preimage(namespace, operation), idempotency);
                }
            }
        }
    }
}
