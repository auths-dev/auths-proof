//! Protocol-neutral canonical signature verification semantics.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

use core::fmt;
use ed25519_dalek::{Signature, VerifyingKey};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256Key, signature::Verifier as _};

/// Auths-defined Ed25519 suite identifier.
pub const ED25519_V1: &str = "ed25519-v1";
/// Auths-defined P-256/SHA-256 suite identifier.
pub const P256_SHA256_V1: &str = "p256-sha256-v1";
const P256_KEY_LEN: usize = 33;

/// RFC 8032 field and negative-zero encoding rules; point validity is separate.
fn ed25519_point_encoding_is_canonical(encoded: &[u8; 32]) -> bool {
    let top = encoded[31] & 0x7f;
    let mut all_max = top == 0x7f;
    let mut all_zero = top == 0;
    // The qualified scan uses this explicit fixed range; its refinement proves
    // every array read in bounds. Keep the index representation shared with it.
    #[expect(
        clippy::needless_range_loop,
        reason = "the source-linked bounded-scan proof uses this explicit index range"
    )]
    for index in 1..31 {
        all_max &= encoded[index] == 0xff;
        all_zero &= encoded[index] == 0;
    }
    if all_max && encoded[0] >= 0xed {
        return false;
    }
    let sign = encoded[31] & 0x80 != 0;
    if sign && ((all_zero && encoded[0] == 1) || (all_max && encoded[0] == 0xec)) {
        return false;
    }
    true
}

/// The Auths P-256 compressed SEC1 form; curve-point decoding is separate.
fn p256_key_encoding_is_canonical(encoded: &[u8]) -> bool {
    if encoded.len() != P256_KEY_LEN {
        return false;
    }
    encoded[0] == 0x02 || encoded[0] == 0x03
}

// SEC 2 secp256r1 subgroup order divided by two, in big-endian form.
const P256_HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

fn p256_signature_is_low_s(encoded: &[u8; 64]) -> bool {
    let mut index = 0;
    while index < 32 {
        let value = encoded[32 + index];
        let bound = P256_HALF_ORDER[index];
        if value < bound {
            return true;
        }
        if value > bound {
            return false;
        }
        index += 1;
    }
    true
}

fn ed25519_same_coordinate(encoded: &[u8; 32], expected: &[u8; 32]) -> bool {
    if encoded[31] & 0x7f != expected[31] & 0x7f {
        return false;
    }
    let mut index = 0;
    while index < 31 {
        if encoded[index] != expected[index] {
            return false;
        }
        index += 1;
    }
    true
}

const ED25519_WEAK_ZERO: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const ED25519_WEAK_ONE: [u8; 32] = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const ED25519_WEAK_MINUS_ONE: [u8; 32] = [
    0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

const ED25519_WEAK_ORDER_EIGHT_A: [u8; 32] = [
    0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
    0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
];

const ED25519_WEAK_ORDER_EIGHT_B: [u8; 32] = [
    0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
    0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
];

fn ed25519_has_small_order_coordinate(encoded: &[u8; 32]) -> bool {
    ed25519_same_coordinate(encoded, &ED25519_WEAK_ZERO)
        || ed25519_same_coordinate(encoded, &ED25519_WEAK_ONE)
        || ed25519_same_coordinate(encoded, &ED25519_WEAK_MINUS_ONE)
        || ed25519_same_coordinate(encoded, &ED25519_WEAK_ORDER_EIGHT_A)
        || ed25519_same_coordinate(encoded, &ED25519_WEAK_ORDER_EIGHT_B)
}

fn ed25519_signature_r_is_allowed(encoded: &[u8; 64]) -> bool {
    let r: &[u8; 32] = match encoded[..32].try_into() {
        Ok(r) => r,
        Err(_) => return false,
    };
    ed25519_point_encoding_is_canonical(r) && !ed25519_has_small_order_coordinate(r)
}

/// Failure classes shared by every Ed25519 protocol adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ed25519Error {
    /// The verification key is not one canonical Ed25519 public key.
    InvalidKey,
    /// The signature is not one canonical fixed-width Ed25519 signature.
    InvalidSignatureEncoding,
    /// The signature does not authenticate the exact supplied message.
    VerificationFailed,
}

impl fmt::Display for Ed25519Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidKey => "invalid Ed25519 verification key",
            Self::InvalidSignatureEncoding => "invalid Ed25519 signature encoding",
            Self::VerificationFailed => "Ed25519 verification failed",
        })
    }
}

impl core::error::Error for Ed25519Error {}

/// Failure classes shared by every P-256/SHA-256 protocol adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P256Error {
    /// The verification key is not one 33-byte compressed SEC1 P-256 point with tag `0x02` or
    /// `0x03`.
    InvalidKey,
    /// The signature is not one canonical fixed-width P-256 signature.
    InvalidSignatureEncoding,
    /// The signature is high-S or does not authenticate the exact supplied message.
    VerificationFailed,
}

impl fmt::Display for P256Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidKey => "invalid P-256 verification key",
            Self::InvalidSignatureEncoding => "invalid P-256 signature encoding",
            Self::VerificationFailed => "P-256/SHA-256 verification failed",
        })
    }
}

impl core::error::Error for P256Error {}

/// Validates one canonical Ed25519 public key.
///
/// # Errors
///
/// Rejects malformed Ed25519 verification material.
pub fn validate_ed25519_key(verification_key: &[u8]) -> Result<(), Ed25519Error> {
    decode_ed25519_key(verification_key).map(|_| ())
}

fn ed25519_key_encoding(bytes: &[u8]) -> Result<&[u8; 32], Ed25519Error> {
    let Ok(bytes) = bytes.try_into() else {
        return Err(Ed25519Error::InvalidKey);
    };
    if !ed25519_point_encoding_is_canonical(bytes) {
        return Err(Ed25519Error::InvalidKey);
    }
    Ok(bytes)
}

fn decode_ed25519_key_with<K, D>(bytes: &[u8], decode: D) -> Result<K, Ed25519Error>
where
    D: FnOnce(&[u8; 32]) -> Option<K>,
{
    let bytes = ed25519_key_encoding(bytes)?;
    match decode(bytes) {
        Some(key) => Ok(key),
        None => Err(Ed25519Error::InvalidKey),
    }
}

fn decode_ed25519_point(bytes: &[u8; 32]) -> Option<VerifyingKey> {
    VerifyingKey::from_bytes(bytes).ok()
}

#[expect(
    clippy::redundant_closure,
    reason = "explicit closure dictionaries are supported by the qualified Rust-to-Lean backend"
)]
fn decode_ed25519_key(bytes: &[u8]) -> Result<VerifyingKey, Ed25519Error> {
    decode_ed25519_key_with(bytes, |encoded| decode_ed25519_point(encoded))
}

fn verify_ed25519_with<K, D, V>(
    bytes: &[u8],
    message: &[u8],
    signature: &[u8],
    decode: D,
    verify: V,
) -> Result<(), Ed25519Error>
where
    D: FnOnce(&[u8; 32]) -> Option<K>,
    V: FnOnce(&K, &[u8], &[u8; 64]) -> bool,
{
    let bytes = ed25519_key_encoding(bytes)?;
    let Some(key) = decode(bytes) else {
        return Err(Ed25519Error::InvalidKey);
    };
    let signature: &[u8; 64] = match signature.try_into() {
        Ok(signature) => signature,
        Err(_) => return Err(Ed25519Error::InvalidSignatureEncoding),
    };
    if ed25519_has_small_order_coordinate(bytes) || !ed25519_signature_r_is_allowed(signature) {
        return Err(Ed25519Error::VerificationFailed);
    }
    if verify(&key, message, signature) {
        Ok(())
    } else {
        Err(Ed25519Error::VerificationFailed)
    }
}

fn verify_ed25519_equation(key: &VerifyingKey, message: &[u8], signature: &[u8; 64]) -> bool {
    key.verify_strict(message, &Signature::from_bytes(signature))
        .is_ok()
}

/// Verifies an Ed25519 signature with the repository's one strict implementation.
///
/// This primitive assigns no protocol meaning to `message`; each caller remains responsible for
/// constructing its own domain-separated signing preimage.
///
/// # Errors
///
/// Distinguishes malformed keys, malformed signature encodings, and cryptographic failure.
#[expect(
    clippy::redundant_closure,
    reason = "explicit closure dictionaries are supported by the qualified Rust-to-Lean backend"
)]
pub fn verify_ed25519(
    verification_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Ed25519Error> {
    verify_ed25519_with(
        verification_key,
        message,
        signature,
        |encoded| decode_ed25519_point(encoded),
        |key, message, signature| verify_ed25519_equation(key, message, signature),
    )
}

/// Validates one P-256 verification key.
///
/// The only accepted encoding is the 33-byte compressed SEC1 point: tag `0x02` or `0x03`
/// followed by the 32-byte big-endian x-coordinate of a point on the curve. Every other
/// length is rejected, as are the SEC1 identity (`0x00`), uncompressed (`0x04`), compact
/// (`0x05`), and hybrid (`0x06`/`0x07`) forms, so one key has exactly one accepted encoding.
///
/// # Errors
///
/// Returns [`P256Error::InvalidKey`] for any other encoding, and for an x-coordinate that is not
/// below the field modulus or has no point on the curve.
pub fn validate_p256_key(verification_key: &[u8]) -> Result<(), P256Error> {
    match decode_p256_key(verification_key) {
        Ok(_) => Ok(()),
        Err(reason) => Err(reason),
    }
}

// One explicit primitive interface keeps the suite's encoding, error ordering
// and low-S policy in the same production algorithm used by the native adapter.
trait P256Primitive {
    type Key;
    type Signature;
    fn decode(bytes: &[u8]) -> Option<Self::Key>;
    fn parse(bytes: &[u8; 64]) -> Option<Self::Signature>;
    fn verify(key: &Self::Key, message: &[u8], signature: &Self::Signature) -> bool;
}
struct NativeP256;
impl P256Primitive for NativeP256 {
    type Key = P256Key;
    type Signature = P256Signature;
    fn decode(bytes: &[u8]) -> Option<P256Key> {
        decode_p256_point(bytes)
    }
    fn parse(bytes: &[u8; 64]) -> Option<P256Signature> {
        parse_p256_signature(bytes)
    }
    fn verify(key: &P256Key, message: &[u8], signature: &P256Signature) -> bool {
        verify_p256_equation(key, message, signature)
    }
}
/// Decodes the one key encoding [`validate_p256_key`] accepts.
///
/// The tag and length are checked before point decoding because the SEC1 decoder also accepts
/// the uncompressed and compact forms of the same point.
fn decode_p256_key_with<T: P256Primitive>(bytes: &[u8]) -> Result<T::Key, P256Error> {
    if !p256_key_encoding_is_canonical(bytes) {
        return Err(P256Error::InvalidKey);
    }
    match T::decode(bytes) {
        Some(key) => Ok(key),
        None => Err(P256Error::InvalidKey),
    }
}

fn decode_p256_point(bytes: &[u8]) -> Option<P256Key> {
    P256Key::from_sec1_bytes(bytes).ok()
}

fn decode_p256_key(bytes: &[u8]) -> Result<P256Key, P256Error> {
    decode_p256_key_with::<NativeP256>(bytes)
}

fn parse_p256_signature(bytes: &[u8; 64]) -> Option<P256Signature> {
    P256Signature::from_slice(bytes).ok()
}

fn verify_p256_equation(key: &P256Key, message: &[u8], signature: &P256Signature) -> bool {
    key.verify(message, signature).is_ok()
}

fn verify_p256_sha256_with<T: P256Primitive>(
    bytes: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), P256Error> {
    let key = decode_p256_key_with::<T>(bytes)?;
    // A fixed-size owned copy avoids region-erased borrowed array types in the
    // monomorphic native-library extraction; the byte contract is unchanged.
    let signature: [u8; 64] = match signature.try_into() {
        Ok(signature) => signature,
        Err(_) => return Err(P256Error::InvalidSignatureEncoding),
    };
    let Some(parsed) = T::parse(&signature) else {
        return Err(P256Error::InvalidSignatureEncoding);
    };
    if !p256_signature_is_low_s(&signature) {
        return Err(P256Error::VerificationFailed);
    }
    if T::verify(&key, message, &parsed) {
        Ok(())
    } else {
        Err(P256Error::VerificationFailed)
    }
}

/// Verifies one fixed-width low-S P-256/SHA-256 signature.
///
/// The key must use the one encoding [`validate_p256_key`] accepts. This primitive assigns no
/// protocol meaning to `message`; each caller remains responsible for constructing its own
/// domain-separated signing preimage.
///
/// # Errors
///
/// Distinguishes malformed keys, malformed signature encodings, and cryptographic failure. High-S
/// signatures are rejected rather than normalized.
pub fn verify_p256_sha256(
    verification_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), P256Error> {
    verify_p256_sha256_with::<NativeP256>(verification_key, message, signature)
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use alloc::{vec, vec::Vec};
    use ed25519_dalek::{Signer as _, SigningKey};
    use p256::ecdsa::SigningKey as P256SigningKey;

    #[test]
    fn strict_verifier_binds_every_byte_and_classifies_shapes() {
        let signing = SigningKey::from_bytes(&[17; 32]);
        let signature = signing.sign(b"canonical message").to_bytes();
        let key = signing.verifying_key().to_bytes();

        assert_eq!(
            verify_ed25519(&key, b"canonical message", &signature),
            Ok(())
        );
        assert_eq!(
            verify_ed25519(&key, b"changed message", &signature),
            Err(Ed25519Error::VerificationFailed)
        );
        assert_eq!(
            verify_ed25519(&key[..31], b"canonical message", &signature),
            Err(Ed25519Error::InvalidKey)
        );
        assert_eq!(
            verify_ed25519(&key, b"canonical message", &signature[..63]),
            Err(Ed25519Error::InvalidSignatureEncoding)
        );
    }

    #[test]
    fn ed25519_rejects_noncanonical_fields_before_signature_parsing() {
        for offset in 0u8..19 {
            let mut key = [0xff; 32];
            key[0] = 0xed + offset;
            for sign in [0, 0x80] {
                key[31] = 0x7f | sign;
                assert!(!ed25519_point_encoding_is_canonical(&key));
                assert_eq!(validate_ed25519_key(&key), Err(Ed25519Error::InvalidKey));
                assert_eq!(
                    verify_ed25519(&key, b"message", &[]),
                    Err(Ed25519Error::InvalidKey)
                );
            }
        }
        // A permissively decodable, non-weak point demonstrates why neither
        // a length check nor the library's low-order check supplies this rule.
        let mut noncanonical = [0xff; 32];
        noncanonical[0] = 0xf0; // p + 3
        noncanonical[31] = 0x7f;
        let decoded = VerifyingKey::from_bytes(&noncanonical).unwrap();
        assert!(!decoded.is_weak());
        assert_eq!(
            validate_ed25519_key(&noncanonical),
            Err(Ed25519Error::InvalidKey)
        );
    }

    #[test]
    fn ed25519_rejects_negative_zero_and_preserves_canonical_boundaries() {
        let mut identity = [0; 32];
        identity[0] = 1;
        let mut order_two = [0xff; 32];
        order_two[0] = 0xec;
        order_two[31] = 0x7f;
        for canonical in [identity, order_two] {
            assert!(ed25519_point_encoding_is_canonical(&canonical));
            assert_eq!(validate_ed25519_key(&canonical), Ok(()));
            let mut negative_zero = canonical;
            negative_zero[31] |= 0x80;
            assert!(VerifyingKey::from_bytes(&negative_zero).is_ok());
            assert_eq!(
                validate_ed25519_key(&negative_zero),
                Err(Ed25519Error::InvalidKey)
            );
            // Canonical small-order encodings remain subject to strict
            // verification; an encoding check does not authenticate them.
            assert_eq!(
                verify_ed25519(&canonical, b"message", &[0; 64]),
                Err(Ed25519Error::VerificationFailed)
            );
        }
    }

    #[test]
    fn rfc8032_public_vector_one_verifies_the_exact_empty_message() {
        let key = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        let signature = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];
        assert_eq!(validate_ed25519_key(&key), Ok(()));
        assert_eq!(verify_ed25519(&key, b"", &signature), Ok(()));
        assert_eq!(
            verify_ed25519(&key, b"changed", &signature),
            Err(Ed25519Error::VerificationFailed)
        );
    }

    const P256_MESSAGE: &[u8] = b"canonical message";

    /// A fixed P-256 key whose public point is the one its compact form `0x05 || x` decodes to.
    ///
    /// A compact point decodes to the candidate with the smaller of y and p - y. Negating the
    /// scalar reflects the point to (x, p - y), so exactly one of d and n - d qualifies.
    fn compact_decodable_p256_key() -> P256SigningKey {
        let mut scalar = [0; 32];
        scalar[31] = 7;
        let key = P256SigningKey::from_bytes((&scalar).into()).unwrap();
        let mut compact = vec![0x05];
        compact.extend_from_slice(&key.verifying_key().to_encoded_point(true).as_bytes()[1..]);
        if P256Key::from_sec1_bytes(&compact).unwrap() == *key.verifying_key() {
            key
        } else {
            P256SigningKey::from(-*key.as_nonzero_scalar())
        }
    }

    fn with_tag(tag: u8, rest: &[u8]) -> Vec<u8> {
        let mut encoded = vec![tag];
        encoded.extend_from_slice(rest);
        encoded
    }

    #[test]
    fn ed25519_glue_refuses_weak_inputs_before_the_equation() {
        use core::cell::Cell;
        let good = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        for coordinate in [
            ED25519_WEAK_ZERO,
            ED25519_WEAK_ONE,
            ED25519_WEAK_MINUS_ONE,
            ED25519_WEAK_ORDER_EIGHT_A,
            ED25519_WEAK_ORDER_EIGHT_B,
        ] {
            for sign in [0, 0x80] {
                let mut weak = coordinate;
                weak[31] |= sign;
                if !ed25519_point_encoding_is_canonical(&weak) {
                    continue;
                }
                assert!(ed25519_has_small_order_coordinate(&weak));
                assert!(VerifyingKey::from_bytes(&weak).unwrap().is_weak());
                let calls = Cell::new(0);
                let mut signature = [0; 64];
                signature[..32].copy_from_slice(&good);
                let rejected = verify_ed25519_with(
                    &weak,
                    b"message",
                    &signature,
                    |_| Some(()),
                    |(), _, _| {
                        calls.set(calls.get() + 1);
                        true
                    },
                );
                assert_eq!(rejected, Err(Ed25519Error::VerificationFailed));
                assert_eq!(calls.get(), 0);
                signature[..32].copy_from_slice(&weak);
                let rejected = verify_ed25519_with(
                    &good,
                    b"message",
                    &signature,
                    |_| Some(()),
                    |(), _, _| {
                        calls.set(calls.get() + 1);
                        true
                    },
                );
                assert_eq!(rejected, Err(Ed25519Error::VerificationFailed));
                assert_eq!(calls.get(), 0);
            }
        }
        // The real glue must still reach a supplied primitive on valid form,
        // forwarding the exact key, message and signature. This mock does not
        // claim that the zero scalar below authenticates a real signature.
        let mut signature = [0; 64];
        signature[..32].copy_from_slice(&good);
        assert_eq!(
            verify_ed25519_with(
                &good,
                b"exact message",
                &signature,
                |bytes| {
                    assert_eq!(bytes, &good);
                    Some(17u8)
                },
                |key, message, bytes| {
                    assert_eq!(*key, 17);
                    assert_eq!(message, b"exact message");
                    assert_eq!(bytes, &signature);
                    true
                }
            ),
            Ok(())
        );
        assert_eq!(
            verify_ed25519_with(
                &ED25519_WEAK_ONE,
                b"message",
                &signature[..63],
                |_| Some(()),
                |(), _, _| panic!("equation after bad width")
            ),
            Err(Ed25519Error::InvalidSignatureEncoding)
        );
    }

    #[test]
    fn p256_glue_preserves_parse_priority_and_blocks_high_s_before_equation() {
        struct Guarded<const PARSES: bool>;
        impl<const PARSES: bool> P256Primitive for Guarded<PARSES> {
            type Key = ();
            type Signature = ();
            fn decode(_: &[u8]) -> Option<()> {
                Some(())
            }
            fn parse(_: &[u8; 64]) -> Option<()> {
                PARSES.then_some(())
            }
            fn verify((): &(), _: &[u8], (): &()) -> bool {
                panic!("a refused scalar must not reach the equation")
            }
        }
        struct ExactForward;
        impl P256Primitive for ExactForward {
            type Key = u8;
            type Signature = u8;
            fn decode(bytes: &[u8]) -> Option<u8> {
                assert_eq!(bytes, &[2; 33]);
                Some(23)
            }
            fn parse(bytes: &[u8; 64]) -> Option<u8> {
                let mut expected = [0; 64];
                expected[31] = 1;
                expected[32..].copy_from_slice(&P256_HALF_ORDER);
                assert_eq!(bytes, &expected);
                Some(17)
            }
            fn verify(point: &u8, message: &[u8], parsed: &u8) -> bool {
                assert_eq!(*point, 23);
                assert_eq!(message, b"exact message");
                assert_eq!(*parsed, 17);
                true
            }
        }
        let key = [2; 33];
        let mut signature = [0; 64];
        signature[31] = 1;
        signature[32..].copy_from_slice(&P256_HALF_ORDER);
        signature[63] += 1;
        assert_eq!(
            verify_p256_sha256_with::<Guarded<true>>(&key, b"message", &signature),
            Err(P256Error::VerificationFailed)
        );
        assert_eq!(
            verify_p256_sha256_with::<Guarded<false>>(&key, b"message", &signature),
            Err(P256Error::InvalidSignatureEncoding)
        );
        signature[63] -= 1;
        assert_eq!(
            verify_p256_sha256_with::<ExactForward>(&key, b"exact message", &signature),
            Ok(())
        );
    }

    #[test]
    fn p256_scalar_boundary_agrees_with_the_pinned_normalizer() {
        let mut lower = P256_HALF_ORDER;
        lower[31] -= 1;
        let mut upper = P256_HALF_ORDER;
        upper[31] += 1;
        let mut one = [0; 32];
        one[31] = 1;
        for (scalar, admitted) in [
            ([0; 32], true),
            (one, true),
            (lower, true),
            (P256_HALF_ORDER, true),
            (upper, false),
            ([0xff; 32], false),
        ] {
            let mut encoded = [0; 64];
            encoded[31] = 1; // Public r = 1; no signing key is involved.
            encoded[32..].copy_from_slice(&scalar);
            assert_eq!(p256_signature_is_low_s(&encoded), admitted);
            if let Ok(parsed) = P256Signature::from_slice(&encoded) {
                assert_eq!(
                    p256_signature_is_low_s(&encoded),
                    parsed.normalize_s().is_none()
                );
            }
            // The protocol comparison depends only on the encoded s scalar.
            encoded[..32].fill(0xff);
            assert_eq!(p256_signature_is_low_s(&encoded), admitted);
        }
    }

    #[test]
    fn p256_rejects_high_s_without_changing_the_signed_message() {
        let key = compact_decodable_p256_key();
        let signature: P256Signature = key.sign(P256_MESSAGE);
        let low = signature.normalize_s().unwrap_or(signature);
        let (r, s) = low.split_scalars();
        let high = P256Signature::from_scalars(r.to_bytes(), (-s).to_bytes()).unwrap();
        let compressed = key.verifying_key().to_encoded_point(true);
        assert!(high.normalize_s().is_some());
        assert!(key.verifying_key().verify(P256_MESSAGE, &high).is_ok());
        assert_eq!(
            verify_p256_sha256(compressed.as_bytes(), P256_MESSAGE, &low.to_bytes()),
            Ok(())
        );
        assert_eq!(
            verify_p256_sha256(compressed.as_bytes(), P256_MESSAGE, &high.to_bytes()),
            Err(P256Error::VerificationFailed)
        );
    }

    #[test]
    fn p256_accepts_only_the_compressed_encoding_of_a_point() {
        let key = compact_decodable_p256_key();
        let signature: P256Signature = key.sign(P256_MESSAGE);
        let signature = signature.normalize_s().unwrap_or(signature);
        let signature_bytes = signature.to_bytes();
        let compressed = key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let uncompressed = key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let x = &uncompressed[1..33];
        let x_and_y = &uncompressed[1..];
        let compact = with_tag(0x05, x);

        assert_eq!(validate_p256_key(&compressed), Ok(()));
        assert_eq!(
            verify_p256_sha256(&compressed, P256_MESSAGE, &signature_bytes),
            Ok(())
        );

        // The SEC1 decoder accepts these forms and the signature is valid for the point they
        // decode to, so only the encoding rule can reject them below.
        for permissive in [&uncompressed, &compact] {
            let decoded = P256Key::from_sec1_bytes(permissive).unwrap();
            assert_eq!(decoded, *key.verifying_key());
            assert!(decoded.verify(P256_MESSAGE, &signature).is_ok());
        }

        let mut rejected = vec![
            uncompressed.clone(),
            compact,
            with_tag(0x06, x_and_y),
            with_tag(0x07, x_and_y),
            vec![0x00],
            Vec::new(),
            compressed[..32].to_vec(),
            [compressed.as_slice(), &[0]].concat(),
            x_and_y.to_vec(),
            [uncompressed.as_slice(), &[0]].concat(),
            // A compressed tag over an x-coordinate that is not a canonical field element.
            with_tag(0x02, &[0xff; 32]),
        ];
        rejected.extend(
            (0..=u8::MAX)
                .filter(|tag| !matches!(tag, 0x02 | 0x03))
                .map(|tag| with_tag(tag, x)),
        );
        for encoded in &rejected {
            assert_eq!(
                validate_p256_key(encoded),
                Err(P256Error::InvalidKey),
                "{encoded:02x?}"
            );
            assert_eq!(
                verify_p256_sha256(encoded, P256_MESSAGE, &signature_bytes),
                Err(P256Error::InvalidKey),
                "{encoded:02x?}"
            );
        }
    }
}
