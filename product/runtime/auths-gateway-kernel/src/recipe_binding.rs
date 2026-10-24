//! Exact decoded source/profile binding and compiled-recipe hash framing.
//! JSON parsing/canonicalization and SHA-256 remain native primitive boundaries.
//! These functions grant no installation, authorization or execution right.

use crate::construct::field_name_equal;
use crate::derived_tokens::append_digest_hex;
use alloc::vec::Vec;

/// The sole supported decoded recipe-source schema.
pub const SOURCE_SCHEMA: &str = "auths.gateway-recipe-source/2";
/// The sole supported generated profile-lock schema.
pub const LOCK_SCHEMA: &str = "auths.self-hosted-profile-lock/1";
/// The exact domain preceding canonical original source bytes in the digest.
pub const COMPILED_RECIPE_DOMAIN: &[u8] = b"auths.gateway-compiled-recipe/2\0";
/// Maximum encoded recipe-source document accepted before any JSON parsing.
pub const MAX_SOURCE_BYTES: usize = 65_536;
/// Maximum encoded profile-lock document accepted before any JSON parsing.
pub const MAX_LOCK_BYTES: usize = 65_536;
const SOURCE_SCHEMA_BYTES: &[u8] = SOURCE_SCHEMA.as_bytes();
const LOCK_SCHEMA_BYTES: &[u8] = LOCK_SCHEMA.as_bytes();

/// Checks the complete public compiler's encoded-document size boundary.
///
/// Both original documents must contain 1–65,536 bytes. This scalar length
/// gate reads no document bytes, allocates nothing and grants no
/// parsing, installation or execution authority. The caller maps every
/// refusal to its existing `InvalidSource` result before either parser runs.
#[must_use]
#[allow(
    clippy::manual_range_contains,
    reason = "scalar comparisons keep the public input gate directly translatable"
)]
pub const fn source_lengths_bounded(source_length: usize, lock_length: usize) -> bool {
    source_length > 0
        && source_length <= MAX_SOURCE_BYTES
        && lock_length > 0
        && lock_length <= MAX_LOCK_BYTES
}

/// The exact source/lock identity components, without normalization/coercion.
#[derive(Clone, Copy, Debug)]
pub struct ProfileBinding<'a> {
    /// Exact decoded service name.
    pub service: &'a [u8],
    /// Exact decoded tool name.
    pub tool: &'a [u8],
    /// Canonical lowercase digest spelling from the same decoded record.
    pub schema_digest: &'a [u8],
}

/// Complete metadata consumed before canonicalizing/hashing the lock schema.
#[derive(Clone, Copy, Debug)]
pub struct LockMetadata<'a> {
    /// Exact decoded lock schema.
    pub schema: &'a [u8],
    /// Generated format version; only version two is supported.
    pub generator_format: u8,
    /// Nonzero profile version.
    pub version: u16,
    /// Nonempty decoded profile identifier.
    pub profile: &'a [u8],
    /// Identity from this same lock.
    pub binding: ProfileBinding<'a>,
}

/// Borrowed hash input; creation allocates nothing and copies no source bytes.
#[derive(Clone, Copy, Debug)]
pub struct RecipeDigestInput<'a> {
    /// Fixed compiled-recipe domain.
    pub domain: &'a [u8],
    /// The exact canonical original source supplied to the constructor.
    pub canonical_source: &'a [u8],
}

#[allow(
    clippy::manual_range_contains,
    reason = "byte comparisons translate without an external range-contains model"
)]
fn lower_hex_byte(byte: u8) -> bool {
    (byte >= b'0' && byte <= b'9') || (byte >= b'a' && byte <= b'f')
}

/// Accepts exactly 64 lowercase ASCII hexadecimal bytes.
#[must_use]
pub fn lower_hex_digest(value: &[u8]) -> bool {
    if value.len() != 64 { return false; }
    let mut position = 0;
    while position < value.len() {
        let byte = value[position];
        if !lower_hex_byte(byte) { return false; }
        position += 1;
    }
    true
}

/// Checks the source schema before profile-lock validation.
#[must_use]
pub fn source_schema_supported(schema: &[u8]) -> bool {
    field_name_equal(schema, SOURCE_SCHEMA_BYTES)
}

/// Checks metadata only. The native caller must still hash the canonical
/// command schema, compare its digest, and parse/validate every field schema.
#[must_use]
pub fn lock_metadata_valid(lock: LockMetadata<'_>) -> bool {
    field_name_equal(lock.schema, LOCK_SCHEMA_BYTES)
        && lock.generator_format == 2
        && lock.version != 0
        && !lock.profile.is_empty()
        && !lock.binding.service.is_empty()
        && !lock.binding.tool.is_empty()
        && lower_hex_digest(lock.binding.schema_digest)
}

/// Exact service/tool/schema-digest equality. Metadata validity and digest
/// provenance are independent obligations; equality alone grants no trust.
#[must_use]
pub fn source_matches_profile(source: ProfileBinding<'_>, lock: ProfileBinding<'_>) -> bool {
    field_name_equal(source.service, lock.service)
        && field_name_equal(source.tool, lock.tool)
        && field_name_equal(source.schema_digest, lock.schema_digest)
}

/// Compares declared bytes with the lowercase spelling of the actual digest.
/// Uppercase, wrong-length and arbitrary non-ASCII spellings cannot match.
#[must_use]
pub fn schema_digest_matches(declared: &[u8], digest: &[u8; 32]) -> bool {
    let encoded = append_digest_hex(Vec::new(), digest);
    field_name_equal(declared, &encoded)
}

/// Returns the exact two chunks hashed for a compiled recipe. The caller must
/// supply canonical bytes of its original validated source and use SHA-256.
#[must_use]
pub const fn recipe_digest_input(canonical_source: &[u8]) -> RecipeDigestInput<'_> {
    RecipeDigestInput { domain: COMPILED_RECIPE_DOMAIN, canonical_source }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::String;

    fn binding() -> ProfileBinding<'static> {
        ProfileBinding {
            service: b"service",
            tool: b"tool",
            schema_digest: b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        }
    }

    fn metadata() -> LockMetadata<'static> {
        LockMetadata {
            schema: b"auths.self-hosted-profile-lock/1",
            generator_format: 2,
            version: 1,
            profile: b"profile",
            binding: binding(),
        }
    }

    #[test]
    fn every_byte_at_every_hex_position_uses_exact_lowercase_ascii() {
        for position in 0..64 {
            for byte in 0_u8..=255 {
                let mut declared = [b'0'; 64];
                declared[position] = byte;
                let expected = byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte);
                assert_eq!(lower_hex_digest(&declared), expected);
            }
        }
        for length in [0, 1, 32, 63, 65, 128] {
            assert!(!lower_hex_digest(&alloc::vec![b'0'; length]));
        }
        assert!(lower_hex_digest(binding().schema_digest));
    }

    #[test]
    fn lock_metadata_requires_every_component_without_trusting_the_schema() {
        let valid = metadata();
        assert!(lock_metadata_valid(valid));
        assert!(!lock_metadata_valid(LockMetadata { schema: b"auths.self-hosted-profile-lock/2", ..valid }));
        for generator_format in [0, 1, 3, u8::MAX] {
            assert!(!lock_metadata_valid(LockMetadata { generator_format, ..valid }));
        }
        assert!(!lock_metadata_valid(LockMetadata { version: 0, ..valid }));
        assert!(!lock_metadata_valid(LockMetadata { profile: b"", ..valid }));
        for invalid in [
            ProfileBinding { service: b"", ..binding() },
            ProfileBinding { tool: b"", ..binding() },
            ProfileBinding { schema_digest: b"", ..binding() },
            ProfileBinding { schema_digest: b"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", ..binding() },
        ] {
            assert!(!lock_metadata_valid(LockMetadata { binding: invalid, ..valid }));
        }
        assert!(lock_metadata_valid(LockMetadata { version: u16::MAX, ..valid }));
        // Metadata admission intentionally preserves the existing nonempty
        // identifier contract. Profile schema validation occurs at the caller.
        assert!(lock_metadata_valid(LockMetadata {
            profile: "profile/é".as_bytes(),
            binding: ProfileBinding { service: "service/é".as_bytes(), tool: b"tool.with-suffix", ..binding() },
            ..valid
        }));
    }

    #[test]
    fn schema_and_profile_binding_compare_whole_original_components() {
        assert!(source_schema_supported(b"auths.gateway-recipe-source/2"));
        for schema in [b"".as_slice(), b"auths.gateway-recipe-source/1", b"auths.gateway-recipe-source/2\0", b"AUTHS.gateway-recipe-source/2"] {
            assert!(!source_schema_supported(schema));
        }
        let lock = binding();
        assert!(source_matches_profile(lock, lock));
        for changed in [
            ProfileBinding { service: b"service-suffix", ..lock },
            ProfileBinding { tool: b"tool-suffix", ..lock },
            ProfileBinding { schema_digest: b"1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", ..lock },
        ] {
            assert!(!source_matches_profile(changed, lock));
            assert!(!source_matches_profile(lock, changed));
        }
    }

    #[test]
    fn declared_digest_compares_against_an_independent_formatter() {
        for position in 0..32 {
            for byte in 0_u8..=255 {
                let mut digest = [0; 32];
                digest[position] = byte;
                let expected: String = digest.iter().map(|value| format!("{value:02x}")).collect();
                assert!(schema_digest_matches(expected.as_bytes(), &digest));
                let mut changed = expected.clone().into_bytes();
                changed[2 * position] = if changed[2 * position] == b'0' { b'1' } else { b'0' };
                assert!(!schema_digest_matches(&changed, &digest));
                assert!(!schema_digest_matches(&expected.as_bytes()[1..], &digest));
            }
        }
        assert!(!schema_digest_matches(&[b'A'; 64], &[0xaa; 32]));
    }

    #[test]
    fn digest_frame_retains_the_exact_original_bytes_and_fixed_domain() {
        for canonical_source in [b"".as_slice(), b"{}", b"{\"origin\":\"https://example.test\"}", b"\0\xff\x7f"] {
            let input = recipe_digest_input(canonical_source);
            assert_eq!(input.domain, b"auths.gateway-compiled-recipe/2\0");
            assert_eq!(input.canonical_source, canonical_source);
            assert_eq!(input.canonical_source.as_ptr(), canonical_source.as_ptr());
        }
    }
}
