//! Identifier and bounded-value newtypes. Each constructor enforces its
//! size and grammar, so a raw string never stands in for one of them.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// A value that breaks the size or grammar of its identifier type.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
#[error("the identifier breaks its size or grammar")]
pub struct InvalidIdentifier;

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// `[a-z][a-z0-9-]{0,63}`, the grammar of provider kinds and aliases.
fn is_lower_token(value: &str) -> bool {
    let mut bytes = value.bytes();
    (1..=64).contains(&value.len())
        && bytes.next().is_some_and(|first| first.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// A SHA-256 digest, carried in JSON as 64 lowercase hexadecimal characters.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Wraps digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the 64-character lowercase hexadecimal form.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl TryFrom<String> for Sha256Digest {
    type Error = InvalidIdentifier;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() != 64 || !is_lower_hex(&value) {
            return Err(InvalidIdentifier);
        }
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(&value, &mut bytes).map_err(|_| InvalidIdentifier)?;
        Ok(Self(bytes))
    }
}

impl From<Sha256Digest> for String {
    fn from(value: Sha256Digest) -> Self {
        value.to_hex()
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Sha256Digest({})", self.to_hex())
    }
}

macro_rules! string_identifier {
    ($(#[$meta:meta])* $name:ident, $valid:expr) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Parses the canonical form.
            ///
            /// # Errors
            ///
            /// Returns [`InvalidIdentifier`] for a value outside the type's
            /// size or grammar.
            pub fn parse(value: impl Into<String>) -> Result<Self, InvalidIdentifier> {
                Self::try_from(value.into())
            }

            /// Returns the canonical form.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = InvalidIdentifier;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                let valid: fn(&str) -> bool = $valid;
                if valid(&value) {
                    Ok(Self(value))
                } else {
                    Err(InvalidIdentifier)
                }
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

string_identifier!(
    /// The stable identifier of one recipe family: `[a-z][a-z0-9-]{0,63}`.
    ///
    /// Invariant `declared-family`: the identifier is the one an accepted
    /// decision record names for the family. It is never derived from a
    /// provider's name, an origin, or a tool name.
    RecipeFamilyId,
    is_lower_token
);

string_identifier!(
    /// The identifier of one qualification: `qlf_` and 32 lowercase
    /// hexadecimal characters, assigned by the protected run.
    QualificationId,
    |value| value.len() == 36 && value.starts_with("qlf_") && is_lower_hex(&value[4..])
);

string_identifier!(
    /// The identifier of one release signer: `[a-z][a-z0-9-]{0,63}`.
    QualificationSignerId,
    is_lower_token
);

string_identifier!(
    /// The identifier of one qualification trust root: `[a-z][a-z0-9-]{0,63}`.
    QualificationRootId,
    is_lower_token
);

string_identifier!(
    /// An immutable Git commit: 40 or 64 lowercase hexadecimal characters.
    GitCommit,
    |value| matches!(value.len(), 40 | 64) && is_lower_hex(value)
);

/// Opaque text of 1 to `MAX` bytes: printable ASCII with no leading or
/// trailing space. Text outside ASCII is refused, so two visually equal
/// values are always byte-equal.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct BoundedText<const MAX: usize>(String);

impl<const MAX: usize> BoundedText<MAX> {
    /// Parses bounded text.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIdentifier`] for empty, oversized, non-ASCII, or
    /// non-printable text, or text that starts or ends with a space.
    pub fn parse(value: impl Into<String>) -> Result<Self, InvalidIdentifier> {
        Self::try_from(value.into())
    }

    /// Returns the text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<const MAX: usize> TryFrom<String> for BoundedText<MAX> {
    type Error = InvalidIdentifier;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let valid = (1..=MAX).contains(&value.len())
            && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
            && !value.starts_with(' ')
            && !value.ends_with(' ');
        if valid {
            Ok(Self(value))
        } else {
            Err(InvalidIdentifier)
        }
    }
}

impl<const MAX: usize> From<BoundedText<MAX>> for String {
    fn from(value: BoundedText<MAX>) -> Self {
        value.0
    }
}

macro_rules! fixed_base64 {
    ($(#[$meta:meta])* $name:ident, $length:expr) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Encodes the fixed-width bytes.
            #[must_use]
            pub fn from_bytes(bytes: &[u8; $length]) -> Self {
                Self(Base64UrlUnpadded::encode_string(bytes))
            }

            /// Returns the fixed-width bytes.
            #[must_use]
            pub fn to_bytes(&self) -> [u8; $length] {
                let mut bytes = [0_u8; $length];
                // INVARIANT: the constructors accept only text that decodes
                // to exactly this width, so the decode cannot fail.
                let _ = Base64UrlUnpadded::decode(&self.0, &mut bytes);
                bytes
            }

            /// Returns the base64url text without padding.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = InvalidIdentifier;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                let mut bytes = [0_u8; $length];
                match Base64UrlUnpadded::decode(&value, &mut bytes) {
                    Ok(decoded) if decoded.len() == $length => Ok(Self(value)),
                    _ => Err(InvalidIdentifier),
                }
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

fixed_base64!(
    /// A 32-byte public key as base64url without padding.
    PublicKeyB64,
    32
);

fixed_base64!(
    /// A 64-byte signature as base64url without padding.
    SignatureB64,
    64
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_accept_only_64_lowercase_hex_characters() {
        let hex = "ab".repeat(32);
        let digest = Sha256Digest::try_from(hex.clone()).expect("digest");
        assert_eq!(digest.to_hex(), hex);
        assert_eq!(digest.as_bytes(), &[0xab; 32]);
        for invalid in [
            "",
            &"ab".repeat(31),
            &"AB".repeat(32),
            &"zz".repeat(32),
            &"ab".repeat(33),
        ] {
            assert_eq!(
                Sha256Digest::try_from(invalid.to_owned()),
                Err(InvalidIdentifier),
                "{invalid}"
            );
        }
    }

    #[test]
    fn declared_family_identifiers_follow_the_lower_token_grammar() {
        for valid in ["a", "stripe-refund-v1", &format!("a{}", "0".repeat(63))] {
            assert!(RecipeFamilyId::parse(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "",
            "Stripe-refund",
            "1stripe",
            "-stripe",
            "stripe_refund",
            "stripe refund",
            "stripe/refund",
            "stripe\u{0440}efund",
            &format!("a{}", "0".repeat(64)),
        ] {
            assert_eq!(
                RecipeFamilyId::parse(invalid),
                Err(InvalidIdentifier),
                "{invalid}"
            );
        }
    }

    #[test]
    fn qualification_identifiers_are_prefixed_fixed_width_hex() {
        let valid = format!("qlf_{}", "0f".repeat(16));
        assert_eq!(
            QualificationId::parse(valid.clone()).expect("id").as_str(),
            valid
        );
        for invalid in [
            format!("qlf_{}", "0f".repeat(15)),
            format!("qlf_{}", "0F".repeat(16)),
            format!("QLF_{}", "0f".repeat(16)),
            format!("rcp_{}", "0f".repeat(16)),
            format!("qlf_{}0", "0f".repeat(16)),
        ] {
            assert_eq!(
                QualificationId::parse(invalid.clone()),
                Err(InvalidIdentifier),
                "{invalid}"
            );
        }
    }

    #[test]
    fn commits_are_full_width_lowercase_hex() {
        assert!(GitCommit::parse("a".repeat(40)).is_ok());
        assert!(GitCommit::parse("a".repeat(64)).is_ok());
        for invalid in [
            "a".repeat(7),
            "a".repeat(41),
            "A".repeat(40),
            "main".to_owned(),
        ] {
            assert_eq!(
                GitCommit::parse(invalid.clone()),
                Err(InvalidIdentifier),
                "{invalid}"
            );
        }
    }

    #[test]
    fn bounded_text_is_printable_ascii_within_its_bound() {
        assert!(BoundedText::<8>::parse("a b").is_ok());
        assert!(BoundedText::<8>::parse("12345678").is_ok());
        for invalid in [
            "",
            "123456789",
            " a",
            "a ",
            "a\tb",
            "a\nb",
            "caf\u{e9}",
            "a\u{0}b",
        ] {
            assert_eq!(
                BoundedText::<8>::parse(invalid),
                Err(InvalidIdentifier),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn keys_and_signatures_have_exact_widths() {
        let key = PublicKeyB64::from_bytes(&[7; 32]);
        assert_eq!(key.to_bytes(), [7; 32]);
        assert_eq!(
            PublicKeyB64::try_from(key.as_str().to_owned()),
            Ok(key.clone())
        );
        let signature = SignatureB64::from_bytes(&[9; 64]);
        assert_eq!(signature.to_bytes(), [9; 64]);
        assert_eq!(
            PublicKeyB64::try_from(signature.as_str().to_owned()),
            Err(InvalidIdentifier),
            "a signature is not a key"
        );
        assert_eq!(
            SignatureB64::try_from(key.as_str().to_owned()),
            Err(InvalidIdentifier)
        );
        assert_eq!(
            PublicKeyB64::try_from(format!("{}=", key.as_str())),
            Err(InvalidIdentifier),
            "padding is refused"
        );
    }
}
