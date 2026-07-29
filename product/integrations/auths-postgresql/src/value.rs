//! Canonical typed values; strings never become SQL syntax.

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization as _;
use uuid::Uuid;

use crate::schema::{PgIdentifier, ValidationError, ValueConstraintV1, ValueKindV1};

const MAX_VALUE_BYTES: usize = 64 * 1024;

/// Closed canonical PostgreSQL value.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "kebab-case")]
pub enum TypedValueV1 {
    Null(ValueKindV1),
    Boolean(bool),
    Int64(i64),
    Text(String),
    Uuid(String),
    Decimal {
        unscaled: String,
        scale: u8,
    },
    TimestampUtc {
        unix_micros: i64,
        precision: u8,
    },
    EnumText {
        enum_name: PgIdentifier,
        value: String,
    },
}

impl TypedValueV1 {
    pub fn text(value: impl Into<String>) -> Result<Self, ValidationError> {
        let normalized: String = value.into().nfc().collect();
        if normalized.len() > MAX_VALUE_BYTES {
            return Err(ValidationError::LimitExceeded);
        }
        Ok(Self::Text(normalized))
    }

    pub fn uuid(value: &str) -> Result<Self, ValidationError> {
        let parsed = Uuid::parse_str(value).map_err(|_| ValidationError::MalformedMutation)?;
        Ok(Self::Uuid(parsed.hyphenated().to_string()))
    }

    pub fn decimal(negative: bool, digits: &str, scale: u8) -> Result<Self, ValidationError> {
        if digits.is_empty()
            || digits.len() > 38
            || scale > 38
            || !digits.bytes().all(|byte| byte.is_ascii_digit())
            || (digits.len() > 1 && digits.starts_with('0'))
        {
            return Err(ValidationError::MalformedMutation);
        }
        let unscaled = if negative && digits != "0" {
            format!("-{digits}")
        } else {
            digits.to_owned()
        };
        Ok(Self::Decimal { unscaled, scale })
    }

    pub fn timestamp_utc(unix_micros: i64, precision: u8) -> Result<Self, ValidationError> {
        if precision > 6 {
            return Err(ValidationError::MalformedMutation);
        }
        let divisor = 10_i64.pow(u32::from(6 - precision));
        if unix_micros.rem_euclid(divisor) != 0 {
            return Err(ValidationError::MalformedMutation);
        }
        Ok(Self::TimestampUtc {
            unix_micros,
            precision,
        })
    }

    pub fn enum_text(
        enum_name: PgIdentifier,
        value: impl Into<String>,
    ) -> Result<Self, ValidationError> {
        let value: String = value.into().nfc().collect();
        if value.is_empty() || value.len() > 256 {
            return Err(ValidationError::MalformedMutation);
        }
        Ok(Self::EnumText { enum_name, value })
    }

    #[must_use]
    pub const fn kind(&self) -> &ValueKindV1 {
        match self {
            Self::Null(kind) => kind,
            Self::Boolean(_) => &ValueKindV1::Boolean,
            Self::Int64(_) => &ValueKindV1::Int64,
            Self::Text(_) => &ValueKindV1::Text,
            Self::Uuid(_) => &ValueKindV1::Uuid,
            Self::Decimal { .. } => &ValueKindV1::Decimal,
            Self::TimestampUtc { .. } => &ValueKindV1::TimestampUtc,
            Self::EnumText { .. } => &ValueKindV1::EnumText,
        }
    }

    /// Text sent through the PostgreSQL wire protocol and cast by trusted SQL.
    #[must_use]
    pub fn protocol_text(&self) -> Option<String> {
        match self {
            Self::Null(_) => None,
            Self::Boolean(value) => Some(value.to_string()),
            Self::Int64(value) => Some(value.to_string()),
            Self::Text(value) | Self::Uuid(value) | Self::EnumText { value, .. } => {
                Some(value.clone())
            }
            Self::Decimal { unscaled, scale } => {
                let negative = unscaled.starts_with('-');
                let digits = unscaled.trim_start_matches('-');
                let value = if *scale == 0 {
                    digits.to_owned()
                } else if digits.len() <= usize::from(*scale) {
                    format!(
                        "0.{}{digits}",
                        "0".repeat(usize::from(*scale) - digits.len())
                    )
                } else {
                    let split = digits.len() - usize::from(*scale);
                    format!("{}.{}", &digits[..split], &digits[split..])
                };
                Some(if negative { format!("-{value}") } else { value })
            }
            Self::TimestampUtc {
                unix_micros,
                precision: _,
            } => Some(unix_micros.to_string()),
        }
    }

    pub fn validate_canonical(&self) -> Result<(), ValidationError> {
        match self {
            Self::Null(_) | Self::Boolean(_) | Self::Int64(_) => Ok(()),
            Self::Text(value) => {
                let normalized: String = value.nfc().collect();
                if normalized == *value && value.len() <= MAX_VALUE_BYTES {
                    Ok(())
                } else {
                    Err(ValidationError::UnsupportedValue)
                }
            }
            Self::Uuid(value) => {
                if Self::uuid(value)? == *self {
                    Ok(())
                } else {
                    Err(ValidationError::UnsupportedValue)
                }
            }
            Self::Decimal { unscaled, scale } => {
                let negative = unscaled.starts_with('-');
                let digits = unscaled.trim_start_matches('-');
                if digits.is_empty()
                    || digits.len() > 38
                    || *scale > 38
                    || !digits.bytes().all(|byte| byte.is_ascii_digit())
                    || (digits.len() > 1 && digits.starts_with('0'))
                    || (negative && digits == "0")
                {
                    Err(ValidationError::UnsupportedValue)
                } else {
                    Ok(())
                }
            }
            Self::TimestampUtc {
                unix_micros,
                precision,
            } => {
                if Self::timestamp_utc(*unix_micros, *precision)? == *self {
                    Ok(())
                } else {
                    Err(ValidationError::UnsupportedValue)
                }
            }
            Self::EnumText { value, .. } => {
                let normalized: String = value.nfc().collect();
                if normalized == *value && !value.is_empty() && value.len() <= 256 {
                    Ok(())
                } else {
                    Err(ValidationError::UnsupportedValue)
                }
            }
        }
    }

    pub fn validate(&self, constraint: &ValueConstraintV1) -> Result<(), ValidationError> {
        self.validate_canonical()?;
        if matches!(self, Self::Null(_)) {
            return if constraint.nullable && self.kind() == &constraint.kind {
                Ok(())
            } else {
                Err(ValidationError::UnsupportedValue)
            };
        }
        if self.kind() != &constraint.kind {
            return Err(ValidationError::UnsupportedValue);
        }
        match self {
            Self::Text(value) => {
                let normalized: String = value.nfc().collect();
                if normalized != *value
                    || u32::try_from(value.len()).map_or(true, |length| {
                        constraint
                            .maximum_text_bytes
                            .is_none_or(|limit| length > limit)
                    })
                {
                    return Err(ValidationError::UnsupportedValue);
                }
            }
            Self::Uuid(value) => {
                if Self::uuid(value)? != *self {
                    return Err(ValidationError::UnsupportedValue);
                }
            }
            Self::Decimal { unscaled, scale } => {
                let digits = unscaled.trim_start_matches('-');
                if Some(*scale) != constraint.decimal_scale
                    || u8::try_from(digits.len()).map_or(true, |length| {
                        constraint
                            .decimal_precision
                            .is_none_or(|limit| length > limit)
                    })
                    || !digits.bytes().all(|byte| byte.is_ascii_digit())
                    || (digits.len() > 1 && digits.starts_with('0'))
                    || unscaled == "-0"
                {
                    return Err(ValidationError::UnsupportedValue);
                }
            }
            Self::TimestampUtc {
                unix_micros,
                precision,
            } => {
                if Some(*precision) != constraint.timestamp_precision
                    || Self::timestamp_utc(*unix_micros, *precision)? != *self
                {
                    return Err(ValidationError::UnsupportedValue);
                }
            }
            Self::EnumText { enum_name, value } => {
                if constraint.enum_name.as_ref() != Some(enum_name)
                    || constraint.allowed_enum_values.binary_search(value).is_err()
                {
                    return Err(ValidationError::UnsupportedValue);
                }
            }
            Self::Boolean(_) | Self::Int64(_) | Self::Null(_) => {}
        }
        Ok(())
    }
}

/// Named value sorted by canonical column identifier.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedValueV1 {
    pub column: PgIdentifier,
    pub value: TypedValueV1,
}

/// Named digest for a committed before value.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedCommitmentV1 {
    pub column: PgIdentifier,
    pub digest: crate::schema::DigestHex,
}

/// Exact assignment.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentV1 {
    pub column: PgIdentifier,
    pub value: TypedValueV1,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_nfc_and_type_distinct() {
        let composed = TypedValueV1::text("Cafe\u{301}").unwrap();
        assert_eq!(composed, TypedValueV1::Text("Café".into()));
        assert_ne!(TypedValueV1::Text("1".into()), TypedValueV1::Int64(1));
    }

    #[test]
    fn decimal_scale_is_exact_including_values_below_one() {
        let value = TypedValueV1::decimal(false, "1", 2).unwrap();
        assert_eq!(value.protocol_text().as_deref(), Some("0.01"));
        assert_eq!(
            TypedValueV1::decimal(true, "12300", 2)
                .unwrap()
                .protocol_text()
                .as_deref(),
            Some("-123.00")
        );
        assert!(TypedValueV1::decimal(true, "0", 2).is_ok());
    }

    #[test]
    fn timestamp_precision_rejects_hidden_fraction() {
        assert!(TypedValueV1::timestamp_utc(1_234_000, 3).is_ok());
        assert!(TypedValueV1::timestamp_utc(1_234_001, 3).is_err());
    }

    #[test]
    fn identifiers_reject_quoting_and_case_variants() {
        assert!(PgIdentifier::parse("demo_accounts").is_ok());
        assert!(PgIdentifier::parse("DemoAccounts").is_err());
        assert!(PgIdentifier::parse("demo\".accounts").is_err());
    }
}
