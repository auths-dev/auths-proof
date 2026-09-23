//! Bounded JSON tree for untrusted API description documents.
//!
//! The tree keeps source key order (for readable output), rejects duplicate
//! object keys at every depth, and refuses nesting deeper than the document
//! bound before any mapping runs.

use serde::de::{DeserializeSeed, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use std::collections::BTreeSet;
use std::fmt;

/// Maximum container nesting of a whole document.
pub(crate) const MAX_DOCUMENT_DEPTH: usize = 32;

/// Largest integer every supported language represents exactly.
pub(crate) const SAFE_INTEGER: i64 = (1_i64 << 53) - 1;

/// One parsed JSON value with duplicate-free, source-ordered objects.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Json {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    pub(crate) fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(entries) => entries
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub(crate) fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    pub(crate) fn as_object(&self) -> Option<&[(String, Self)]> {
        match self {
            Self::Object(entries) => Some(entries),
            _ => None,
        }
    }

    /// Returns an exact integer, accepting an integral floating spelling
    /// such as `4.0` inside the safe-integer range.
    pub(crate) fn as_integer(&self) -> Option<i64> {
        let Self::Number(number) = self else {
            return None;
        };
        if let Some(value) = number.as_i64() {
            return (-SAFE_INTEGER..=SAFE_INTEGER)
                .contains(&value)
                .then_some(value);
        }
        if number.as_u64().is_some() {
            return None;
        }
        let value = number.as_f64()?;
        if value.fract() != 0.0 || value.abs() > 9_007_199_254_740_991.0 {
            return None;
        }
        // INVARIANT: the value is integral and inside the exactly
        // representable safe-integer range, so the conversion is exact.
        #[allow(clippy::cast_possible_truncation)]
        Some(value as i64)
    }

    /// Compact UTF-8 serialization length, used only to bound slices.
    pub(crate) fn compact_len(&self) -> usize {
        match self {
            Self::Null | Self::Bool(true) => 4,
            Self::Bool(false) => 5,
            Self::Number(number) => number.to_string().len(),
            Self::String(value) => string_len(value),
            Self::Array(items) => {
                2 + items.iter().map(Self::compact_len).sum::<usize>()
                    + items.len().saturating_sub(1)
            }
            Self::Object(entries) => {
                2 + entries
                    .iter()
                    .map(|(key, value)| string_len(key) + 1 + value.compact_len())
                    .sum::<usize>()
                    + entries.len().saturating_sub(1)
            }
        }
    }
}

/// Serialized length of one JSON string, including quotes and escapes.
pub(crate) fn string_len(value: &str) -> usize {
    2 + value
        .chars()
        .map(|character| match character {
            '"' | '\\' | '\n' | '\r' | '\t' | '\u{08}' | '\u{0c}' => 2,
            '\u{00}'..='\u{1f}' => 6,
            other => other.len_utf8(),
        })
        .sum::<usize>()
}

/// Parses bounded bytes into a tree.
///
/// # Errors
/// Returns a human reason for invalid UTF-8 or JSON, duplicate keys,
/// excessive nesting, or trailing bytes.
pub(crate) fn parse(bytes: &[u8]) -> Result<Json, String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = Seed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(|error| format!("the document is not valid bounded JSON: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("the document has trailing bytes: {error}"))?;
    Ok(value)
}

struct Seed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for Seed {
    type Value = Json;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Json, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed {
    type Value = Json;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Json, E> {
        Ok(Json::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Json, E> {
        Ok(Json::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Json, E> {
        Ok(Json::Number(value.into()))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Json, E> {
        serde_json::Number::from_f64(value)
            .map(Json::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Json, E> {
        Ok(Json::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Json, E> {
        Ok(Json::String(value))
    }

    fn visit_unit<E>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Json, A::Error> {
        let depth = self.depth + 1;
        if depth > MAX_DOCUMENT_DEPTH {
            return Err(A::Error::custom("nesting exceeds 32 levels"));
        }
        let mut items = Vec::new();
        while let Some(item) = sequence.next_element_seed(Seed { depth })? {
            items.push(item);
        }
        Ok(Json::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
        let depth = self.depth + 1;
        if depth > MAX_DOCUMENT_DEPTH {
            return Err(A::Error::custom("nesting exceeds 32 levels"));
        }
        let mut seen = BTreeSet::new();
        let mut entries = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(A::Error::custom(format!("duplicate object key {key:?}")));
            }
            let value = map.next_value_seed(Seed { depth })?;
            entries.push((key, value));
        }
        Ok(Json::Object(entries))
    }
}

/// Escapes one JSON-pointer reference token.
pub(crate) fn escape_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_keys_and_deep_nesting_are_rejected() {
        assert!(parse(br#"{"a":1,"a":2}"#).is_err());
        assert!(parse(br#"{"a":{"b":1,"b":1}}"#).is_err());
        let deep = format!("{}{}", "[".repeat(33), "]".repeat(33));
        assert!(parse(deep.as_bytes()).is_err());
        let fits = format!("{}{}", "[".repeat(32), "]".repeat(32));
        assert!(parse(fits.as_bytes()).is_ok());
        assert!(parse(b"{} x").is_err());
    }

    #[test]
    fn integral_floats_are_integers_and_order_is_kept() {
        let value = parse(br#"{"z":4.0,"a":4.5,"m":9007199254740992}"#).unwrap();
        assert_eq!(value.get("z").and_then(Json::as_integer), Some(4));
        assert_eq!(value.get("a").and_then(Json::as_integer), None);
        assert_eq!(value.get("m").and_then(Json::as_integer), None);
        let keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, _)| key.as_str())
            .collect();
        assert_eq!(keys, ["z", "a", "m"]);
    }
}
