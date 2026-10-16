//! Reject duplicate members before either the typed source or lock parser can
//! collapse an object into a map. The caller bounds the complete byte input;
//! `serde_json`'s standard recursion limit applies to both parsing passes.

use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::collections::BTreeSet;
use std::fmt;

struct UniqueMembers;
struct UniqueVisitor;

impl<'de> Deserialize<'de> for UniqueMembers {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueVisitor)?;
        Ok(Self)
    }
}

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON with unique object members")
    }

    fn visit_bool<E: de::Error>(self, _value: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: de::Error>(self, _value: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: de::Error>(self, _value: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: de::Error>(self, _value: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: de::Error>(self, _value: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_string<E: de::Error>(self, _value: String) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        while sequence.next_element::<UniqueMembers>()?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<(), A::Error> {
        let mut names = BTreeSet::new();
        while let Some(name) = object.next_key::<String>()? {
            if !names.insert(name) {
                return Err(de::Error::custom("duplicate object member"));
            }
            object.next_value::<UniqueMembers>()?;
        }
        Ok(())
    }
}

/// Parses one bounded source/lock document after checking decoded member-name
/// uniqueness at every nesting level, including escaped spellings of a name.
pub(super) fn from_slice<T: DeserializeOwned>(input: &[u8]) -> Result<T, serde_json::Error> {
    let mut parser = serde_json::Deserializer::from_slice(input);
    UniqueMembers::deserialize(&mut parser)?;
    parser.end()?;
    serde_json::from_slice(input)
}

#[cfg(test)]
mod tests {
    use super::from_slice;
    use serde_json::{Value, json};

    #[test]
    fn duplicate_names_are_refused_at_every_depth() {
        for input in [
            r#"{"a":1,"a":2}"#,
            r#"{"fields":{"invoice":1,"invoice":2}}"#,
            r#"{"body":[{"x":1,"x":2}]}"#,
            r#"{"a":1,"\u0061":2}"#,
            r#"{"x":{"a":1,"a":1}}"#,
        ] {
            assert!(from_slice::<Value>(input.as_bytes()).is_err());
        }
    }

    #[test]
    fn distinct_scopes_types_and_whitespace_keep_their_meaning() {
        let input = br#" {"a":{"x":1},"b":{"x":2},"list":[null,true,3,"text"]} "#;
        assert_eq!(
            from_slice::<Value>(input).unwrap(),
            json!({"a":{"x":1},"b":{"x":2},"list":[null,true,3,"text"]})
        );
        assert!(from_slice::<Value>(br#"{"a":1} {"b":2}"#).is_err());
        assert!(from_slice::<Value>(br#"{"a":1"#).is_err());
    }

    #[test]
    fn recursion_limit_is_retained() {
        let input = format!("{}0{}", "[".repeat(200), "]".repeat(200));
        assert!(from_slice::<Value>(input.as_bytes()).is_err());
    }
}
