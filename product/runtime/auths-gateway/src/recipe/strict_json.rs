//! Reject duplicate members from original source, lock and provider bytes.
//! Ordinary JSON validation enforces numeric/Unicode syntax and the standard
//! recursion limit. Its temporary Value is discarded: only original raw child
//! slices supply uniqueness evidence. Container visits never recursively call
//! an Auths Deserialize implementation; an explicit worklist visits every raw
//! descendant before typed decoding. The caller bounds the input bytes.

use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, value::RawValue};
use std::collections::BTreeSet;
use std::fmt;

struct RawChildren<'a>(Vec<&'a RawValue>);
struct ContainerVisitor;

fn sequence_step<'de, A: SeqAccess<'de>>(sequence: &mut A, children: &mut Vec<&'de RawValue>) -> Result<bool, A::Error> {
    match sequence.next_element::<&'de RawValue>()? {
        Some(child) => { children.push(child); Ok(true) }
        None => Ok(false),
    }
}

fn object_step<'de, A: MapAccess<'de>>(object: &mut A, names: &mut BTreeSet<String>, children: &mut Vec<&'de RawValue>) -> Result<bool, A::Error> {
    let Some(name) = object.next_key::<String>()? else { return Ok(false); };
    if !insert_member_name(names, name) {
        return Err(de::Error::custom("duplicate object member"));
    }
    children.push(object.next_value::<&'de RawValue>()?);
    Ok(true)
}

// This exact insertion boundary is selected for native refinement. It keeps
// the standard ordered set and its complete decoded String keys; no byte/token
// normalization or alternate duplicate detector is introduced.
fn insert_member_name(names: &mut BTreeSet<String>, name: String) -> bool {
    names.insert(name)
}

impl<'de> Deserialize<'de> for RawChildren<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ContainerVisitor)
    }
}

impl<'de> Visitor<'de> for ContainerVisitor {
    type Value = RawChildren<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON container with unique object members")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut children = Vec::new();
        let mut progress = Ok(true);
        while matches!(progress, Ok(true)) {
            progress = sequence_step(&mut sequence, &mut children);
        }
        progress?;
        Ok(RawChildren(children))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Self::Value, A::Error> {
        let mut names = BTreeSet::new();
        let mut children = Vec::new();
        let mut progress = Ok(true);
        while matches!(progress, Ok(true)) {
            progress = object_step(&mut object, &mut names, &mut children);
        }
        progress?;
        Ok(RawChildren(children))
    }
}

fn is_container(raw: &str) -> bool {
    let input = raw.as_bytes();
    let mut index = 0;
    let mut found = false;
    let mut container = false;
    while index < input.len() && !found {
        let byte = input[index];
        if !matches!(byte, b' ' | b'\n' | b'\t' | b'\r') {
            container = matches!(byte, b'{' | b'[');
            found = true;
        } else {
            index += 1;
        }
    }
    container
}

fn visit_raw<'a>(raw: &'a RawValue, pending: &mut Vec<&'a RawValue>) -> Result<(), serde_json::Error> {
    if is_container(raw.get()) {
        let RawChildren(mut children) = serde_json::from_str(raw.get())?;
        let mut next = children.pop();
        while let Some(child) = next {
            pending.push(child);
            next = children.pop();
        }
    }
    Ok(())
}

fn preflight(input: &[u8]) -> Result<(), serde_json::Error> {
    // This discarded parse validates all original numeric/string leaves and
    // bounds source nesting. A collapsed map never proves member uniqueness.
    let _: Value = serde_json::from_slice(input)?;
    let original: &RawValue = serde_json::from_slice(input)?;
    let mut pending = Vec::new();
    pending.push(original);
    let mut next = pending.pop();
    let mut result = Ok(());
    while let Some(raw) = next {
        result = visit_raw(raw, &mut pending);
        next = if result.is_ok() { pending.pop() } else { None };
    }
    result
}

/// Parses one bounded JSON document after checking decoded member-name
/// uniqueness at every nesting level, including escaped spellings of a name.
pub(crate) fn from_slice<T: DeserializeOwned>(input: &[u8]) -> Result<T, serde_json::Error> {
    // Worklist storage has been dropped before typed deserialization begins.
    preflight(input)?;
    serde_json::from_slice(input)
}

#[cfg(test)]
mod tests {
    use super::from_slice;
    use serde_json::{Value, json};

    // Frozen recursive preflight used solely as an acceptance oracle. The
    // production implementation above keeps recursion out of Auths visitors.
    struct RecursiveOracle;
    struct OracleVisitor;
    impl<'de> serde::Deserialize<'de> for RecursiveOracle {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserializer.deserialize_any(OracleVisitor)?;
            Ok(Self)
        }
    }
    impl<'de> serde::de::Visitor<'de> for OracleVisitor {
        type Value = ();
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { formatter.write_str("unique JSON") }
        fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> { Ok(()) }
        fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> { Ok(()) }
        fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> { Ok(()) }
        fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<(), E> { Ok(()) }
        fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<(), E> { Ok(()) }
        fn visit_string<E: serde::de::Error>(self, _: String) -> Result<(), E> { Ok(()) }
        fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> { Ok(()) }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
            while sequence.next_element::<RecursiveOracle>()?.is_some() {}
            Ok(())
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, mut object: A) -> Result<(), A::Error> {
            let mut names = std::collections::BTreeSet::new();
            while let Some(name) = object.next_key::<String>()? {
                if !names.insert(name) { return Err(serde::de::Error::custom("duplicate object member")); }
                object.next_value::<RecursiveOracle>()?;
            }
            Ok(())
        }
    }

    fn oracle_accepts(input: &[u8]) -> bool {
        let mut parser = serde_json::Deserializer::from_slice(input);
        <RecursiveOracle as serde::Deserialize>::deserialize(&mut parser).is_ok() && parser.end().is_ok()
    }

    #[test]
    fn iterative_raw_preflight_has_recursive_oracle_parity_on_adversarial_originals() {
        for input in ["null", " true \n", "-0", "1.5e2", "1e309", "1e21474836480", "\"\\ud800\"",
            "{\"a\":1,\"\\u0061\":2}", "{\"a\":{\"x\":1,\"x\":2},\"b\":0}",
            "[{},[],{\"a\":1} , [null,true]]", "[1,]", "{}{}", "{\"x\":0,}",
            "{\"x\":{\"a\":1},\"y\":{\"a\":2}}", "{\"ignored\":[{\"x\":1,\"x\":2}]}"] {
            assert_eq!(from_slice::<Value>(input.as_bytes()).is_ok(), oracle_accepts(input.as_bytes()), "{input}");
        }
        for depth in 124_usize..=130 {
            let input = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
            assert_eq!(from_slice::<Value>(input.as_bytes()).is_ok(), oracle_accepts(input.as_bytes()), "depth {depth}");
        }
    }

    proptest::proptest! {
        #[test]
        fn iterative_raw_preflight_keeps_every_original_duplicate_scope(
            name in ".{0,64}", depth in 0_usize..32, negative in proptest::arbitrary::any::<bool>(),
        ) {
            let name = serde_json::to_string(&name).expect("original decoded key");
            let value = if negative { "-0" } else { "1" };
            let input = format!("{}{{{name}:{value},{name}:null}}{}", "[".repeat(depth), "]".repeat(depth));
            proptest::prop_assert_eq!(from_slice::<Value>(input.as_bytes()).is_ok(), oracle_accepts(input.as_bytes()));
            proptest::prop_assert!(from_slice::<Value>(input.as_bytes()).is_err());
            let distinct = format!("{}[{{{name}:{value}}},{{{name}:null}}]{}", "[".repeat(depth), "]".repeat(depth));
            proptest::prop_assert_eq!(from_slice::<Value>(distinct.as_bytes()).is_ok(), oracle_accepts(distinct.as_bytes()));
            proptest::prop_assert!(from_slice::<Value>(distinct.as_bytes()).is_ok());
        }
    }

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
