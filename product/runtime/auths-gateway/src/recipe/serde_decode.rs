//! Closed source decoding forms used by the actual recipe compiler. String
//! field dispatch avoids byte-pattern metadata operations in generated derive
//! visitors. The field tables at each type remain explicit production code.
//! Maps reject unknown/duplicate fields; positional records retain declared
//! defaults. Identifier decoding delegates to the actual deserializer so raw
//! JSON string tags and buffered ordinal tags stay distinct.

use serde::de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::Deserializer;
use serde_json::Value;
use std::fmt;

pub(super) struct TagSeed {
    names: Vec<String>,
}

impl TagSeed {
    pub(super) fn new(names: Vec<String>) -> Self { Self { names } }
}

struct TagVisitor {
    names: Vec<String>,
}

impl<'de> Visitor<'de> for TagVisitor {
    type Value = usize;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a declared source variant identifier")
    }

    fn visit_str<E: de::Error>(self, name: &str) -> Result<usize, E> {
        let mut index = 0;
        let mut selected = None;
        while index < self.names.len() && selected.is_none() {
            if self.names[index].as_str() == name { selected = Some(index); } else { index += 1; }
        }
        selected.ok_or_else(|| E::custom("unknown source variant"))
    }

    fn visit_u64<E: de::Error>(self, index: u64) -> Result<usize, E> {
        match usize::try_from(index) {
            Ok(index) if index < self.names.len() => Ok(index),
            _ => Err(E::custom("unknown source variant index")),
        }
    }

    fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<usize, E> {
        let name = std::str::from_utf8(bytes).map_err(|_| E::custom("invalid UTF-8 source variant"))?;
        self.visit_str(name)
    }
}

impl<'de> DeserializeSeed<'de> for TagSeed {
    type Value = usize;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<usize, D::Error> {
        deserializer.deserialize_identifier(TagVisitor { names: self.names })
    }
}

pub(super) enum Payload {
    Map(Vec<(String, Value)>),
    Sequence(Vec<Value>),
}

pub(super) fn tagged_map_step<'de, A: MapAccess<'de>>(map: &mut A, tag: &mut Option<usize>,
    fields: &mut Vec<(String, Value)>, names: &[String]) -> Result<bool, A::Error> {
    let Some(name) = map.next_key::<String>()? else { return Ok(false); };
    if name == "kind" {
        if tag.is_some() { return Err(de::Error::duplicate_field("kind")); }
        let mut declared = Vec::new();
        for name in names { declared.push(name.clone()); }
        *tag = Some(map.next_value_seed(TagSeed::new(declared))?);
    } else {
        fields.push((name, map.next_value::<Value>()?));
    }
    Ok(true)
}

pub(super) fn tagged_sequence_step<'de, A: SeqAccess<'de>>(sequence: &mut A, fields: &mut Vec<Value>) -> Result<bool, A::Error> {
    match sequence.next_element::<Value>()? {
        Some(value) => { fields.push(value); Ok(true) }
        None => Ok(false),
    }
}

pub(super) fn payload<T: DeserializeOwned>(fields: Payload) -> Result<T, serde_json::Error> {
    // Iterator access retains the complete occurrence sequence, including
    // duplicate payload names. It must not first collapse fields into a map.
    match fields {
        Payload::Map(fields) => T::deserialize(de::value::MapDeserializer::<_, serde_json::Error>::new(fields.into_iter())),
        Payload::Sequence(fields) => T::deserialize(de::value::SeqDeserializer::<_, serde_json::Error>::new(fields.into_iter())),
    }
}

pub(super) fn unit_payload(fields: Payload) -> Result<(), serde_json::Error> {
    match fields {
        Payload::Map(_) => Ok(()),
        Payload::Sequence(values) if values.is_empty() => Ok(()),
        Payload::Sequence(_) => Err(<serde_json::Error as de::Error>::custom("unexpected source unit content")),
    }
}

// Closed literal tables become owned strings before entering a visitor.
// No parser mode, identifier order or public serde dispatch is changed.
macro_rules! recipe_tag_names {
    ($($tag:literal),* $(,)?) => {{
        let mut names = Vec::new();
        $(names.push(String::from($tag));)*
        names
    }};
}

macro_rules! recipe_missing_field {
    ($slot:expr, $name:ident, required, $error:ty) => {
        match $slot {
            Some(value) => value,
            None => return Err(<$error as serde::de::Error>::missing_field(stringify!($name))),
        }
    };
    ($slot:expr, $name:ident, default, $error:ty) => {
        match $slot { Some(value) => value, None => Default::default() }
    };
}

macro_rules! recipe_record_decode {
    ($name:ident { $($field:ident : $ty:ty => $missing:ident),* $(,)? }) => {
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct Slots { $($field: Option<$ty>),* }
                impl Slots {
                    fn step<'de, A: serde::de::MapAccess<'de>>(&mut self, map: &mut A) -> Result<bool, A::Error> {
                        let Some(name) = map.next_key::<String>()? else { return Ok(false); };
                        match name.as_str() {
                            $(stringify!($field) => {
                                if self.$field.is_some() { return Err(serde::de::Error::duplicate_field(stringify!($field))); }
                                self.$field = Some(map.next_value::<$ty>()?);
                            }),*
                            _ => return Err(serde::de::Error::unknown_field(&name, &[$(stringify!($field)),*])),
                        }
                        Ok(true)
                    }
                }
                struct RecordVisitor;
                impl<'de> serde::de::Visitor<'de> for RecordVisitor {
                    type Value = $name;
                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        formatter.write_str(concat!("source record ", stringify!($name)))
                    }
                    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<$name, A::Error> {
                        let mut slots = Slots { $($field: None),* };
                        let mut progress = Ok(true);
                        while matches!(progress, Ok(true)) { progress = slots.step(&mut map); }
                        progress?;
                        let Slots { $($field),* } = slots;
                        Ok($name { $($field: recipe_missing_field!($field, $field, $missing, A::Error)),* })
                    }
                    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut sequence: A) -> Result<$name, A::Error> {
                        $(let $field = recipe_missing_field!(sequence.next_element::<$ty>()?, $field, $missing, A::Error);)*
                        if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                            return Err(serde::de::Error::custom("trailing source record element"));
                        }
                        Ok($name { $($field),* })
                    }
                }
                deserializer.deserialize_struct(stringify!($name), &[$(stringify!($field)),*], RecordVisitor)
            }
        }
    };
}

macro_rules! recipe_variant_payload {
    ($name:ident, $variant:ident, $fields:expr, [$payload:ident { $($field:ident : $ty:ty => $missing:ident),* $(,)? }]) => {{
        let parsed: $payload = match crate::recipe::serde_decode::payload($fields) {
            Ok(parsed) => parsed,
            Err(error) => return Err(serde::de::Error::custom(error)),
        };
        Ok($name::$variant { $($field: parsed.$field),* })
    }};
    ($name:ident, $variant:ident, $fields:expr, []) => {{
        match crate::recipe::serde_decode::unit_payload($fields) {
            Ok(()) => {},
            Err(error) => return Err(serde::de::Error::custom(error)),
        }
        Ok($name::$variant)
    }};
}

macro_rules! recipe_payload_record {
    ([$payload:ident { $($field:ident : $ty:ty => $missing:ident),* $(,)? }]) => {
        struct $payload { $($field: $ty),* }
        recipe_record_decode!($payload { $($field: $ty => $missing),* });
    };
    ([]) => {};
}

macro_rules! recipe_internal_enum_decode {
    ($name:ident { $($index:literal => $tag:literal => $variant:ident $payload:tt),* $(,)? }) => {
        $(recipe_payload_record!($payload);)*
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct EnumVisitor;
                impl<'de> serde::de::Visitor<'de> for EnumVisitor {
                    type Value = $name;
                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        formatter.write_str(concat!("internally tagged ", stringify!($name)))
                    }
                    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<$name, A::Error> {
                        let names = recipe_tag_names!($($tag),*);
                        let mut tag = None;
                        let mut fields = Vec::new();
                        let mut progress = Ok(true);
                        while matches!(progress, Ok(true)) {
                            progress = crate::recipe::serde_decode::tagged_map_step(&mut map, &mut tag, &mut fields, &names);
                        }
                        progress?;
                        let tag = tag.ok_or_else(|| <A::Error as serde::de::Error>::missing_field("kind"))?;
                        let fields = crate::recipe::serde_decode::Payload::Map(fields);
                        match tag {
                            $($index => recipe_variant_payload!($name, $variant, fields, $payload),)*
                            _ => Err(serde::de::Error::custom("unknown source variant")),
                        }
                    }
                    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut sequence: A) -> Result<$name, A::Error> {
                        let tag = sequence.next_element_seed(crate::recipe::serde_decode::TagSeed::new(recipe_tag_names!($($tag),*)))?
                            .ok_or_else(|| <A::Error as serde::de::Error>::missing_field("kind"))?;
                        let mut fields = Vec::new();
                        let mut progress = Ok(true);
                        while matches!(progress, Ok(true)) {
                            progress = crate::recipe::serde_decode::tagged_sequence_step(&mut sequence, &mut fields);
                        }
                        progress?;
                        let fields = crate::recipe::serde_decode::Payload::Sequence(fields);
                        match tag {
                            $($index => recipe_variant_payload!($name, $variant, fields, $payload),)*
                            _ => Err(serde::de::Error::custom("unknown source variant")),
                        }
                    }
                }
                deserializer.deserialize_any(EnumVisitor)
            }
        }
    };
}

macro_rules! recipe_external_unit_decode {
    ($name:ident { $($index:literal => $tag:literal => $variant:ident),* $(,)? }) => {
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct UnitVisitor;
                impl<'de> serde::de::Visitor<'de> for UnitVisitor {
                    type Value = $name;
                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        formatter.write_str(concat!("unit variant ", stringify!($name)))
                    }
                    fn visit_enum<A: serde::de::EnumAccess<'de>>(self, data: A) -> Result<$name, A::Error> {
                        let (tag, variant) = data.variant_seed(crate::recipe::serde_decode::TagSeed::new(recipe_tag_names!($($tag),*)))?;
                        serde::de::VariantAccess::unit_variant(variant)?;
                        match tag {
                            $($index => Ok($name::$variant),)*
                            _ => Err(serde::de::Error::custom("unknown source unit variant")),
                        }
                    }
                }
                deserializer.deserialize_enum(stringify!($name), &[$($tag),*], UnitVisitor)
            }
        }
    };
}

#[cfg(test)]
mod oracle;
#[cfg(test)]
mod tests;
