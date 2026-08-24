use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const MAX_SCHEMA_BYTES: usize = 262_144;
const MAX_TYPES: usize = 128;
const MAX_FIELDS: usize = 1_024;
const MAX_DEPTH: usize = 8;

/// Restricted, language-neutral caller API for one domain package.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileApi {
    schema: String,
    types: BTreeMap<String, ProfileType>,
}

/// One node in the closed profile caller-API grammar.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ProfileType {
    Boolean,
    Uint {
        bits: u8,
        minimum: String,
        maximum: String,
    },
    Int {
        bits: u8,
        minimum: String,
        maximum: String,
    },
    String {
        #[serde(rename = "minimumBytes")]
        minimum_bytes: usize,
        #[serde(rename = "maximumBytes")]
        maximum_bytes: usize,
        alphabet: StringAlphabet,
    },
    Bytes {
        #[serde(rename = "minimumBytes")]
        minimum_bytes: usize,
        #[serde(rename = "maximumBytes")]
        maximum_bytes: usize,
        #[serde(rename = "sourceConvenience", default)]
        source_convenience: Option<SourceConvenience>,
        #[serde(default)]
        sensitive: bool,
    },
    Enum {
        values: Vec<String>,
    },
    Option {
        value: Box<ProfileType>,
    },
    Ref {
        name: String,
    },
    List {
        value: Box<ProfileType>,
        #[serde(rename = "minimumItems")]
        minimum_items: usize,
        #[serde(rename = "maximumItems")]
        maximum_items: usize,
    },
    Record {
        fields: Vec<ProfileField>,
    },
    Union {
        discriminator: String,
        variants: Vec<ProfileVariant>,
    },
}

/// One record field in the restricted schema.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileField {
    name: String,
    value: ProfileType,
    sensitive: bool,
}

/// One closed union branch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileVariant {
    tag: String,
    fields: Vec<ProfileField>,
}

/// Supported bounded string alphabets.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StringAlphabet {
    Utf8,
    AsciiGraphic,
    RegisteredToken,
    LowerToken,
    LowerHex,
    Base64url,
}

/// Generated bounded convenience accepted for one bytes field.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceConvenience {
    File,
}

impl ProfileApi {
    /// Parses and fully validates one `auths.profile-api/1` document.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, recursive, unbounded, colliding,
    /// or otherwise unsupported schema input.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ProfileApiError> {
        if bytes.is_empty() || bytes.len() > MAX_SCHEMA_BYTES {
            return Err(ProfileApiError::Limit);
        }
        let api: Self = serde_json::from_slice(bytes).map_err(|_| ProfileApiError::Malformed)?;
        api.validate()?;
        Ok(api)
    }

    /// Validates all grammar, reference, depth, field-count, and collision rules.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileApiError`] when any type is unsupported, unbounded,
    /// recursive, colliding, or outside the global schema limits.
    pub fn validate(&self) -> Result<(), ProfileApiError> {
        if self.schema != "auths.profile-api/1"
            || self.types.is_empty()
            || self.types.len() > MAX_TYPES
        {
            return Err(ProfileApiError::Unsupported);
        }
        let mut python_names = BTreeSet::new();
        for name in self.types.keys() {
            if !type_name(name) || !python_names.insert(to_snake_case(name)) {
                return Err(ProfileApiError::NameCollision);
            }
        }
        let mut fields = 0_usize;
        for (name, node) in &self.types {
            let mut stack = BTreeSet::new();
            stack.insert(name.as_str());
            self.validate_node(node, 1, &mut fields, &mut stack)?;
        }
        if fields > MAX_FIELDS {
            return Err(ProfileApiError::Limit);
        }
        Ok(())
    }

    /// Returns the exact named type.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ProfileType> {
        self.types.get(name)
    }

    /// Returns the exact named-type map in byte-sorted order.
    #[must_use]
    pub const fn types(&self) -> &BTreeMap<String, ProfileType> {
        &self.types
    }

    /// Computes the closed named-type subset reachable from the supplied roles.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileApiError::UnknownReference`] for an unknown role or
    /// [`ProfileApiError::Recursive`] for a recursive reference graph.
    pub fn reachable_types<'a>(
        &'a self,
        roots: impl IntoIterator<Item = &'a str>,
    ) -> Result<BTreeMap<String, ProfileType>, ProfileApiError> {
        let mut output = BTreeMap::new();
        let mut visiting = BTreeSet::new();
        for root in roots {
            self.collect_named(root, &mut visiting, &mut output)?;
        }
        Ok(output)
    }

    /// Computes the exact worst-case deterministic-CBOR size of a named type.
    ///
    /// All arithmetic is checked and references are expanded only through the
    /// already validated acyclic graph.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileApiError`] for an unknown type or size arithmetic that
    /// exceeds the supported bounds.
    pub fn maximum_encoded_size(&self, name: &str) -> Result<usize, ProfileApiError> {
        let node = self
            .types
            .get(name)
            .ok_or(ProfileApiError::UnknownReference)?;
        self.maximum_node_size(node)
    }

    fn collect_named(
        &self,
        name: &str,
        visiting: &mut BTreeSet<String>,
        output: &mut BTreeMap<String, ProfileType>,
    ) -> Result<(), ProfileApiError> {
        let node = self
            .types
            .get(name)
            .ok_or(ProfileApiError::UnknownReference)?;
        if output.contains_key(name) {
            return Ok(());
        }
        if !visiting.insert(name.to_owned()) {
            return Err(ProfileApiError::Recursive);
        }
        self.collect_refs(node, visiting, output)?;
        visiting.remove(name);
        output.insert(name.to_owned(), node.clone());
        Ok(())
    }

    fn collect_refs(
        &self,
        node: &ProfileType,
        visiting: &mut BTreeSet<String>,
        output: &mut BTreeMap<String, ProfileType>,
    ) -> Result<(), ProfileApiError> {
        match node {
            ProfileType::Ref { name } => self.collect_named(name, visiting, output),
            ProfileType::Option { value } | ProfileType::List { value, .. } => {
                self.collect_refs(value, visiting, output)
            }
            ProfileType::Record { fields } => {
                for field in fields {
                    self.collect_refs(&field.value, visiting, output)?;
                }
                Ok(())
            }
            ProfileType::Union { variants, .. } => {
                for variant in variants {
                    for field in &variant.fields {
                        self.collect_refs(&field.value, visiting, output)?;
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn validate_node<'a>(
        &'a self,
        node: &'a ProfileType,
        depth: usize,
        fields_seen: &mut usize,
        stack: &mut BTreeSet<&'a str>,
    ) -> Result<(), ProfileApiError> {
        if depth > MAX_DEPTH {
            return Err(ProfileApiError::Limit);
        }
        match node {
            ProfileType::Boolean => Ok(()),
            ProfileType::Uint {
                bits,
                minimum,
                maximum,
            } => validate_uint(*bits, minimum, maximum),
            ProfileType::Int {
                bits,
                minimum,
                maximum,
            } => validate_int(*bits, minimum, maximum),
            ProfileType::String {
                minimum_bytes,
                maximum_bytes,
                ..
            } => bounded_range(*minimum_bytes, *maximum_bytes, 65_536),
            ProfileType::Bytes {
                minimum_bytes,
                maximum_bytes,
                ..
            } => bounded_range(*minimum_bytes, *maximum_bytes, 16_777_216),
            ProfileType::Enum { values } => {
                if values.is_empty() || values.len() > 64 {
                    return Err(ProfileApiError::Limit);
                }
                let mut unique = BTreeSet::new();
                if values
                    .iter()
                    .any(|value| !lower_token(value) || !unique.insert(value))
                {
                    return Err(ProfileApiError::InvalidNode);
                }
                Ok(())
            }
            ProfileType::Ref { name } => {
                if !type_name(name) || !self.types.contains_key(name) {
                    return Err(ProfileApiError::UnknownReference);
                }
                if !stack.insert(name) {
                    return Err(ProfileApiError::Recursive);
                }
                let referenced = self
                    .types
                    .get(name)
                    .ok_or(ProfileApiError::UnknownReference)?;
                self.validate_node(referenced, depth + 1, fields_seen, stack)?;
                stack.remove(name.as_str());
                Ok(())
            }
            ProfileType::Option { value } => {
                self.validate_node(value, depth + 1, fields_seen, stack)
            }
            ProfileType::List {
                value,
                minimum_items,
                maximum_items,
            } => {
                bounded_range(*minimum_items, *maximum_items, 4_096)?;
                self.validate_node(value, depth + 1, fields_seen, stack)
            }
            ProfileType::Record { fields } => {
                if fields.is_empty() || fields.len() > 64 {
                    return Err(ProfileApiError::Limit);
                }
                *fields_seen = fields_seen
                    .checked_add(fields.len())
                    .ok_or(ProfileApiError::Limit)?;
                let mut names = BTreeSet::new();
                let mut python_names = BTreeSet::new();
                for field in fields {
                    if field.name == "auths"
                        || !field_name(&field.name)
                        || !names.insert(field.name.as_str())
                        || !python_names.insert(to_snake_case(&field.name))
                    {
                        return Err(ProfileApiError::NameCollision);
                    }
                    self.validate_node(&field.value, depth + 1, fields_seen, stack)?;
                }
                Ok(())
            }
            ProfileType::Union {
                discriminator,
                variants,
            } => {
                if discriminator != "kind" || variants.len() < 2 || variants.len() > 16 {
                    return Err(ProfileApiError::Limit);
                }
                let mut tags = BTreeSet::new();
                for variant in variants {
                    if !lower_token(&variant.tag) || !tags.insert(variant.tag.as_str()) {
                        return Err(ProfileApiError::InvalidNode);
                    }
                    *fields_seen = fields_seen
                        .checked_add(variant.fields.len())
                        .ok_or(ProfileApiError::Limit)?;
                    let mut names = BTreeSet::new();
                    let mut python_names = BTreeSet::new();
                    if variant.fields.len() > 64 {
                        return Err(ProfileApiError::Limit);
                    }
                    for field in &variant.fields {
                        if field.name == *discriminator
                            || field.name == "auths"
                            || !field_name(&field.name)
                            || !names.insert(field.name.as_str())
                            || !python_names.insert(to_snake_case(&field.name))
                        {
                            return Err(ProfileApiError::NameCollision);
                        }
                        self.validate_node(&field.value, depth + 1, fields_seen, stack)?;
                    }
                }
                Ok(())
            }
        }
    }

    fn maximum_node_size(&self, node: &ProfileType) -> Result<usize, ProfileApiError> {
        match node {
            ProfileType::Boolean => Ok(1),
            ProfileType::Uint { maximum, .. } => maximum
                .parse::<u64>()
                .map(cbor_uint_size)
                .map_err(|_| ProfileApiError::InvalidNode),
            ProfileType::Int {
                minimum, maximum, ..
            } => {
                let minimum = minimum
                    .parse::<i64>()
                    .map_err(|_| ProfileApiError::InvalidNode)?;
                let maximum = maximum
                    .parse::<i64>()
                    .map_err(|_| ProfileApiError::InvalidNode)?;
                Ok(cbor_int_size(minimum).max(cbor_int_size(maximum)))
            }
            ProfileType::String { maximum_bytes, .. }
            | ProfileType::Bytes { maximum_bytes, .. } => cbor_head_size(*maximum_bytes)
                .checked_add(*maximum_bytes)
                .ok_or(ProfileApiError::Limit),
            ProfileType::Enum { values } => values
                .iter()
                .map(|value| {
                    cbor_head_size(value.len())
                        .checked_add(value.len())
                        .ok_or(ProfileApiError::Limit)
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .max()
                .ok_or(ProfileApiError::InvalidNode),
            ProfileType::Option { value } => Ok(1_usize.max(self.maximum_node_size(value)?)),
            ProfileType::Ref { name } => self.maximum_encoded_size(name),
            ProfileType::List {
                value,
                maximum_items,
                ..
            } => cbor_head_size(*maximum_items)
                .checked_add(
                    self.maximum_node_size(value)?
                        .checked_mul(*maximum_items)
                        .ok_or(ProfileApiError::Limit)?,
                )
                .ok_or(ProfileApiError::Limit),
            ProfileType::Record { fields } => maximum_record_size(self, fields),
            ProfileType::Union {
                discriminator,
                variants,
            } => variants
                .iter()
                .map(|variant| {
                    let discriminator_size = maximum_text_pair_size(discriminator, &variant.tag)?;
                    cbor_head_size(variant.fields.len() + 1)
                        .checked_add(discriminator_size)
                        .and_then(|value| {
                            maximum_record_fields_size(self, &variant.fields)
                                .ok()
                                .and_then(|fields| value.checked_add(fields))
                        })
                        .ok_or(ProfileApiError::Limit)
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .max()
                .ok_or(ProfileApiError::InvalidNode),
        }
    }
}

fn maximum_record_size(
    api: &ProfileApi,
    fields: &[ProfileField],
) -> Result<usize, ProfileApiError> {
    cbor_head_size(fields.len())
        .checked_add(maximum_record_fields_size(api, fields)?)
        .ok_or(ProfileApiError::Limit)
}

fn maximum_record_fields_size(
    api: &ProfileApi,
    fields: &[ProfileField],
) -> Result<usize, ProfileApiError> {
    fields.iter().try_fold(0_usize, |total, field| {
        let key = cbor_head_size(field.name.len())
            .checked_add(field.name.len())
            .ok_or(ProfileApiError::Limit)?;
        total
            .checked_add(key)
            .and_then(|value| value.checked_add(api.maximum_node_size(&field.value).ok()?))
            .ok_or(ProfileApiError::Limit)
    })
}

fn maximum_text_pair_size(key: &str, value: &str) -> Result<usize, ProfileApiError> {
    cbor_head_size(key.len())
        .checked_add(key.len())
        .and_then(|size| size.checked_add(cbor_head_size(value.len())))
        .and_then(|size| size.checked_add(value.len()))
        .ok_or(ProfileApiError::Limit)
}

const fn cbor_head_size(value: usize) -> usize {
    match value {
        0..=23 => 1,
        24..=255 => 2,
        256..=65_535 => 3,
        65_536..=4_294_967_295 => 5,
        _ => 9,
    }
}

const fn cbor_uint_size(value: u64) -> usize {
    match value {
        0..=23 => 1,
        24..=255 => 2,
        256..=65_535 => 3,
        65_536..=4_294_967_295 => 5,
        _ => 9,
    }
}

const fn cbor_int_size(value: i64) -> usize {
    if value >= 0 {
        cbor_uint_size(value.cast_unsigned())
    } else {
        cbor_uint_size((-1 - value).cast_unsigned())
    }
}

fn bounded_range(minimum: usize, maximum: usize, hard: usize) -> Result<(), ProfileApiError> {
    if minimum > maximum || maximum == 0 || maximum > hard {
        Err(ProfileApiError::InvalidNode)
    } else {
        Ok(())
    }
}

fn validate_uint(bits: u8, minimum: &str, maximum: &str) -> Result<(), ProfileApiError> {
    if !matches!(bits, 8 | 16 | 32 | 64)
        || !canonical_integer(minimum, false)
        || !canonical_integer(maximum, false)
    {
        return Err(ProfileApiError::InvalidNode);
    }
    let min = minimum
        .parse::<u128>()
        .map_err(|_| ProfileApiError::InvalidNode)?;
    let max = maximum
        .parse::<u128>()
        .map_err(|_| ProfileApiError::InvalidNode)?;
    let ceiling = if bits == 64 {
        u128::from(u64::MAX)
    } else {
        (1_u128 << bits) - 1
    };
    if min > max || max > ceiling {
        Err(ProfileApiError::InvalidNode)
    } else {
        Ok(())
    }
}

fn validate_int(bits: u8, minimum: &str, maximum: &str) -> Result<(), ProfileApiError> {
    if !matches!(bits, 8 | 16 | 32 | 64)
        || !canonical_integer(minimum, true)
        || !canonical_integer(maximum, true)
    {
        return Err(ProfileApiError::InvalidNode);
    }
    let min = minimum
        .parse::<i128>()
        .map_err(|_| ProfileApiError::InvalidNode)?;
    let max = maximum
        .parse::<i128>()
        .map_err(|_| ProfileApiError::InvalidNode)?;
    let ceiling = (1_i128 << (bits - 1)) - 1;
    let floor = -(1_i128 << (bits - 1));
    if min > max || min < floor || max > ceiling {
        Err(ProfileApiError::InvalidNode)
    } else {
        Ok(())
    }
}

fn canonical_integer(value: &str, signed: bool) -> bool {
    let digits = value.strip_prefix('-').unwrap_or(value);
    (signed || !value.starts_with('-'))
        && !digits.is_empty()
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'))
        && value != "-0"
}

fn type_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_uppercase()
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn field_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn lower_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn to_snake_case(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 4);
    let characters = value.as_bytes();
    for (index, byte) in characters.iter().copied().enumerate() {
        if byte.is_ascii_uppercase()
            && index > 0
            && (characters[index - 1].is_ascii_lowercase()
                || characters[index - 1].is_ascii_digit()
                || characters
                    .get(index + 1)
                    .is_some_and(u8::is_ascii_lowercase))
        {
            output.push('_');
        }
        output.push(char::from(byte.to_ascii_lowercase()));
    }
    output
}

/// Closed profile API validation error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProfileApiError {
    #[error("profile API exceeds a hard limit")]
    Limit,
    #[error("profile API JSON is malformed")]
    Malformed,
    #[error("profile API semantic identity is unsupported")]
    Unsupported,
    #[error("profile API contains an invalid node")]
    InvalidNode,
    #[error("profile API contains an unknown reference")]
    UnknownReference,
    #[error("profile API contains a recursive reference")]
    Recursive,
    #[error("profile API names collide in a generated binding")]
    NameCollision,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_closed_schema_parses() {
        let api = ProfileApi::from_json(
            br#"{"schema":"auths.profile-api/1","types":{"Input":{"kind":"record","fields":[{"name":"messageId","value":{"kind":"string","minimumBytes":1,"maximumBytes":64,"alphabet":"registered-token"},"sensitive":false}]},"Output":{"kind":"boolean"}}}"#,
        )
        .unwrap();
        assert!(api.get("Input").is_some());
    }

    #[test]
    fn option_and_exact_worst_case_size_are_supported() {
        let api = ProfileApi::from_json(
            br#"{"schema":"auths.profile-api/1","types":{"Input":{"kind":"record","fields":[{"name":"note","value":{"kind":"option","value":{"kind":"string","minimumBytes":1,"maximumBytes":24,"alphabet":"utf8"}},"sensitive":false}]}}}"#,
        )
        .unwrap();
        // one-entry map + 5-byte encoded key + 26-byte maximum text value
        assert_eq!(api.maximum_encoded_size("Input").unwrap(), 32);
    }

    #[test]
    fn records_are_nonempty_and_individually_bounded() {
        let empty =
            br#"{"schema":"auths.profile-api/1","types":{"Input":{"kind":"record","fields":[]}}}"#;
        assert_eq!(
            ProfileApi::from_json(empty).unwrap_err(),
            ProfileApiError::Limit
        );
    }

    #[test]
    fn recursive_and_binding_colliding_schemas_fail() {
        let recursive =
            br#"{"schema":"auths.profile-api/1","types":{"Loop":{"kind":"ref","name":"Loop"}}}"#;
        assert_eq!(
            ProfileApi::from_json(recursive).unwrap_err(),
            ProfileApiError::Recursive
        );
        let colliding = br#"{"schema":"auths.profile-api/1","types":{"Input":{"kind":"record","fields":[{"name":"itemID","value":{"kind":"boolean"},"sensitive":false},{"name":"itemId","value":{"kind":"boolean"},"sensitive":false}]}}}"#;
        assert_eq!(
            ProfileApi::from_json(colliding).unwrap_err(),
            ProfileApiError::NameCollision
        );

        let reserved_record = br#"{"schema":"auths.profile-api/1","types":{"Output":{"kind":"record","fields":[{"name":"auths","value":{"kind":"boolean"},"sensitive":false}]}}}"#;
        assert_eq!(
            ProfileApi::from_json(reserved_record).unwrap_err(),
            ProfileApiError::NameCollision
        );

        let reserved_union = br#"{"schema":"auths.profile-api/1","types":{"Output":{"kind":"union","discriminator":"kind","variants":[{"tag":"ok","fields":[{"name":"auths","value":{"kind":"boolean"},"sensitive":false}]},{"tag":"other","fields":[]}]}}}"#;
        assert_eq!(
            ProfileApi::from_json(reserved_union).unwrap_err(),
            ProfileApiError::NameCollision
        );
    }
}
