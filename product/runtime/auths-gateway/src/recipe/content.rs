//! Recipe-declared content acquisition. Request construction reuses the closed
//! path/header leaf; response projection is bounded and never releases bytes.

use super::*;
use std::collections::BTreeSet;
use zeroize::Zeroizing;

/// Versioned opt-in capability inside the digest-bound recipe source.
pub const CONTENT_READ_SCHEMA: &str = "auths.gateway-content-read/1";

/// Why retained provider evidence cannot produce the declared private content.
/// These are response facts, never native authorization denials.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContentProjectionError {
    /// The response status differs from the declared successful status.
    #[error("provider response status does not permit content projection")]
    Status,
    /// Response media type or charset differs from the declared representation.
    #[error("provider response media type does not permit content projection")]
    MediaType,
    /// Raw response exceeds its independently charged bound.
    #[error("provider response exceeds the declared byte limit")]
    ResponseLimit,
    /// Invalid UTF-8, malformed or duplicate-member JSON.
    #[error("provider content is malformed")]
    Malformed,
    /// The declared JSON pointer is absent or does not select a string.
    #[error("provider response lacks the declared string projection")]
    Projection,
    /// The exact projected content exceeds the limit; it is never truncated.
    #[error("projected content exceeds the declared byte limit")]
    ContentLimit,
}

impl ContentProjectionError {
    /// Stable redacted failure code, independent of provider content.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Status => "gateway.content.response-status",
            Self::MediaType => "gateway.content.response-media-type",
            Self::ResponseLimit => "gateway.content.response-too-large",
            Self::Malformed => "gateway.content.invalid-response",
            Self::Projection => "gateway.content.missing-projection",
            Self::ContentLimit => "gateway.content.content-too-large",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ContentSource {
    schema: String,
    resource_field: String,
    path: Vec<PathSegment>,
    query: Vec<QueryPair>,
    projection: ContentProjection,
    maximum_response_bytes: u64,
    maximum_content_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct QueryPair {
    name: String,
    value: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum ContentProjection {
    Utf8,
    JsonString { pointer: String },
}

impl ContentSource {
    pub(super) fn validate(
        &self,
        fields: &BTreeMap<String, FieldSchema>,
    ) -> Result<(), GatewayRecipeError> {
        if self.schema != CONTENT_READ_SCHEMA
            || matches!(
                self.resource_field.as_str(),
                "operation_id" | "operator_namespace" | "recipe_digest"
            )
            || !fields
                .get(&self.resource_field)
                .is_some_and(FieldSchema::is_path_scalar)
            || !(1..=65_536).contains(&self.maximum_response_bytes)
            || !(1..=self.maximum_response_bytes).contains(&self.maximum_content_bytes)
            || self.query.len() > 8
            || !self.path.iter().any(
                |part| matches!(part, PathSegment::Field { name } if name == &self.resource_field),
            )
            || self.path.iter().any(|part| match part {
                PathSegment::Fixed { .. } => false,
                PathSegment::Field { name } => name != &self.resource_field,
                PathSegment::Echo | PathSegment::ResponseField { .. } => true,
            })
        {
            return Err(GatewayRecipeError::InvalidSource);
        }
        super::validate::validate_content_path(&self.path, fields)?;
        let mut previous = None;
        for query in &self.query {
            if query.name.is_empty()
                || query.name.len() > 64
                || !query
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                || query.value.len() > 512
                || query.value.chars().any(char::is_control)
                || previous.is_some_and(|name: &str| name >= query.name.as_str())
            {
                return Err(GatewayRecipeError::InvalidSource);
            }
            previous = Some(query.name.as_str());
        }
        if let ContentProjection::JsonString { pointer } = &self.projection {
            if !super::validate::valid_response_pointer(pointer) || !valid_escapes(pointer) {
                return Err(GatewayRecipeError::InvalidSource);
            }
        }
        Ok(())
    }
}

fn valid_escapes(pointer: &str) -> bool {
    let mut bytes = pointer.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'~' && !matches!(bytes.next(), Some(b'0' | b'1')) {
            return false;
        }
    }
    true
}

/// Compiler-owned GET and projection. It is data, never an acquisition or
/// disclosure permit, and has no deserializer. Content cannot be derived from
/// credential probes or recovery reads by selecting this type at runtime.
#[derive(Clone)]
pub struct ClosedContentRead {
    read: ClosedActionRead,
    projection: ContentProjection,
    maximum_content_bytes: usize,
    arguments: Map<String, Value>,
}

impl std::fmt::Debug for ClosedContentRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClosedContentRead { private: [redacted] }")
    }
}

impl ClosedContentRead {
    pub(crate) const fn transport(&self) -> &ClosedActionRead {
        &self.read
    }

    pub(crate) fn private_request(&self) -> Value {
        serde_json::json!({
            "method": "GET", "url": self.read.url(),
            "headers": self.read.headers().iter().map(|h| (h.name(), h.value())).collect::<Vec<_>>(),
            "maximum_response_bytes": self.read.maximum_response_bytes(),
        })
    }
    /// Complete private request and interpretation contract for native review
    /// and effect identity. It contains no provider response or credential.
    #[must_use]
    pub fn private_contract(&self) -> Value {
        serde_json::json!({
            "schema": CONTENT_READ_SCHEMA,
            "request": self.private_request(),
            "resource_arguments": self.arguments,
            "projection": self.projection,
            "maximum_content_bytes": self.maximum_content_bytes,
            "required_status": 200,
            "required_media_type": self.media_type(),
            "maximum_transport_seconds": 15,
            "disclosure": "separate-authorization-required",
        })
    }

    /// The exact expected response media type. Only an optional UTF-8 charset
    /// is accepted by projection. The caller must establish identity encoding
    /// from retained transport metadata before projecting response bytes.
    #[must_use]
    pub const fn media_type(&self) -> &'static str {
        match self.projection {
            ContentProjection::Utf8 => "text/plain",
            ContentProjection::JsonString { .. } => "application/json",
        }
    }

    /// Projects an acquired response into a private, zeroizing buffer. This
    /// function does no I/O and authorizes no disclosure. The caller must supply
    /// authenticated transport facts from the corresponding durable acquisition.
    /// No truncation, lossy UTF-8 conversion or last-key-wins JSON is permitted.
    ///
    /// # Errors
    /// Refuses status/media mismatch, oversized content, invalid UTF-8, duplicate
    /// JSON, missing/non-string projections or malformed provider responses.
    pub fn project_response(
        &self,
        status: u16,
        media_type: &str,
        body: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ContentProjectionError> {
        if status != 200 {
            return Err(ContentProjectionError::Status);
        }
        if body.len() > self.read.maximum_response_bytes() {
            return Err(ContentProjectionError::ResponseLimit);
        }
        if media_type.len() > 128 || !self.accepts_media_type(media_type) {
            return Err(ContentProjectionError::MediaType);
        }
        let content = match &self.projection {
            ContentProjection::Utf8 => {
                std::str::from_utf8(body).map_err(|_| ContentProjectionError::Malformed)?;
                Zeroizing::new(body.to_vec())
            }
            ContentProjection::JsonString { pointer } => {
                let document =
                    parse_provider_response(body).ok_or(ContentProjectionError::Malformed)?;
                let value = document
                    .pointer(pointer)
                    .and_then(Value::as_str)
                    .ok_or(ContentProjectionError::Projection)?;
                Zeroizing::new(value.as_bytes().to_vec())
            }
        };
        if content.len() > self.maximum_content_bytes {
            return Err(ContentProjectionError::ContentLimit);
        }
        Ok(content)
    }

    fn accepts_media_type(&self, value: &str) -> bool {
        let mut parts = value.split(';');
        let matches = parts
            .next()
            .is_some_and(|base| base.trim().eq_ignore_ascii_case(self.media_type()));
        matches
            && match (parts.next(), parts.next()) {
                (None, None) => true,
                (Some(parameter), None) => parameter.trim().eq_ignore_ascii_case("charset=utf-8"),
                _ => false,
            }
    }
}

impl CompiledRecipe {
    /// Compiles the recipe's explicit content capability for an exact resource
    /// and optional account scope. The argument set is closed: unused fields,
    /// operation IDs, caller URLs and implicit recovery targets are refused.
    /// This authoring data must later be bound to native read authority and exact
    /// approval; constructing it grants neither custody nor external entry.
    ///
    /// # Errors
    /// Refuses an absent declaration, missing/extra/invalid arguments, unsafe
    /// path values or a request exceeding the existing 8,192-byte URL bound.
    pub fn content_read(
        &self,
        arguments: &Map<String, Value>,
    ) -> Result<ClosedContentRead, GatewayRecipeError> {
        let source = self
            .source
            .content
            .as_ref()
            .ok_or(GatewayRecipeError::InvalidSource)?;
        let mut names = BTreeSet::from([source.resource_field.as_str()]);
        if let Some(scope) = &self.source.account_scope {
            names.insert(scope.field.as_str());
        }
        if arguments.len() != names.len()
            || arguments.keys().any(|name| !names.contains(name.as_str()))
        {
            return Err(GatewayRecipeError::ActionMismatch);
        }
        for (name, value) in arguments {
            if !self
                .fields
                .get(name)
                .is_some_and(|schema| schema.validate_value(value))
            {
                return Err(GatewayRecipeError::ActionMismatch);
            }
        }
        // Unused profile slots are deliberately non-path values. The closed
        // plan may consume only the exact resource and declared account scope.
        let values = self
            .fields
            .iter()
            .map(|(name, schema)| {
                arguments
                    .get(name)
                    .and_then(|value| schema.argument_value(value))
                    .unwrap_or(ArgumentValue::Boolean(false))
            })
            .collect::<Vec<_>>();
        let plan = super::lower::content_plan(&self.source, &self.fields, &source.path)?;
        let mut read = ClosedActionRead::construct(
            &plan,
            &values,
            bounded_usize(source.maximum_response_bytes),
        )?;
        if !source.query.is_empty() {
            let mut url = read.url.into_bytes();
            for (index, pair) in source.query.iter().enumerate() {
                url.push(if index == 0 { b'?' } else { b'&' });
                url = construct::append_path_encoded(url, pair.name.as_bytes());
                url.push(b'=');
                url = construct::append_path_encoded(url, pair.value.as_bytes());
            }
            if url.len() > construct::MAX_PATH_BYTES {
                return Err(GatewayRecipeError::UnsafePath);
            }
            read.url = ascii(url)?;
        }
        Ok(ClosedContentRead {
            read,
            projection: source.projection.clone(),
            maximum_content_bytes: bounded_usize(source.maximum_content_bytes),
            arguments: arguments.clone(),
        })
    }
}
