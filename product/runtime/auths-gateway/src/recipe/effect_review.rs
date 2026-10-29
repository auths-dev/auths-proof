//! Recipe-owned presentation semantics. Labels and units come only from the
//! operator-approved recipe; values come only from the sealed native command.

use super::{FieldSchema, GatewayRecipeError};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const SCHEMA: &str = "auths.effect-review-contract/1";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReviewContract {
    schema: String,
    consequences: Vec<String>,
    #[serde(deserialize_with = "unique_fields")]
    fields: BTreeMap<String, Presentation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Presentation {
    Text { label: String },
    Identifier { label: String },
    Boolean { label: String },
    Integer { label: String, unit: String },
}

fn unique_fields<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, Presentation>, D::Error> {
    struct Fields;
    impl<'de> serde::de::Visitor<'de> for Fields {
        type Value = BTreeMap<String, Presentation>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("unique review field names")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> Result<Self::Value, M::Error> {
            let mut fields = BTreeMap::new();
            while let Some((key, value)) = map.next_entry()? {
                if fields.len() >= super::MAX_VERIFIED_FIELDS || fields.insert(key, value).is_some()
                {
                    return Err(serde::de::Error::custom("invalid review fields"));
                }
            }
            Ok(fields)
        }
    }
    deserializer.deserialize_map(Fields)
}

fn trusted_text(text: &str, maximum: usize) -> bool {
    !text.is_empty()
        && text.len() <= maximum
        && text.trim() == text
        && text
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
}

fn binding_field(name: &str) -> bool {
    matches!(
        name,
        "operation_id" | "operator_namespace" | "recipe_digest"
    )
}

impl ReviewContract {
    pub(super) fn validate(
        &self,
        fields: &BTreeMap<String, FieldSchema>,
    ) -> Result<(), GatewayRecipeError> {
        let invalid = GatewayRecipeError::InvalidSource;
        if self.schema != SCHEMA
            || self.consequences.is_empty()
            || self.consequences.len() > 8
            || self
                .consequences
                .iter()
                .any(|text| !trusted_text(text, 512))
            || self.fields.len() != fields.keys().filter(|name| !binding_field(name)).count()
        {
            return Err(invalid);
        }
        let mut labels = BTreeSet::new();
        for (name, presentation) in &self.fields {
            if binding_field(name) {
                return Err(invalid);
            }
            let (label, compatible) = match (presentation, fields.get(name)) {
                (
                    Presentation::Text { label } | Presentation::Identifier { label },
                    Some(FieldSchema::String { .. } | FieldSchema::Enum { .. }),
                )
                | (Presentation::Boolean { label }, Some(FieldSchema::Boolean)) => (label, true),
                (Presentation::Integer { label, unit }, Some(FieldSchema::Integer { .. })) => {
                    (label, trusted_text(unit, 80))
                }
                _ => return Err(invalid),
            };
            if !compatible || !trusted_text(label, 80) || !labels.insert(label.to_ascii_lowercase())
            {
                return Err(invalid);
            }
        }
        Ok(())
    }

    /// Required full values are never truncated or interpreted as markup.
    pub(super) fn project(
        &self,
        arguments: &Map<String, Value>,
    ) -> Result<Value, GatewayRecipeError> {
        let fields = self
            .fields
            .iter()
            .map(|(name, presentation)| {
                let value = arguments
                    .get(name)
                    .ok_or(GatewayRecipeError::InvalidSource)?;
                let mut field = serde_json::to_value(presentation)
                    .map_err(|_| GatewayRecipeError::InvalidSource)?;
                field["argument"] = Value::String(name.clone());
                field["value"] = value.clone();
                Ok(field)
            })
            .collect::<Result<Vec<_>, GatewayRecipeError>>()?;
        Ok(serde_json::json!({
            "schema": SCHEMA,
            "presentation": "literal-complete-values/1",
            "consequences": self.consequences,
            "fields": fields,
        }))
    }
}

/// Explicitly synthetic declarations for native test builders, never production
/// authoring defaults. Production recipes must provide their own semantics.
#[cfg(any(test, feature = "testkit-harness"))]
pub(crate) fn synthetic_review(fields: &Value) -> Value {
    let declarations = fields
        .as_object()
        .into_iter()
        .flat_map(|fields| fields.iter())
        .filter(|(name, _)| !binding_field(name))
        .map(|(name, field)| {
            let kind = field
                .get("kind")
                .or_else(|| field.get("type"))
                .and_then(Value::as_str);
            let presentation = match kind {
                Some("integer") => {
                    serde_json::json!({"kind": "integer", "label": name, "unit": "synthetic units"})
                }
                Some("boolean") => serde_json::json!({"kind": "boolean", "label": name}),
                _ => serde_json::json!({"kind": "text", "label": name}),
            };
            (name.clone(), presentation)
        })
        .collect::<Map<_, _>>();
    serde_json::json!({"schema": SCHEMA, "fields": declarations, "consequences": ["Synthetic fixture mutation; no production semantics or human-review claim."]})
}
