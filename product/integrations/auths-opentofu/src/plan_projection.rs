//! Sanitized, deterministic projection of `tofu show -json` output.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    canonical::{canonical_digest, canonical_json, sha256},
    errors::{CanonicalError, ValidationError},
    types::{
        DigestHex, HARD_MAX_RESOURCE_CHANGES, OpenTofuVerifierConfigurationV1, ResourceAction,
    },
};

const HARD_MAX_SHOW_JSON_BYTES: usize = 16 * 1024 * 1024;
const HARD_MAX_PATHS_PER_CHANGE: usize = 4_096;

/// One sanitized resource change.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceChangeV1 {
    pub address: String,
    pub provider_source: String,
    pub resource_type: String,
    pub resource_name: String,
    pub actions: Vec<ResourceAction>,
    pub before_commitment: DigestHex,
    pub after_commitment: DigestHex,
    pub sensitive_paths: Vec<String>,
    pub unknown_paths: Vec<String>,
    pub replacement_paths: Vec<String>,
}

/// Sanitized plan semantics safe to include by commitment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedPlanProjectionV1 {
    pub format_version: String,
    pub terraform_version: String,
    pub resource_changes: Vec<ResourceChangeV1>,
    pub output_change_commitments: Vec<DigestHex>,
    pub checks_commitment: DigestHex,
    pub provider_configuration_commitment: DigestHex,
}

impl SavedPlanProjectionV1 {
    /// Parses bounded OpenTofu JSON and immediately applies the closed policy.
    pub fn from_show_json(
        bytes: &[u8],
        configuration: &OpenTofuVerifierConfigurationV1,
    ) -> Result<Self, ValidationError> {
        if bytes.is_empty() || bytes.len() > HARD_MAX_SHOW_JSON_BYTES {
            return Err(ValidationError::LimitExceeded);
        }
        configuration.validate()?;
        let root: Value = serde_json::from_slice(bytes).map_err(|_| ValidationError::Malformed)?;
        let object = root.as_object().ok_or(ValidationError::Malformed)?;
        let format_version = string_field(object, "format_version")?;
        let terraform_version = string_field(object, "terraform_version")?;
        if !configuration
            .allowed_opentofu_versions()
            .iter()
            .any(|version| version == &terraform_version)
        {
            return Err(ValidationError::UnsupportedProfile);
        }
        let raw_changes = object
            .get("resource_changes")
            .and_then(Value::as_array)
            .ok_or(ValidationError::Malformed)?;
        if raw_changes.len()
            > usize::try_from(configuration.maximum_resource_changes())
                .map_err(|_| ValidationError::LimitExceeded)?
            || raw_changes.len() > HARD_MAX_RESOURCE_CHANGES
        {
            return Err(ValidationError::LimitExceeded);
        }
        let mut resource_changes = raw_changes
            .iter()
            .map(|change| project_change(change, configuration))
            .collect::<Result<Vec<_>, _>>()?;
        resource_changes.sort_by(|left, right| left.address.cmp(&right.address));
        if resource_changes
            .windows(2)
            .any(|pair| pair[0].address == pair[1].address)
        {
            return Err(ValidationError::Malformed);
        }
        let mut output_changes = object
            .get("output_changes")
            .and_then(Value::as_object)
            .map_or_else(
                || Ok(Vec::new()),
                |outputs| {
                    outputs
                        .iter()
                        .map(|(name, value)| {
                            if !configuration.allow_sensitive_outputs()
                                && contains_true(
                                    value.get("after_sensitive").unwrap_or(&Value::Null),
                                )
                            {
                                return Err(ValidationError::ChangeOutsideProfile);
                            }
                            canonical_json(&(name, value))
                                .map(|bytes| sha256(&bytes))
                                .map_err(|_| ValidationError::Malformed)
                        })
                        .collect::<Result<Vec<_>, _>>()
                },
            )?;
        output_changes.sort();
        let checks_commitment = commit_value(object.get("checks").unwrap_or(&Value::Null))?;
        let provider_configuration_commitment = commit_value(
            object
                .get("configuration")
                .and_then(|configuration| configuration.get("provider_config"))
                .unwrap_or(&Value::Null),
        )?;
        Ok(Self {
            format_version,
            terraform_version,
            resource_changes,
            output_change_commitments: output_changes,
            checks_commitment,
            provider_configuration_commitment,
        })
    }

    pub fn validate(
        &self,
        configuration: &OpenTofuVerifierConfigurationV1,
    ) -> Result<(), ValidationError> {
        if self.resource_changes.len()
            > usize::try_from(configuration.maximum_resource_changes())
                .map_err(|_| ValidationError::LimitExceeded)?
            || !configuration
                .allowed_opentofu_versions()
                .contains(&self.terraform_version)
        {
            return Err(ValidationError::ChangeOutsideProfile);
        }
        for change in &self.resource_changes {
            validate_projected_change(change, configuration)?;
        }
        if self
            .resource_changes
            .windows(2)
            .any(|pair| pair[0].address >= pair[1].address)
        {
            return Err(ValidationError::NonCanonical);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

fn project_change(
    value: &Value,
    configuration: &OpenTofuVerifierConfigurationV1,
) -> Result<ResourceChangeV1, ValidationError> {
    let object = value.as_object().ok_or(ValidationError::Malformed)?;
    let address = string_field(object, "address")?;
    let provider_source = object
        .get("provider_name")
        .or_else(|| object.get("provider_source"))
        .and_then(Value::as_str)
        .ok_or(ValidationError::Malformed)?
        .to_owned();
    let resource_type = string_field(object, "type")?;
    let resource_name = string_field(object, "name")?;
    let change = object
        .get("change")
        .and_then(Value::as_object)
        .ok_or(ValidationError::Malformed)?;
    let action_values = change
        .get("actions")
        .and_then(Value::as_array)
        .ok_or(ValidationError::Malformed)?;
    let actions = action_values
        .iter()
        .map(parse_action)
        .collect::<Result<Vec<_>, _>>()?;
    let before_commitment = commit_value(change.get("before").unwrap_or(&Value::Null))?;
    let after_commitment = commit_value(change.get("after").unwrap_or(&Value::Null))?;
    let mut sensitive_paths = Vec::new();
    collect_true_paths(
        change.get("before_sensitive").unwrap_or(&Value::Null),
        "",
        &mut sensitive_paths,
    )?;
    collect_true_paths(
        change.get("after_sensitive").unwrap_or(&Value::Null),
        "",
        &mut sensitive_paths,
    )?;
    sensitive_paths.sort();
    sensitive_paths.dedup();
    let mut unknown_paths = Vec::new();
    collect_true_paths(
        change.get("after_unknown").unwrap_or(&Value::Null),
        "",
        &mut unknown_paths,
    )?;
    unknown_paths.sort();
    unknown_paths.dedup();
    let replacement_paths = change
        .get("replace_paths")
        .and_then(Value::as_array)
        .map_or_else(
            || Ok(Vec::new()),
            |paths| paths.iter().map(path_string).collect::<Result<Vec<_>, _>>(),
        )?;
    let projected = ResourceChangeV1 {
        address,
        provider_source,
        resource_type,
        resource_name,
        actions,
        before_commitment,
        after_commitment,
        sensitive_paths,
        unknown_paths,
        replacement_paths,
    };
    validate_projected_change(&projected, configuration)?;
    Ok(projected)
}

fn validate_projected_change(
    change: &ResourceChangeV1,
    configuration: &OpenTofuVerifierConfigurationV1,
) -> Result<(), ValidationError> {
    if change.address.is_empty()
        || change.address.len() > 1_024
        || change.resource_name.is_empty()
        || change.actions.is_empty()
        || change.actions.len() > 2
        || change.sensitive_paths.len() > HARD_MAX_PATHS_PER_CHANGE
        || change.unknown_paths.len() > HARD_MAX_PATHS_PER_CHANGE
        || change.replacement_paths.len() > HARD_MAX_PATHS_PER_CHANGE
    {
        return Err(ValidationError::Malformed);
    }
    if change.actions.contains(&ResourceAction::Delete) {
        if change.actions.contains(&ResourceAction::Create) || !change.replacement_paths.is_empty()
        {
            return Err(ValidationError::ReplacementDenied);
        }
        return Err(ValidationError::DestroyDenied);
    }
    if !change.replacement_paths.is_empty() {
        return Err(ValidationError::ReplacementDenied);
    }
    if !configuration
        .allowed_provider_sources()
        .contains(&change.provider_source)
        || !configuration
            .allowed_resource_types()
            .contains(&change.resource_type)
        || change
            .actions
            .iter()
            .any(|action| !configuration.allowed_actions().contains(action))
    {
        return Err(ValidationError::ChangeOutsideProfile);
    }
    Ok(())
}

fn parse_action(value: &Value) -> Result<ResourceAction, ValidationError> {
    match value.as_str().ok_or(ValidationError::Malformed)? {
        "no-op" => Ok(ResourceAction::NoOp),
        "create" => Ok(ResourceAction::Create),
        "read" => Ok(ResourceAction::Read),
        "update" => Ok(ResourceAction::Update),
        "delete" => Ok(ResourceAction::Delete),
        _ => Err(ValidationError::ChangeOutsideProfile),
    }
}

fn string_field(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<String, ValidationError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 1_024)
        .map(str::to_owned)
        .ok_or(ValidationError::Malformed)
}

fn commit_value(value: &Value) -> Result<DigestHex, ValidationError> {
    canonical_json(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|_| ValidationError::Malformed)
}

fn contains_true(value: &Value) -> bool {
    match value {
        Value::Bool(value) => *value,
        Value::Array(values) => values.iter().any(contains_true),
        Value::Object(values) => values.values().any(contains_true),
        _ => false,
    }
}

fn collect_true_paths(
    value: &Value,
    prefix: &str,
    output: &mut Vec<String>,
) -> Result<(), ValidationError> {
    if output.len() > HARD_MAX_PATHS_PER_CHANGE {
        return Err(ValidationError::LimitExceeded);
    }
    match value {
        Value::Bool(true) => output.push(prefix.to_owned()),
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                collect_true_paths(child, &format!("{prefix}/{index}"), output)?;
            }
        }
        Value::Object(values) => {
            for (key, child) in values {
                collect_true_paths(child, &format!("{prefix}/{}", escape_pointer(key)), output)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn path_string(value: &Value) -> Result<String, ValidationError> {
    let path = value.as_array().ok_or(ValidationError::Malformed)?;
    if path.len() > 64 {
        return Err(ValidationError::LimitExceeded);
    }
    let mut output = String::new();
    for component in path {
        output.push('/');
        match component {
            Value::String(value) => output.push_str(&escape_pointer(value)),
            Value::Number(value) => output.push_str(&value.to_string()),
            _ => return Err(ValidationError::Malformed),
        }
    }
    Ok(output)
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::test_support::configuration;

    fn show(actions: &[&str], replace_paths: &Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "format_version": "1.2",
            "terraform_version": "1.9.0",
            "resource_changes": [{
                "address": "cloudflare_dns_record.demo",
                "provider_name": "registry.opentofu.org/cloudflare/cloudflare",
                "type": "cloudflare_dns_record",
                "name": "demo",
                "change": {
                    "actions": actions,
                    "before": {"content": "old"},
                    "after": {"content": "new"},
                    "after_unknown": {"id": true},
                    "before_sensitive": {},
                    "after_sensitive": {},
                    "replace_paths": replace_paths
                }
            }],
            "output_changes": {},
            "checks": [],
            "configuration": {"provider_config": {}}
        }))
        .unwrap()
    }

    #[test]
    fn projection_denies_destroy_and_replacement() {
        assert_eq!(
            SavedPlanProjectionV1::from_show_json(
                &show(&["delete"], &Value::Array(Vec::new())),
                &configuration()
            ),
            Err(ValidationError::DestroyDenied)
        );
        assert_eq!(
            SavedPlanProjectionV1::from_show_json(
                &show(&["delete", "create"], &json!([["content"]])),
                &configuration()
            ),
            Err(ValidationError::ReplacementDenied)
        );
    }
}
