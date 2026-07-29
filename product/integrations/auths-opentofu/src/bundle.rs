//! Bounded, agent-proposed OpenTofu source bundles.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    canonical::{canonical_digest, canonical_json},
    errors::{CanonicalError, ValidationError},
    types::DigestHex,
};

/// Hard source-file count.
pub const HARD_MAX_SOURCE_FILES: usize = 128;
/// Hard total source bytes.
pub const HARD_MAX_SOURCE_BYTES: usize = 2 * 1024 * 1024;
/// Hard single text value.
pub const HARD_MAX_TEXT_BYTES: usize = 256 * 1024;
/// Hard lexical delimiter nesting before invoking an HCL parser.
pub const HARD_MAX_EXPRESSION_DEPTH: usize = 64;

/// One pinned remote or local module.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModulePinV1 {
    pub source: String,
    pub version: String,
    pub digest: DigestHex,
}

/// Bounded source submitted to the protected planner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenTofuSourceBundleV1 {
    pub root_module_files: BTreeMap<String, String>,
    pub variable_values: BTreeMap<String, String>,
    pub dependency_lock_file: String,
    pub module_manifest: Vec<ModulePinV1>,
    pub requested_workspace: String,
}

impl OpenTofuSourceBundleV1 {
    /// Validates paths, limits, pins, and the closed MVP feature surface.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.root_module_files.is_empty()
            || self.root_module_files.len() > HARD_MAX_SOURCE_FILES
            || self.requested_workspace.is_empty()
            || self.requested_workspace.len() > 128
            || self.dependency_lock_file.is_empty()
            || self.dependency_lock_file.len() > HARD_MAX_TEXT_BYTES
        {
            return Err(ValidationError::LimitExceeded);
        }
        let mut total = self.dependency_lock_file.len();
        for (path, contents) in &self.root_module_files {
            validate_path(path)?;
            if contents.len() > HARD_MAX_TEXT_BYTES {
                return Err(ValidationError::LimitExceeded);
            }
            total = total
                .checked_add(path.len())
                .and_then(|value| value.checked_add(contents.len()))
                .ok_or(ValidationError::LimitExceeded)?;
            reject_forbidden_hcl(contents)?;
        }
        for (name, value) in &self.variable_values {
            if !valid_identifier(name) || value.len() > HARD_MAX_TEXT_BYTES {
                return Err(ValidationError::Malformed);
            }
            total = total
                .checked_add(name.len())
                .and_then(|bytes| bytes.checked_add(value.len()))
                .ok_or(ValidationError::LimitExceeded)?;
        }
        if total > HARD_MAX_SOURCE_BYTES {
            return Err(ValidationError::LimitExceeded);
        }
        if self.module_manifest.iter().any(|module| {
            module.source.is_empty()
                || module.source.len() > 512
                || module.version.is_empty()
                || module.version.len() > 128
                || module.version == "latest"
        }) {
            return Err(ValidationError::DependencyNotPinned);
        }
        let mut modules = self.module_manifest.clone();
        modules.sort_by(|left, right| {
            (&left.source, &left.version, &left.digest).cmp(&(
                &right.source,
                &right.version,
                &right.digest,
            ))
        });
        if modules != self.module_manifest
            || modules
                .windows(2)
                .any(|pair| pair[0].source == pair[1].source)
        {
            return Err(ValidationError::NonCanonical);
        }
        Ok(())
    }

    /// Returns canonical bytes after validation.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ValidationError> {
        self.validate()?;
        canonical_json(self).map_err(|_| ValidationError::Malformed)
    }

    /// Commits to every file, variable, lock, pin, and workspace.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

fn validate_path(path: &str) -> Result<(), ValidationError> {
    let extension_is_tf = std::path::Path::new(path)
        .extension()
        .is_some_and(|extension| extension == "tf");
    if path.is_empty()
        || path.len() > 512
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.split('/').any(|segment| {
            segment.is_empty() || segment == "." || segment == ".." || segment.starts_with('.')
        })
        || !extension_is_tf
    {
        return Err(ValidationError::Malformed);
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && value.len() <= 128
}

fn reject_forbidden_hcl(contents: &str) -> Result<(), ValidationError> {
    let mut depth = 0_usize;
    for character in contents.chars() {
        match character {
            '{' | '[' | '(' => {
                depth = depth.checked_add(1).ok_or(ValidationError::LimitExceeded)?;
                if depth > HARD_MAX_EXPRESSION_DEPTH {
                    return Err(ValidationError::LimitExceeded);
                }
            }
            '}' | ']' | ')' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    let normalized: String = contents
        .chars()
        .map(|character| {
            if character.is_ascii_whitespace() {
                ' '
            } else {
                character.to_ascii_lowercase()
            }
        })
        .collect();
    let forbidden = [
        "provisioner ",
        "backend ",
        "terraform_remote_state",
        "data \"external\"",
        "source = \"./",
        "source=\"./",
    ];
    if forbidden.iter().any(|needle| normalized.contains(needle)) {
        return Err(ValidationError::ForbiddenFeature);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> OpenTofuSourceBundleV1 {
        OpenTofuSourceBundleV1 {
            root_module_files: BTreeMap::from([(
                "main.tf".into(),
                "resource \"cloudflare_record\" \"demo\" {}".into(),
            )]),
            variable_values: BTreeMap::from([("value".into(), "reviewed".into())]),
            dependency_lock_file: "provider \"registry.opentofu.org/cloudflare/cloudflare\" {}"
                .into(),
            module_manifest: Vec::new(),
            requested_workspace: "demo".into(),
        }
    }

    #[test]
    fn source_bundle_rejects_traversal_and_forbidden_hooks() {
        let mut traversal = bundle();
        traversal
            .root_module_files
            .insert("../main.tf".into(), String::new());
        assert_eq!(traversal.validate(), Err(ValidationError::Malformed));

        let mut provisioner = bundle();
        provisioner.root_module_files.insert(
            "hook.tf".into(),
            "provisioner \"local-exec\" { command = \"id\" }".into(),
        );
        assert_eq!(
            provisioner.validate(),
            Err(ValidationError::ForbiddenFeature)
        );

        let mut deeply_nested = bundle();
        deeply_nested
            .root_module_files
            .insert("deep.tf".into(), "(".repeat(HARD_MAX_EXPRESSION_DEPTH + 1));
        assert_eq!(
            deeply_nested.validate(),
            Err(ValidationError::LimitExceeded)
        );
    }
}
