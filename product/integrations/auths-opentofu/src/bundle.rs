//! Bounded, agent-proposed OpenTofu source bundles.

use std::collections::{BTreeMap, BTreeSet};

use hcl::{
    Body, Expression, ObjectKey, Structure,
    expr::{Operation, TraversalOperator},
};
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
const HARD_MAX_HCL_STRUCTURES: usize = 4_096;
const HARD_MAX_EXPRESSION_NODES: usize = 16_384;

/// Structurally parsed static provider and module closure from all root files.
#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct HclDependencyClosure {
    pub(crate) providers: BTreeSet<(String, String)>,
    pub(crate) modules: BTreeSet<(String, String)>,
    provider_local_names: BTreeMap<String, (String, String)>,
    provider_usages: BTreeSet<String>,
}

/// Commitment to the deliberately empty v1 module closure.
pub(crate) fn empty_module_manifest_digest() -> Result<DigestHex, CanonicalError> {
    canonical_digest(&Vec::<String>::new())
}

/// Bounded source submitted to the protected planner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenTofuSourceBundleV1 {
    pub root_module_files: BTreeMap<String, String>,
    pub variable_values: BTreeMap<String, String>,
    pub dependency_lock_file: String,
    pub requested_workspace: String,
}

impl OpenTofuSourceBundleV1 {
    /// Validates paths, limits, pins, and the closed MVP feature surface.
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.validated_hcl_dependency_closure().map(|_| ())
    }

    /// Parses every root file and returns its exact static provider/module set.
    pub(crate) fn hcl_dependency_closure(&self) -> Result<HclDependencyClosure, ValidationError> {
        self.validated_hcl_dependency_closure()
    }

    fn validated_hcl_dependency_closure(&self) -> Result<HclDependencyClosure, ValidationError> {
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
        let mut closure = HclDependencyClosure::default();
        let mut structures = 0_usize;
        for (path, contents) in &self.root_module_files {
            validate_path(path)?;
            if contents.len() > HARD_MAX_TEXT_BYTES {
                return Err(ValidationError::LimitExceeded);
            }
            total = total
                .checked_add(path.len())
                .and_then(|value| value.checked_add(contents.len()))
                .ok_or(ValidationError::LimitExceeded)?;
            inspect_hcl_file(contents, &mut closure, &mut structures)?;
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
        if !closure
            .provider_usages
            .iter()
            .all(|name| closure.provider_local_names.contains_key(name))
        {
            return Err(ValidationError::DependencyNotPinned);
        }
        Ok(closure)
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
        || path.contains('/')
        || path.contains('\\')
        || path.split('/').any(|segment| {
            segment.is_empty() || segment == "." || segment == ".." || segment.starts_with('.')
        })
        || !extension_is_tf
        || path == "override.tf"
        || path.ends_with("_override.tf")
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

fn inspect_hcl_file(
    contents: &str,
    closure: &mut HclDependencyClosure,
    structures: &mut usize,
) -> Result<(), ValidationError> {
    let mut recursion_tokens = 0_usize;
    for character in contents.chars() {
        match character {
            // Deliberately monotonic and conservative: quotes/comments cannot
            // cancel this pre-parser recursion budget.
            '{' | '[' | '(' | '?' | '!' | '-' => {
                recursion_tokens = recursion_tokens
                    .checked_add(1)
                    .ok_or(ValidationError::LimitExceeded)?;
                if recursion_tokens > HARD_MAX_EXPRESSION_DEPTH {
                    return Err(ValidationError::LimitExceeded);
                }
            }
            _ => {}
        }
    }
    let body = hcl::parse(contents).map_err(|_| ValidationError::Malformed)?;
    let mut expression_nodes = 0_usize;
    inspect_hcl_body(&body, closure, structures, &mut expression_nodes, None)
}

fn inspect_hcl_body(
    body: &Body,
    closure: &mut HclDependencyClosure,
    structures: &mut usize,
    expression_nodes: &mut usize,
    parent: Option<&str>,
) -> Result<(), ValidationError> {
    for structure in body.iter() {
        *structures = structures
            .checked_add(1)
            .ok_or(ValidationError::LimitExceeded)?;
        if *structures > HARD_MAX_HCL_STRUCTURES {
            return Err(ValidationError::LimitExceeded);
        }
        let Structure::Block(block) = structure else {
            if let Structure::Attribute(attribute) = structure {
                inspect_expression(attribute.expr(), expression_nodes, 0)?;
            }
            continue;
        };
        let identifier = block.identifier();
        if matches!(
            identifier,
            "terraform" | "module" | "resource" | "data" | "provider"
        ) && parent.is_some()
        {
            return Err(ValidationError::Malformed);
        }
        match identifier {
            "provisioner" | "backend" | "import" | "moved" | "removed" => {
                return Err(ValidationError::ForbiddenFeature);
            }
            "data"
                if block.labels().first().is_some_and(|label| {
                    matches!(label.as_str(), "external" | "terraform_remote_state")
                }) =>
            {
                return Err(ValidationError::ForbiddenFeature);
            }
            // Modules remain fail-closed until their installed bytes are materialized,
            // no-follow hashed, and matched to the reviewed digest before `init`.
            "module" => return Err(ValidationError::ForbiddenFeature),
            "required_providers" if parent == Some("terraform") => {
                inspect_required_providers(block, closure)?;
            }
            "required_providers" => return Err(ValidationError::Malformed),
            "resource" | "data" => inspect_provider_resource(block, closure)?,
            "provider" => inspect_provider_block(block, closure)?,
            _ => {}
        }
        inspect_hcl_body(
            block.body(),
            closure,
            structures,
            expression_nodes,
            Some(identifier),
        )?;
    }
    Ok(())
}

fn inspect_expression(
    expression: &Expression,
    nodes: &mut usize,
    depth: usize,
) -> Result<(), ValidationError> {
    *nodes = nodes.checked_add(1).ok_or(ValidationError::LimitExceeded)?;
    if *nodes > HARD_MAX_EXPRESSION_NODES || depth > HARD_MAX_EXPRESSION_DEPTH {
        return Err(ValidationError::LimitExceeded);
    }
    let descend =
        |child: &Expression, nodes: &mut usize| inspect_expression(child, nodes, depth + 1);
    match expression {
        Expression::Null
        | Expression::Bool(_)
        | Expression::Number(_)
        | Expression::String(_)
        | Expression::Variable(_) => Ok(()),
        Expression::Array(values) => {
            for value in values {
                descend(value, nodes)?;
            }
            Ok(())
        }
        Expression::Object(fields) => {
            for (key, value) in fields {
                if let ObjectKey::Expression(key) = key {
                    descend(key, nodes)?;
                }
                descend(value, nodes)?;
            }
            Ok(())
        }
        // Interpolated templates and all functions are outside the closed v1
        // input surface. This includes file/templatefile/fileset/path access.
        Expression::TemplateExpr(_) | Expression::FuncCall(_) => {
            Err(ValidationError::ForbiddenFeature)
        }
        Expression::Traversal(traversal) => {
            descend(&traversal.expr, nodes)?;
            for operator in &traversal.operators {
                if let TraversalOperator::Index(index) = operator {
                    descend(index, nodes)?;
                }
            }
            Ok(())
        }
        Expression::Parenthesis(inner) => descend(inner, nodes),
        Expression::Conditional(conditional) => {
            descend(&conditional.cond_expr, nodes)?;
            descend(&conditional.true_expr, nodes)?;
            descend(&conditional.false_expr, nodes)
        }
        Expression::Operation(operation) => match operation.as_ref() {
            Operation::Unary(unary) => descend(&unary.expr, nodes),
            Operation::Binary(binary) => {
                descend(&binary.lhs_expr, nodes)?;
                descend(&binary.rhs_expr, nodes)
            }
        },
        Expression::ForExpr(for_expression) => {
            descend(&for_expression.collection_expr, nodes)?;
            if let Some(key) = &for_expression.key_expr {
                descend(key, nodes)?;
            }
            descend(&for_expression.value_expr, nodes)?;
            if let Some(condition) = &for_expression.cond_expr {
                descend(condition, nodes)?;
            }
            Ok(())
        }
        _ => Err(ValidationError::ForbiddenFeature),
    }
}

fn inspect_required_providers(
    block: &hcl::Block,
    closure: &mut HclDependencyClosure,
) -> Result<(), ValidationError> {
    if !block.labels().is_empty() || block.body().attributes().count() == 0 {
        return Err(ValidationError::Malformed);
    }
    for attribute in block.body().attributes() {
        let local_name = attribute.key();
        if !static_source_token(local_name, 128) {
            return Err(ValidationError::DependencyNotPinned);
        }
        let Expression::Object(fields) = attribute.expr() else {
            return Err(ValidationError::DependencyNotPinned);
        };
        let mut source = None;
        let mut version = None;
        for (key, value) in fields {
            let ObjectKey::Identifier(key) = key else {
                return Err(ValidationError::DependencyNotPinned);
            };
            let Expression::String(value) = value else {
                return Err(ValidationError::DependencyNotPinned);
            };
            match key.as_str() {
                "source" if source.replace(value.as_str()).is_none() => {}
                "version" if version.replace(value.as_str()).is_none() => {}
                _ => return Err(ValidationError::DependencyNotPinned),
            }
        }
        let source =
            normalize_provider_source(source.ok_or(ValidationError::DependencyNotPinned)?)?;
        let version = version.ok_or(ValidationError::DependencyNotPinned)?;
        let pin = (source, version.to_owned());
        if !static_dependency_token(version, 128)
            || closure
                .provider_local_names
                .insert(local_name.into(), pin.clone())
                .is_some()
            || !closure.providers.insert(pin)
        {
            return Err(ValidationError::DependencyNotPinned);
        }
    }
    Ok(())
}

fn inspect_provider_resource(
    block: &hcl::Block,
    closure: &mut HclDependencyClosure,
) -> Result<(), ValidationError> {
    if block.labels().len() != 2 {
        return Err(ValidationError::Malformed);
    }
    let resource_type = block.labels()[0].as_str();
    let provider_name = resource_type
        .split_once('_')
        .map_or(resource_type, |(provider, _)| provider);
    if !static_source_token(provider_name, 128) {
        return Err(ValidationError::DependencyNotPinned);
    }
    closure.provider_usages.insert(provider_name.into());
    Ok(())
}

fn inspect_provider_block(
    block: &hcl::Block,
    closure: &mut HclDependencyClosure,
) -> Result<(), ValidationError> {
    if block.labels().len() != 1 || !static_source_token(block.labels()[0].as_str(), 128) {
        return Err(ValidationError::Malformed);
    }
    closure
        .provider_usages
        .insert(block.labels()[0].as_str().into());
    Ok(())
}

fn normalize_provider_source(source: &str) -> Result<String, ValidationError> {
    if source.starts_with('.') || source.starts_with('/') || source.contains('\\') {
        return Err(ValidationError::DependencyNotPinned);
    }
    let segments = source.split('/').collect::<Vec<_>>();
    let normalized = match segments.as_slice() {
        [namespace, provider]
            if static_source_token(namespace, 128) && static_source_token(provider, 128) =>
        {
            format!("registry.opentofu.org/{namespace}/{provider}")
        }
        [host, namespace, provider]
            if static_source_token(host, 256)
                && static_source_token(namespace, 128)
                && static_source_token(provider, 128) =>
        {
            format!("{host}/{namespace}/{provider}")
        }
        _ => return Err(ValidationError::DependencyNotPinned),
    };
    Ok(normalized)
}

fn static_dependency_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(
                    byte,
                    b'.' | b'_' | b'-' | b'+' | b'=' | b'<' | b'>' | b'!' | b'~'
                )
        })
}

fn static_source_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> OpenTofuSourceBundleV1 {
        OpenTofuSourceBundleV1 {
            root_module_files: BTreeMap::from([(
                "main.tf".into(),
                "terraform { required_providers { cloudflare = { source = \"cloudflare/cloudflare\" version = \"5.0.0\" } } }\nresource \"cloudflare_record\" \"demo\" {}".into(),
            )]),
            variable_values: BTreeMap::from([("value".into(), "reviewed".into())]),
            dependency_lock_file: "provider \"registry.opentofu.org/cloudflare/cloudflare\" {}"
                .into(),
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

    #[test]
    fn hcl_closure_is_structural_and_exact() {
        let mut value = bundle();
        value.root_module_files = BTreeMap::from([(
            "main.tf".into(),
            r#"
              # module "decoy" { source = "evil.local/no/no" version = "9" }
              terraform {
                required_providers {
                  null = {
                    source = "hashicorp/null"
                    version = "3.2.4"
                  }
                }
              }
              resource "null_resource" "qualification" {
                triggers = { marker = "reviewed" }
              }
            "#
            .into(),
        )]);
        let closure = value.hcl_dependency_closure().unwrap();
        assert_eq!(
            closure.providers,
            BTreeSet::from([(
                "registry.opentofu.org/hashicorp/null".into(),
                "3.2.4".into(),
            )])
        );
        assert!(closure.modules.is_empty());

        for hostile in [
            "module \"x\" { source = \"auths.local/qualification/resource\" version = \"1.0.0\" }",
            "module \"x\" { source = \"./local\" version = \"1.0.0\" }",
            "module \"x\" { source = var.source version = \"1.0.0\" }",
            "data \"external\" \"x\" { program = [\"id\"] }",
            "data \"terraform_remote_state\" \"x\" { backend = \"local\" }",
            "terraform { backend \"local\" {} }",
            "import { to = null_resource.x id = \"x\" }",
            "moved { from = null_resource.x to = null_resource.y }",
            "removed { from = null_resource.x lifecycle { destroy = false } }",
            "resource \"null_resource\" \"x\" { provisioner \"local-exec\" { command = \"id\" } }",
            "output \"credential\" { value = file(\".auths-backend.hcl\") }",
            "output \"credential\" { value = templatefile(\".auths-backend.hcl\", {}) }",
            "output \"files\" { value = fileset(\".\", \"**\") }",
        ] {
            let mut hostile_bundle = bundle();
            hostile_bundle
                .root_module_files
                .insert("hostile.tf".into(), hostile.into());
            assert!(
                hostile_bundle.validate().is_err(),
                "hostile HCL must fail structurally: {hostile}"
            );
        }

        for path in ["nested/pins.tf", "override.tf", "qualification_override.tf"] {
            let mut path_bundle = bundle();
            path_bundle
                .root_module_files
                .insert(path.into(), "resource \"null_resource\" \"x\" {}".into());
            assert_eq!(path_bundle.validate(), Err(ValidationError::Malformed));
        }

        let mut expression_depth = bundle();
        expression_depth.root_module_files.insert(
            "deep-expression.tf".into(),
            format!(
                "output \"deep\" {{ value = {}true }}",
                "!".repeat(HARD_MAX_EXPRESSION_DEPTH + 1)
            ),
        );
        assert!(expression_depth.validate().is_err());

        let mut comment_cannot_cancel_depth = bundle();
        comment_cannot_cancel_depth.root_module_files.insert(
            "comment-depth.tf".into(),
            format!(
                "# {}\noutput \"deep\" {{ value = {}true }}",
                ")".repeat(HARD_MAX_EXPRESSION_DEPTH + 1),
                "(".repeat(HARD_MAX_EXPRESSION_DEPTH + 1),
            ),
        );
        assert_eq!(
            comment_cannot_cancel_depth.validate(),
            Err(ValidationError::LimitExceeded)
        );

        let mut conditional_depth = bundle();
        conditional_depth.root_module_files.insert(
            "conditional-depth.tf".into(),
            format!(
                "output \"deep\" {{ value = {}true{} }}",
                "true ? ".repeat(HARD_MAX_EXPRESSION_DEPTH + 1),
                " : false".repeat(HARD_MAX_EXPRESSION_DEPTH + 1),
            ),
        );
        assert_eq!(
            conditional_depth.validate(),
            Err(ValidationError::LimitExceeded)
        );

        for unbound in [
            "resource \"random_id\" \"x\" { byte_length = 8 }",
            "resource \"null_resource\" \"x\" { required_providers { null = { source = \"hashicorp/null\" version = \"3.2.4\" } } }",
        ] {
            let mut unbound_bundle = value.clone();
            unbound_bundle
                .root_module_files
                .insert("unbound.tf".into(), unbound.into());
            assert!(unbound_bundle.hcl_dependency_closure().is_err());
        }
    }
}
