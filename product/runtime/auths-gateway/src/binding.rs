//! Typed, immutable connection descriptor for an operator-approved recipe.

use crate::{CompiledRecipe, CompiledReleaseRecipe, CredentialRequirement, OperatorNamespace};
use auths_connections::{ConnectionBinding, ConnectionRecord};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const SCHEMA: &str = "auths.gateway-connection-descriptor/1";
/// A dedicated descriptor for several task-bound write recipes using one
/// credential and one operator-owned task journal.
pub const TASK_CONNECTION_DESCRIPTOR_SCHEMA: &str = "auths.gateway-task-connection-descriptor/1";
const CONTRACT: &str = "auths.gateway-operation/1";
const MAX_DESCRIPTOR_BYTES: usize = 1_024;
const MAX_TASK_DESCRIPTOR_BYTES: usize = 2_048;
const MAX_TASK_RECIPES: usize = 4;

/// Binding mismatch stops before a claim or credential lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum GatewayConnectionError {
    /// Descriptor is malformed, unbounded, or not canonical.
    #[error("invalid gateway connection descriptor")]
    InvalidDescriptor,
    /// Approved recipe, namespace, or credential injection differs.
    #[error("gateway connection does not match approved recipe")]
    Mismatch,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DescriptorWire {
    schema: String,
    operator_namespace: String,
    recipe_digest: String,
    credential: CredentialRequirement,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct TaskRecipeEntry {
    operator_namespace: String,
    recipe_digest: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TaskDescriptorWire {
    schema: String,
    recipes: Vec<TaskRecipeEntry>,
    credential: CredentialRequirement,
}

/// One credential approved for a small immutable set of task-bound recipes.
/// The caller must use one shared task journal for every member; this value
/// alone neither activates a task nor authorizes ordinary submission.
pub struct GatewayTaskConnectionDescriptor {
    recipes: Vec<TaskRecipeEntry>,
    credential: CredentialRequirement,
}

impl GatewayTaskConnectionDescriptor {
    /// Review all task recipes before installing the credential. Every recipe
    /// must be task-bound and use the same injection header.
    ///
    /// # Errors
    /// Refuses a duplicate, non-task, mixed-credential or oversized set.
    pub fn approve(
        recipes: &[&CompiledRecipe],
        injection_header: &str,
    ) -> Result<Self, GatewayConnectionError> {
        if !(2..=MAX_TASK_RECIPES).contains(&recipes.len()) {
            return Err(GatewayConnectionError::Mismatch);
        }
        let credential = recipes[0].review().credential().clone();
        let name = match &credential {
            CredentialRequirement::Bearer => "Authorization",
            CredentialRequirement::HeaderApiKey { header } => header.as_str(),
        };
        if injection_header != name {
            return Err(GatewayConnectionError::Mismatch);
        }
        let mut entries = Vec::with_capacity(recipes.len());
        for recipe in recipes {
            if !recipe.requires_task_admission() || recipe.review().credential() != &credential {
                return Err(GatewayConnectionError::Mismatch);
            }
            entries.push(TaskRecipeEntry {
                operator_namespace: recipe.namespace().as_str().to_owned(),
                recipe_digest: recipe.digest_hex(),
            });
        }
        entries.sort();
        if entries.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(GatewayConnectionError::Mismatch);
        }
        Ok(Self {
            recipes: entries,
            credential,
        })
    }

    /// Canonical bounded bytes for the operator-installed connection record.
    ///
    /// # Errors
    /// Refuses unexpected encoding or size failure.
    pub fn to_bytes(&self) -> Result<Vec<u8>, GatewayConnectionError> {
        let wire = TaskDescriptorWire {
            schema: TASK_CONNECTION_DESCRIPTOR_SCHEMA.to_owned(),
            recipes: self.recipes.clone(),
            credential: self.credential.clone(),
        };
        let bytes = serde_json_canonicalizer::to_vec(&wire)
            .map_err(|_| GatewayConnectionError::InvalidDescriptor)?;
        if bytes.len() > MAX_TASK_DESCRIPTOR_BYTES {
            return Err(GatewayConnectionError::InvalidDescriptor);
        }
        Ok(bytes)
    }
}

/// Operator-owned recipe/namespace/credential-header binding. It contains no
/// secret and is stored in `auths-connections::ConnectionRecord::descriptor`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayConnectionDescriptor {
    namespace: OperatorNamespace,
    recipe_digest: [u8; 32],
    credential: CredentialRequirement,
}

impl GatewayConnectionDescriptor {
    /// Creates a descriptor only when the operator-selected injection header
    /// matches the recipe's declared credential requirement.
    ///
    /// # Errors
    /// Refuses a recipe/header mismatch before credential installation.
    pub fn approve(
        recipe: &CompiledRecipe,
        injection_header: &str,
    ) -> Result<Self, GatewayConnectionError> {
        let expected = Self::expected(recipe);
        let name = match &expected.credential {
            CredentialRequirement::Bearer => "Authorization",
            CredentialRequirement::HeaderApiKey { header } => header.as_str(),
        };
        if injection_header != name {
            return Err(GatewayConnectionError::Mismatch);
        }
        Ok(expected)
    }

    /// Seal the same connection contract around a reviewed read-release
    /// recipe. The credential header is operator selected and exact.
    ///
    /// # Errors
    /// Refuses a mismatch before any credential installation.
    pub fn approve_release(
        recipe: &CompiledReleaseRecipe,
        injection_header: &str,
    ) -> Result<Self, GatewayConnectionError> {
        let expected = Self::expected_release(recipe);
        let name = match &expected.credential {
            CredentialRequirement::Bearer => "Authorization",
            CredentialRequirement::HeaderApiKey { header } => header.as_str(),
        };
        if injection_header != name {
            return Err(GatewayConnectionError::Mismatch);
        }
        Ok(expected)
    }

    fn expected(recipe: &CompiledRecipe) -> Self {
        Self {
            namespace: recipe.namespace().clone(),
            recipe_digest: *recipe.digest(),
            credential: recipe.review().credential().clone(),
        }
    }

    fn expected_release(recipe: &CompiledReleaseRecipe) -> Self {
        Self {
            namespace: recipe.namespace().clone(),
            recipe_digest: *recipe.digest(),
            credential: recipe.credential_requirement().clone(),
        }
    }

    /// Encodes the canonical descriptor bytes held in a connection record.
    ///
    /// # Errors
    /// Refuses unexpected serialization or size failure.
    pub fn to_bytes(&self) -> Result<Vec<u8>, GatewayConnectionError> {
        let wire = DescriptorWire {
            schema: SCHEMA.to_owned(),
            operator_namespace: self.namespace.as_str().to_owned(),
            recipe_digest: hex::encode(self.recipe_digest),
            credential: self.credential.clone(),
        };
        let bytes = serde_json_canonicalizer::to_vec(&wire)
            .map_err(|_| GatewayConnectionError::InvalidDescriptor)?;
        if bytes.len() > MAX_DESCRIPTOR_BYTES {
            return Err(GatewayConnectionError::InvalidDescriptor);
        }
        Ok(bytes)
    }

    /// Parses and validates the sealed descriptor in an existing connection
    /// binding against the exact installed recipe.
    ///
    /// # Errors
    /// Refuses wrong schema, digest, namespace, or credential header.
    pub fn from_binding(
        binding: &ConnectionBinding,
        recipe: &CompiledRecipe,
    ) -> Result<Self, GatewayConnectionError> {
        Self::from_parts(
            binding.descriptor_schema().as_str(),
            binding.contract().as_str(),
            binding.descriptor(),
            Self::expected(recipe),
        )
    }

    /// Parses and validates the descriptor in a shared connection record
    /// against the exact installed recipe.
    ///
    /// # Errors
    /// Refuses wrong schema, digest, namespace, or credential header.
    pub fn from_record(
        record: &ConnectionRecord,
        recipe: &CompiledRecipe,
    ) -> Result<Self, GatewayConnectionError> {
        if record.descriptor_schema().as_str() == TASK_CONNECTION_DESCRIPTOR_SCHEMA {
            return Self::from_task_record(record, recipe);
        }
        Self::from_parts(
            record.descriptor_schema().as_str(),
            record.contract().as_str(),
            record.descriptor(),
            Self::expected(recipe),
        )
    }

    fn from_task_record(
        record: &ConnectionRecord,
        recipe: &CompiledRecipe,
    ) -> Result<Self, GatewayConnectionError> {
        if record.contract().as_str() != CONTRACT || !recipe.requires_task_admission() {
            return Err(GatewayConnectionError::Mismatch);
        }
        let bytes = record.descriptor();
        if bytes.is_empty() || bytes.len() > MAX_TASK_DESCRIPTOR_BYTES {
            return Err(GatewayConnectionError::InvalidDescriptor);
        }
        let wire: TaskDescriptorWire =
            serde_json::from_slice(bytes).map_err(|_| GatewayConnectionError::InvalidDescriptor)?;
        let canonical = serde_json_canonicalizer::to_vec(&wire)
            .map_err(|_| GatewayConnectionError::InvalidDescriptor)?;
        if canonical != bytes
            || wire.schema != TASK_CONNECTION_DESCRIPTOR_SCHEMA
            || !(2..=MAX_TASK_RECIPES).contains(&wire.recipes.len())
            || wire.recipes.windows(2).any(|pair| pair[0] >= pair[1])
            || wire.recipes.iter().any(|entry| {
                OperatorNamespace::parse(&entry.operator_namespace).is_err()
                    || entry.recipe_digest.len() != 64
                    || !entry
                        .recipe_digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        {
            return Err(GatewayConnectionError::InvalidDescriptor);
        }
        let expected = Self::expected(recipe);
        let entry = TaskRecipeEntry {
            operator_namespace: expected.namespace.as_str().to_owned(),
            recipe_digest: hex::encode(expected.recipe_digest),
        };
        if wire.credential != expected.credential || !wire.recipes.contains(&entry) {
            return Err(GatewayConnectionError::Mismatch);
        }
        Ok(expected)
    }

    /// Parse an installed connection and bind it to the exact reviewed
    /// read-release recipe before credential access.
    ///
    /// # Errors
    /// Refuses changed schema, digest, namespace or credential header.
    pub fn from_release_record(
        record: &ConnectionRecord,
        recipe: &CompiledReleaseRecipe,
    ) -> Result<Self, GatewayConnectionError> {
        Self::from_parts(
            record.descriptor_schema().as_str(),
            record.contract().as_str(),
            record.descriptor(),
            Self::expected_release(recipe),
        )
    }

    fn from_parts(
        schema: &str,
        contract: &str,
        bytes: &[u8],
        expected: Self,
    ) -> Result<Self, GatewayConnectionError> {
        if schema != SCHEMA || contract != CONTRACT {
            return Err(GatewayConnectionError::Mismatch);
        }
        if bytes.is_empty() || bytes.len() > MAX_DESCRIPTOR_BYTES {
            return Err(GatewayConnectionError::InvalidDescriptor);
        }
        let wire: DescriptorWire =
            serde_json::from_slice(bytes).map_err(|_| GatewayConnectionError::InvalidDescriptor)?;
        let canonical = serde_json_canonicalizer::to_vec(&wire)
            .map_err(|_| GatewayConnectionError::InvalidDescriptor)?;
        if canonical != bytes || wire.schema != SCHEMA {
            return Err(GatewayConnectionError::InvalidDescriptor);
        }
        if wire.operator_namespace != expected.namespace.as_str()
            || wire.recipe_digest != hex::encode(expected.recipe_digest)
            || wire.credential != expected.credential
        {
            return Err(GatewayConnectionError::Mismatch);
        }
        Ok(expected)
    }

    /// Returns the one gateway-injected credential-header requirement.
    #[must_use]
    pub const fn credential(&self) -> &CredentialRequirement {
        &self.credential
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_connections::{
        ConnectionAlias, ConnectionId, ConnectionProfile, ConnectionState, ProviderKind, SemanticId,
    };
    use std::num::NonZeroU64;

    #[test]
    fn descriptor_is_canonical_and_bound_to_compiled_recipe() {
        let cases: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../../bindings/fixtures/gateway/binding-scenarios.json"
        ))
        .expect("binding scenarios");
        assert_eq!(cases["schema"], "auths.gateway-binding-scenarios/1");
        assert_eq!(cases["cases"].as_array().expect("cases").len(), 7);
        let recipe = CompiledRecipe::compile(
            include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json"),
            include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json"),
        )
        .expect("recipe");
        let descriptor = GatewayConnectionDescriptor::approve(&recipe, "Authorization")
            .expect("bearer header approved");
        let bytes = descriptor.to_bytes().expect("canonical descriptor");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
        assert_eq!(value["schema"], SCHEMA);
        assert_eq!(value["operator_namespace"], recipe.namespace().as_str());
        assert_eq!(value["recipe_digest"], recipe.digest_hex());
        assert_eq!(value["credential"]["kind"], "bearer");
        assert!(matches!(
            GatewayConnectionDescriptor::approve(&recipe, "X-Api-Key"),
            Err(GatewayConnectionError::Mismatch)
        ));
    }

    #[test]
    fn api_key_injection_header_is_independently_operator_bound() {
        let mut source: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../../bindings/fixtures/gateway/todoist/recipe.json"
        ))
        .expect("recipe JSON");
        source["credential"] = serde_json::json!({"kind":"header-api-key","header":"X-Api-Key"});
        let source = serde_json::to_vec(&source).expect("recipe bytes");
        let recipe = CompiledRecipe::compile(
            &source,
            include_bytes!("../../../../bindings/fixtures/gateway/todoist/profile.lock.json"),
        )
        .expect("API-key recipe");
        assert!(matches!(
            GatewayConnectionDescriptor::approve(&recipe, "X-Other-Key"),
            Err(GatewayConnectionError::Mismatch)
        ));
        GatewayConnectionDescriptor::approve(&recipe, "X-Api-Key")
            .expect("operator selected the declared header");
    }

    #[test]
    fn read_release_recipe_uses_the_same_connection_descriptor_contract() {
        let recipe = CompiledReleaseRecipe::compile(
            include_bytes!("../../../../demos/airtable-gateway/read_reference/recipe.json"),
            include_bytes!("../../../../demos/airtable-gateway/read_reference/profile.lock.json"),
        )
        .expect("read recipe");
        let descriptor = GatewayConnectionDescriptor::approve_release(&recipe, "Authorization")
            .expect("read descriptor");
        let encoded = descriptor.to_bytes().expect("canonical descriptor");
        let document: serde_json::Value = serde_json::from_slice(&encoded).expect("descriptor");
        assert_eq!(document["recipe_digest"], recipe.digest_hex());
        assert_eq!(document["operator_namespace"], recipe.namespace().as_str());
        assert!(matches!(
            GatewayConnectionDescriptor::approve_release(&recipe, "X-Api-Key"),
            Err(GatewayConnectionError::Mismatch)
        ));
        let record = ConnectionRecord::new(
            ProviderKind::parse("airtable").expect("provider"),
            ConnectionAlias::parse("jules-read").expect("alias"),
            ConnectionId::generate().expect("connection"),
            SemanticId::parse(CONTRACT).expect("contract"),
            SemanticId::parse(SCHEMA).expect("schema"),
            encoded,
            [1; 32],
            [2; 32],
            NonZeroU64::MIN,
            ConnectionState::Active,
            vec!["gateway".to_owned()],
            vec![
                ConnectionProfile::new(SemanticId::parse("auths.mcp").expect("id"), 2)
                    .expect("profile"),
            ],
            10,
            10,
            None,
        )
        .expect("read record");
        assert_eq!(
            GatewayConnectionDescriptor::from_release_record(&record, &recipe),
            Ok(descriptor)
        );
        let google = CompiledReleaseRecipe::compile(
            include_bytes!(
                "../../../../demos/google-employee-delegation/read_reference/recipe.json"
            ),
            include_bytes!(
                "../../../../demos/google-employee-delegation/read_reference/profile.lock.json"
            ),
        )
        .expect("other read recipe");
        assert!(matches!(
            GatewayConnectionDescriptor::from_release_record(&record, &google),
            Err(GatewayConnectionError::Mismatch)
        ));
    }

    #[test]
    fn task_connection_approves_only_its_closed_recipe_set() {
        let edit = CompiledRecipe::compile(
            include_bytes!(
                "../../../../demos/google-employee-delegation/write_reference/recipe.json"
            ),
            include_bytes!(
                "../../../../demos/google-employee-delegation/write_reference/profile.lock.json"
            ),
        )
        .expect("edit recipe");
        let create = CompiledRecipe::compile(
            include_bytes!(
                "../../../../demos/google-employee-delegation/create_reference/recipe.json"
            ),
            include_bytes!(
                "../../../../demos/google-employee-delegation/create_reference/profile.lock.json"
            ),
        )
        .expect("create recipe");
        let unrelated = CompiledRecipe::compile(
            include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json"),
            include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json"),
        )
        .expect("unrelated recipe");
        let approved = GatewayTaskConnectionDescriptor::approve(&[&edit, &create], "Authorization")
            .expect("task recipe set");
        let encoded = approved.to_bytes().expect("canonical task descriptor");
        let record = |descriptor: Vec<u8>| {
            ConnectionRecord::new(
                ProviderKind::parse("google").expect("provider"),
                ConnectionAlias::parse("jules-task").expect("alias"),
                ConnectionId::generate().expect("connection"),
                SemanticId::parse(CONTRACT).expect("contract"),
                SemanticId::parse(TASK_CONNECTION_DESCRIPTOR_SCHEMA).expect("schema"),
                descriptor,
                [1; 32],
                [2; 32],
                NonZeroU64::MIN,
                ConnectionState::Active,
                vec!["gateway".to_owned()],
                vec![
                    ConnectionProfile::new(SemanticId::parse("auths.mcp").expect("id"), 2)
                        .expect("profile"),
                ],
                10,
                10,
                None,
            )
            .expect("record")
        };
        let installed = record(encoded.clone());
        assert!(GatewayConnectionDescriptor::from_record(&installed, &edit).is_ok());
        assert!(GatewayConnectionDescriptor::from_record(&installed, &create).is_ok());
        assert_eq!(
            GatewayConnectionDescriptor::from_record(&installed, &unrelated),
            Err(GatewayConnectionError::Mismatch)
        );
        assert!(
            GatewayTaskConnectionDescriptor::approve(&[&edit, &edit], "Authorization").is_err()
        );
        assert!(GatewayTaskConnectionDescriptor::approve(&[&edit, &create], "X-Api-Key").is_err());
        assert!(
            GatewayTaskConnectionDescriptor::approve(&[&edit, &unrelated], "Authorization")
                .is_err()
        );

        let mut changed: serde_json::Value = serde_json::from_slice(&encoded).expect("descriptor");
        changed["recipes"]
            .as_array_mut()
            .expect("entries")
            .reverse();
        let noncanonical_order = serde_json_canonicalizer::to_vec(&changed).expect("JSON");
        assert_eq!(
            GatewayConnectionDescriptor::from_record(&record(noncanonical_order), &edit),
            Err(GatewayConnectionError::InvalidDescriptor)
        );
    }
}
