//! Typed, immutable connection descriptor for an operator-approved recipe.

use crate::{CompiledRecipe, CompiledReleaseRecipe, CredentialRequirement, OperatorNamespace};
use auths_connections::{ConnectionBinding, ConnectionRecord};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const SCHEMA: &str = "auths.gateway-connection-descriptor/1";
const CONTRACT: &str = "auths.gateway-operation/1";
const MAX_DESCRIPTOR_BYTES: usize = 1_024;

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
        Self::from_parts(
            record.descriptor_schema().as_str(),
            record.contract().as_str(),
            record.descriptor(),
            Self::expected(recipe),
        )
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
}
