//! Typed, immutable connection descriptor for an operator-approved recipe.

use crate::{CompiledRecipe, CredentialRequirement, OperatorNamespace};
use auths_connections::ConnectionBinding;
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
    /// Creates a descriptor solely from a validated recipe for operator
    /// approval, never from an application submission.
    #[must_use]
    pub fn from_recipe(recipe: &CompiledRecipe) -> Self {
        Self {
            namespace: recipe.namespace().clone(),
            recipe_digest: *recipe.digest(),
            credential: recipe.review().credential().clone(),
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
        if binding.descriptor_schema().as_str() != SCHEMA || binding.contract().as_str() != CONTRACT
        {
            return Err(GatewayConnectionError::Mismatch);
        }
        let bytes = binding.descriptor();
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
        let expected = Self::from_recipe(recipe);
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

    #[test]
    fn descriptor_is_canonical_and_bound_to_compiled_recipe() {
        let cases: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../../bindings/fixtures/gateway/binding-scenarios.json"
        ))
        .expect("binding scenarios");
        assert_eq!(cases["schema"], "auths.gateway-binding-scenarios/1");
        assert_eq!(cases["cases"].as_array().expect("cases").len(), 6);
        let recipe = CompiledRecipe::compile(
            include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json"),
            include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json"),
        )
        .expect("recipe");
        let descriptor = GatewayConnectionDescriptor::from_recipe(&recipe);
        let bytes = descriptor.to_bytes().expect("canonical descriptor");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
        assert_eq!(value["schema"], SCHEMA);
        assert_eq!(value["operator_namespace"], recipe.namespace().as_str());
        assert_eq!(value["recipe_digest"], recipe.digest_hex());
        assert_eq!(value["credential"]["kind"], "bearer");
    }
}
