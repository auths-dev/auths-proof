use auths_connections::{ConnectionAdapterError, ValidatedConnectionDescriptor};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;

/// Canonical non-secret Stripe account descriptor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StripeConnectionDescriptor {
    schema: String,
    account_id: String,
    api_version: String,
    livemode: bool,
    allowed_scopes: Vec<String>,
}

impl StripeConnectionDescriptor {
    /// Parses canonical JSON and validates the immutable test-mode account contract.
    ///
    /// # Errors
    ///
    /// Rejects malformed, noncanonical, live-mode, duplicate, unsorted, or
    /// unsupported scope descriptors.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ConnectionAdapterError> {
        if bytes.is_empty() || bytes.len() > 65_536 {
            return Err(ConnectionAdapterError::InvalidDescriptor);
        }
        let descriptor: Self =
            serde_json::from_slice(bytes).map_err(|_| ConnectionAdapterError::InvalidDescriptor)?;
        descriptor.validate()?;
        if descriptor.canonical_bytes()?.as_slice() != bytes {
            return Err(ConnectionAdapterError::InvalidDescriptor);
        }
        Ok(descriptor)
    }

    /// Produces canonical JCS descriptor bytes.
    ///
    /// # Errors
    ///
    /// Returns invalid descriptor if serialization unexpectedly fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ConnectionAdapterError> {
        serde_json_canonicalizer::to_vec(self)
            .map_err(|_| ConnectionAdapterError::InvalidDescriptor)
    }

    /// Returns the stable Stripe account ID.
    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// Returns the pinned Stripe API version.
    #[must_use]
    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    /// Returns whether the descriptor names a live-mode account.
    #[must_use]
    pub const fn livemode(&self) -> bool {
        self.livemode
    }

    /// Returns the byte-sorted immutable scope set.
    #[must_use]
    pub fn allowed_scopes(&self) -> &[String] {
        &self.allowed_scopes
    }

    /// Computes the provider account commitment bound into operations.
    #[must_use]
    pub fn account_commitment(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"auths.stripe.account/1\0");
        digest.update(self.account_id.as_bytes());
        digest.finalize().into()
    }

    /// Builds the shared sealed descriptor projection.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionAdapterError::InvalidDescriptor`] when this value no
    /// longer satisfies the closed Stripe connection contract.
    pub fn validated(&self) -> Result<ValidatedConnectionDescriptor, ConnectionAdapterError> {
        ValidatedConnectionDescriptor::from_adapter(
            self.canonical_bytes()?,
            self.account_commitment(),
        )
    }

    fn validate(&self) -> Result<(), ConnectionAdapterError> {
        let scopes = self.allowed_scopes.iter().collect::<BTreeSet<_>>();
        if self.schema != "auths.stripe.connection-descriptor/1"
            || !self.account_id.starts_with("acct_")
            || !(6..=128).contains(&self.account_id.len())
            || !self
                .account_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || self.api_version.len() != 10
            || self.api_version.as_bytes().get(4) != Some(&b'-')
            || self.api_version.as_bytes().get(7) != Some(&b'-')
            || self.livemode
            || self.allowed_scopes.is_empty()
            || self.allowed_scopes.len() > 32
            || scopes.len() != self.allowed_scopes.len()
            || !self.allowed_scopes.windows(2).all(|pair| pair[0] < pair[1])
            || self.allowed_scopes.as_slice() != ["stripe.refunds.write/1"]
        {
            return Err(ConnectionAdapterError::InvalidDescriptor);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widened_scope_set_is_rejected() {
        let mut value: serde_json::Value =
            serde_json::from_slice(include_bytes!("../../fixtures/connection/v1/valid.json"))
                .unwrap();
        value["allowedScopes"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::Value::String("stripe.unknown/1".into()));
        let bytes = serde_json_canonicalizer::to_vec(&value).unwrap();
        assert_eq!(
            StripeConnectionDescriptor::from_canonical_bytes(&bytes),
            Err(ConnectionAdapterError::InvalidDescriptor)
        );
    }
}
