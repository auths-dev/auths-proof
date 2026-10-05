//! Derived external names. Nothing here reads configuration other than the
//! deployment namespace.

use auths_connections::ConnectionId;
use sha2::{Digest as _, Sha256};
use std::num::NonZeroU64;
use thiserror::Error;

/// The hash domain of a secret's name.
pub const SECRET_NAME_DOMAIN: &str = "auths.gateway-secret-name/1";
/// The hash domain of a secret's version identifier.
pub const SECRET_VERSION_DOMAIN: &str = "auths.gateway-secret-version/1";

/// The operator's deployment namespace: `[a-z][a-z0-9-]{0,63}`. Two
/// deployments with different namespaces never share a secret name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentNamespace(String);

/// A namespace outside the grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
#[error("invalid deployment namespace")]
pub struct InvalidNamespace;

impl DeploymentNamespace {
    /// Parses a namespace.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidNamespace`] for any value outside
    /// `[a-z][a-z0-9-]{0,63}`.
    pub fn parse(value: impl Into<String>) -> Result<Self, InvalidNamespace> {
        let value = value.into();
        let mut bytes = value.bytes();
        let valid = (1..=64).contains(&value.len())
            && bytes.next().is_some_and(|first| first.is_ascii_lowercase())
            && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if valid {
            Ok(Self(value))
        } else {
            Err(InvalidNamespace)
        }
    }

    /// Returns the namespace.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The name of the secret that holds one credential generation: a fixed
/// prefix and the digest of the namespace, connection, and generation.
#[must_use]
pub fn secret_name(
    namespace: &DeploymentNamespace,
    connection_id: &ConnectionId,
    credential_generation: NonZeroU64,
) -> String {
    let mut hash = Sha256::new();
    hash.update(SECRET_NAME_DOMAIN.as_bytes());
    hash.update([0]);
    hash.update(namespace.as_str().as_bytes());
    hash.update([0]);
    hash.update(connection_id.as_str().as_bytes());
    hash.update([0]);
    hash.update(credential_generation.get().to_be_bytes());
    format!("auths-gateway/{}", hex::encode(hash.finalize()))
}

/// The exact version of that secret, bound to the reference commitment the
/// connection record seals. A lease requests this version and no other.
#[must_use]
pub fn secret_version(
    connection_id: &ConnectionId,
    credential_generation: NonZeroU64,
    reference_commitment: &[u8; 32],
) -> String {
    let mut hash = Sha256::new();
    hash.update(SECRET_VERSION_DOMAIN.as_bytes());
    hash.update([0]);
    hash.update(connection_id.as_str().as_bytes());
    hash.update([0]);
    hash.update(credential_generation.get().to_be_bytes());
    hash.update(reference_commitment);
    hex::encode(hash.finalize())
}

/// Whether `reference` has the form of an exact version identifier: 64
/// lowercase hexadecimal characters. A staging label, an alias, a path, or
/// any other spelling is not a version this store will read.
#[must_use]
pub fn is_exact_version(reference: &str) -> bool {
    reference.len() == 64
        && reference
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn custody_vectors() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../bindings/fixtures/gateway/custody-hostile.json"
        );
        serde_json::from_slice(&std::fs::read(path).expect("custody vectors")).expect("JSON")
    }

    #[test]
    fn namespaces_follow_the_lower_token_grammar() {
        for valid in ["a", "production-eu-1", &format!("a{}", "0".repeat(63))] {
            assert!(DeploymentNamespace::parse(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "",
            "Production",
            "1prod",
            "prod_eu",
            "prod/eu",
            &"a".repeat(65),
        ] {
            assert_eq!(
                DeploymentNamespace::parse(invalid),
                Err(InvalidNamespace),
                "{invalid}"
            );
        }
    }

    /// Every frozen derivation: the name and the version identifier.
    #[test]
    fn frozen_secret_names_and_versions_are_derived() {
        let vectors = custody_vectors();
        let names = &vectors["secret_names"];
        assert_eq!(names["name_domain"], SECRET_NAME_DOMAIN);
        assert_eq!(names["version_domain"], SECRET_VERSION_DOMAIN);
        let cases = names["cases"].as_array().expect("cases");
        assert!(!cases.is_empty());
        let mut seen = std::collections::BTreeSet::new();
        for case in cases {
            let id = case["id"].as_str().expect("id");
            let namespace =
                DeploymentNamespace::parse(case["namespace"].as_str().expect("namespace"))
                    .expect("namespace");
            let connection =
                ConnectionId::parse(case["connection_id"].as_str().expect("connection"))
                    .expect("connection");
            let generation =
                NonZeroU64::new(case["credential_generation"].as_u64().expect("generation"))
                    .expect("generation");
            let mut commitment = [0_u8; 32];
            hex::decode_to_slice(
                case["reference_commitment"].as_str().expect("commitment"),
                &mut commitment,
            )
            .expect("commitment hex");
            let name = secret_name(&namespace, &connection, generation);
            let version = secret_version(&connection, generation, &commitment);
            assert_eq!(name, case["name"], "case {id}");
            assert_eq!(version, case["version_id"], "case {id}");
            assert!(is_exact_version(&version), "case {id}");
            assert!(
                seen.insert((name, version)),
                "case {id} repeats a name and version"
            );
        }
    }

    /// Only an exact version identifier is a version: never a stage, an
    /// alias, a path, or a look-alike.
    #[test]
    fn frozen_version_references_are_classified() {
        let vectors = custody_vectors();
        for case in vectors["version_references"].as_array().expect("cases") {
            assert_eq!(
                Value::Bool(is_exact_version(
                    case["reference"].as_str().expect("reference")
                )),
                case["accepted"],
                "case {}",
                case["id"]
            );
        }
    }
}
