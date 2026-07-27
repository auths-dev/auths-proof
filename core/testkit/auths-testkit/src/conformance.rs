//! Machine-readable adversarial conformance inventory.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Versioned adversarial conformance manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConformanceManifest {
    /// Schema identifier.
    pub schema: String,
    /// Protocol major version.
    pub protocol: u16,
    /// Deterministic cases.
    pub cases: Vec<ConformanceCase>,
}

/// One deterministic mutation and exact boundary oracle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConformanceCase {
    /// Stable `<surface>/<seed>/<mutation>/<boundary>` identifier.
    pub case: String,
    /// Semantic requirements exercised by this case.
    pub requirements: Vec<String>,
    /// Boundary under test.
    pub boundary: String,
    /// Expected portable or adapter-local code.
    pub expected_code: String,
}

impl ConformanceManifest {
    /// Parses and validates a conformance manifest.
    ///
    /// # Errors
    ///
    /// Returns a stable diagnostic for schema, identifier, duplicate, or
    /// coverage errors.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let manifest: Self =
            serde_json::from_slice(bytes).map_err(|error| format!("invalid JSON: {error}"))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validates deterministic identifiers and required coverage families.
    ///
    /// # Errors
    ///
    /// Returns a stable diagnostic naming the missing or malformed item.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != "auths-proof-adversarial-conformance/v1" || self.protocol != 1 {
            return Err("unsupported adversarial conformance schema".to_owned());
        }
        let mut ids = BTreeSet::new();
        let mut requirements = BTreeSet::new();
        for case in &self.cases {
            if case.case.split('/').count() != 4
                || !case.case.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'/')
                })
            {
                return Err(format!("invalid conformance case identifier {}", case.case));
            }
            if !ids.insert(case.case.as_str()) {
                return Err(format!("duplicate conformance case {}", case.case));
            }
            if case.requirements.is_empty() {
                return Err(format!("case {} has no requirements", case.case));
            }
            requirements.extend(case.requirements.iter().map(String::as_str));
        }
        for family in [
            "CONTEXT.",
            "ADAPTER.COMMON.",
            "ADAPTER.RAW_KEY.",
            "ADAPTER.DID_KEY.",
            "ADAPTER.DID_KERI.",
            "ADAPTER.DID_WEB.",
            "ADAPTER.WEBAUTHN.",
            "ADAPTER.HSM.",
            "ADAPTER.SPIFFE.",
            "VERIFIER.MAPPING.",
        ] {
            if !requirements
                .iter()
                .any(|requirement| requirement.starts_with(family))
            {
                return Err(format!("missing requirement family {family}"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{adversarial::assert_canonical_context, corpus};

    #[test]
    fn adversarial_manifest_is_valid_and_deterministic() {
        let bytes = include_bytes!("../../../conformance/v1/manifest.json");
        let manifest = ConformanceManifest::parse(bytes).expect("valid conformance manifest");
        let reparsed = serde_json::to_vec(&manifest).expect("serializable conformance manifest");
        let second: ConformanceManifest =
            serde_json::from_slice(&reparsed).expect("round-trip manifest");
        assert_eq!(manifest, second);
    }

    #[test]
    fn every_canonical_context_round_trips_exactly() {
        for fixture in corpus() {
            assert_canonical_context(fixture.context_bytes()).unwrap_or_else(|error| {
                panic!(
                    "{} context failed canonical round trip: {error}",
                    fixture.name()
                )
            });
        }
    }
}
