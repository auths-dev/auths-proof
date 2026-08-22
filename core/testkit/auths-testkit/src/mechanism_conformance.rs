use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConformanceCatalog {
    pub schema: &'static str,
    pub suite_version: u16,
    pub semantic_subject: &'static str,
    pub contracts: Vec<ContractInventory>,
    pub suites: Vec<ConformanceSuite>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractInventory {
    pub contract: &'static str,
    pub classification: &'static str,
    pub evidence: Vec<&'static str>,
    pub disposition: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConformanceSuite {
    pub id: &'static str,
    pub owner: &'static str,
    pub cases: Vec<ConformanceCase>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConformanceCase {
    pub id: &'static str,
    pub classification: &'static str,
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn mechanism_profile_conformance_catalog() -> ConformanceCatalog {
    ConformanceCatalog {
        schema: "auths.mechanism-profile-conformance/1",
        suite_version: 1,
        semantic_subject: "auths.mechanism-profile-conformance/1",
        contracts: vec![
            contract(
                "signer-custody",
                "candidate-mechanism",
                &["auths.mcp/1", "auths.records/1"],
                "publish-framework",
            ),
            contract(
                "atomic-reservation-store",
                "candidate-mechanism",
                &["auths.mcp/1", "auths.records/1"],
                "publish-framework",
            ),
            contract(
                "bounded-byte-transport",
                "candidate-mechanism",
                &["identity-exchange", "proof-exchange"],
                "retain-integrations",
            ),
            contract(
                "approval-transaction",
                "candidate-mechanism",
                &["auths.mcp/1"],
                "retain-internal",
            ),
            contract(
                "provider-gateway",
                "profile-owned",
                &["auths.mcp/1"],
                "retain-profile",
            ),
            contract(
                "provider-result",
                "profile-owned",
                &["auths.mcp/1"],
                "retain-profile",
            ),
            contract(
                "reconciliation",
                "profile-owned",
                &["auths.mcp/1"],
                "retain-profile",
            ),
            contract(
                "generic-framework-adapter",
                "premature-abstraction",
                &[],
                "delete",
            ),
        ],
        suites: vec![
            suite(
                "signer-custody/1",
                "mechanism",
                &[
                    "signer/transaction-binding",
                    "signer/principal-binding",
                    "signer/descriptor-binding",
                    "signer/request-binding",
                    "signer/expiry",
                    "signer/duplicate",
                    "signer/cancellation",
                    "signer/disposal",
                ],
            ),
            suite(
                "atomic-reservation-store/1",
                "mechanism",
                &[
                    "atomic-store/acquire",
                    "atomic-store/exact-replay",
                    "atomic-store/conflict",
                    "atomic-store/concurrent-single-winner",
                    "atomic-store/bounded-record",
                    "atomic-store/isolated-instances",
                    "atomic-store/reopen-durability-claim",
                ],
            ),
            suite(
                "bounded-byte-transport/1",
                "mechanism",
                &[
                    "byte-transport/exact-bytes",
                    "byte-transport/bounded-input",
                    "byte-transport/bounded-output",
                    "byte-transport/cancellation",
                    "byte-transport/disposal",
                ],
            ),
            suite(
                "auths.mcp/1/provider/1",
                "auths.mcp/1",
                &[
                    "mcp/exact-call",
                    "mcp/deny-before-entry",
                    "mcp/concurrent-single-entry",
                    "mcp/ambiguous-no-blind-retry",
                    "mcp/reconcile-without-reentry",
                    "mcp/service-binding",
                    "mcp/bounded-output",
                ],
            ),
        ],
    }
}

/// Returns the immutable v2 adapter-contract catalog used by the rewritten SDKs.
///
/// V1 is deliberately retained above: the v2 signer, reservation, and transport
/// shapes add observable bindings and lifecycle rules and are not aliases for it.
#[must_use]
pub fn mechanism_profile_conformance_catalog_v2() -> ConformanceCatalog {
    ConformanceCatalog {
        schema: "auths.mechanism-profile-conformance/2",
        suite_version: 2,
        semantic_subject: "auths.mechanism-profile-conformance/2",
        contracts: v2_contracts(),
        suites: v2_suites(),
    }
}

fn v2_contracts() -> Vec<ContractInventory> {
    vec![
        contract(
            "signer-custody",
            "candidate-mechanism",
            &["auths.mcp/2", "auths.records/1"],
            "publish-framework",
        ),
        contract(
            "atomic-reservation-store",
            "candidate-mechanism",
            &["auths.mcp/2", "auths.records/1"],
            "publish-framework",
        ),
        contract(
            "bounded-byte-transport",
            "candidate-mechanism",
            &[
                "auths.remote-verification/1",
                "auths.github.issue-address/2",
            ],
            "retain-integrations",
        ),
        contract(
            "approval-transaction",
            "candidate-mechanism",
            &["auths.mcp/2"],
            "retain-internal",
        ),
        contract(
            "provider-gateway",
            "profile-owned",
            &["auths.mcp/2", "auths.github.issue-address/2"],
            "retain-profile",
        ),
        contract(
            "provider-result",
            "profile-owned",
            &["auths.mcp/2", "auths.github.issue-address/2"],
            "retain-profile",
        ),
        contract(
            "reconciliation",
            "profile-owned",
            &["auths.mcp/2", "auths.github.issue-address/2"],
            "retain-profile",
        ),
    ]
}

fn v2_suites() -> Vec<ConformanceSuite> {
    vec![
        suite(
            "signer-custody/2",
            "mechanism",
            &[
                "signer/transaction-binding",
                "signer/principal-binding",
                "signer/descriptor-binding",
                "signer/key-version-binding",
                "signer/object-binding",
                "signer/request-binding",
                "signer/expiry",
                "signer/duplicate",
                "signer/canonical-signature",
                "signer/evidence-binding",
                "signer/denied",
                "signer/cancelled",
                "signer/throttled",
                "signer/unavailable",
                "signer/revoked-key",
                "signer/disabled-key",
                "signer/provider-unknown",
                "signer/invalid-response",
                "signer/concurrent-reordering",
                "signer/disposal",
                "signer/redaction",
            ],
        ),
        suite(
            "atomic-reservation-store/2",
            "mechanism",
            &[
                "atomic-store/acquire",
                "atomic-store/exact-replay",
                "atomic-store/conflict",
                "atomic-store/concurrent-single-winner",
                "atomic-store/bounded-record",
                "atomic-store/isolated-instances",
                "atomic-store/reopen-durability-claim",
                "atomic-store/cancel-after-acquire",
                "atomic-store/disposal",
            ],
        ),
        suite(
            "bounded-byte-transport/2",
            "mechanism",
            &[
                "byte-transport/exact-route-and-bytes",
                "byte-transport/bounded-input",
                "byte-transport/bounded-output",
                "byte-transport/deadline",
                "byte-transport/cancellation",
                "byte-transport/disposal",
            ],
        ),
    ]
}

impl ConformanceCatalog {
    /// # Errors
    ///
    /// Returns an error when the catalog identity, contracts, suites, or cases are invalid.
    pub fn validate(&self) -> Result<(), String> {
        let identity = match self.suite_version {
            1 => "auths.mechanism-profile-conformance/1",
            2 => "auths.mechanism-profile-conformance/2",
            _ => return Err("invalid mechanism/profile conformance catalog identity".to_owned()),
        };
        if self.schema != identity || self.semantic_subject != identity {
            return Err("invalid mechanism/profile conformance catalog identity".to_owned());
        }
        let mut contracts = std::collections::BTreeSet::new();
        for contract in &self.contracts {
            if !valid_id(contract.contract) || !contracts.insert(contract.contract) {
                return Err(format!(
                    "invalid conformance contract {}",
                    contract.contract
                ));
            }
            if contract.classification.is_empty()
                || contract.disposition.is_empty()
                || contract.evidence.iter().any(|value| value.len() > 128)
            {
                return Err(format!(
                    "incomplete conformance contract {}",
                    contract.contract
                ));
            }
        }
        let mut suites = std::collections::BTreeSet::new();
        let mut cases = std::collections::BTreeSet::new();
        for suite in &self.suites {
            if !valid_id(suite.id) || !suites.insert(suite.id) || suite.cases.is_empty() {
                return Err(format!("invalid conformance suite {}", suite.id));
            }
            for case in &suite.cases {
                if !valid_id(case.id)
                    || !cases.insert(case.id)
                    || case.classification != "deterministic"
                {
                    return Err(format!("invalid conformance case {}", case.id));
                }
            }
        }
        Ok(())
    }
}

fn contract(
    contract: &'static str,
    classification: &'static str,
    evidence: &[&'static str],
    disposition: &'static str,
) -> ContractInventory {
    ContractInventory {
        contract,
        classification,
        evidence: evidence.to_vec(),
        disposition,
    }
}

fn suite(id: &'static str, owner: &'static str, cases: &[&'static str]) -> ConformanceSuite {
    ConformanceSuite {
        id,
        owner,
        cases: cases
            .iter()
            .map(|id| ConformanceCase {
                id,
                classification: "deterministic",
            })
            .collect(),
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.' | b'/')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_complete_and_unique() {
        mechanism_profile_conformance_catalog().validate().unwrap();
        mechanism_profile_conformance_catalog_v2()
            .validate()
            .unwrap();
    }
}
