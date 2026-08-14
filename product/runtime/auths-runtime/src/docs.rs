//! Read-only facts for documentation and release tooling.

/// Stable metadata for one production runtime endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeEndpointSpecV1 {
    /// Stable endpoint identity.
    pub id: &'static str,
    /// Product operation served by this endpoint.
    pub operation: Option<&'static str>,
    /// Stable documentation page identity.
    pub page: &'static str,
    /// Closed endpoint class.
    pub class: EndpointClass,
    /// HTTP method.
    pub method: HttpMethod,
    /// Absolute, template-form route path.
    pub path: &'static str,
    /// Maximum accepted request body in bytes.
    pub max_body_bytes: u32,
    /// Outcomes this endpoint may return.
    pub outcomes: &'static [OutcomeKind],
    /// Scenario that qualifies effectful or recovery behavior.
    pub scenario: Option<&'static str>,
    /// Trust-boundary facts fixed by the runtime contract.
    pub trust: EndpointTrustBoundary,
}

/// Closed classes used to organize the runtime API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointClass {
    /// Liveness without authority or provider access.
    Health,
    /// Runtime version and compatibility facts.
    Version,
    /// Authority creation and inspection.
    Authority,
    /// Authorization followed by closed profile execution.
    ProfileExecution,
    /// Recovery of a prior execution.
    WorkflowRecovery,
    /// Bounded receipt projection.
    ReceiptSummary,
    /// Authorized receipt disclosure.
    ReceiptDisclosure,
}

/// HTTP methods admitted by the V1 runtime contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    /// Read a bounded projection.
    Get,
    /// Submit exact bytes for parsing and processing.
    Post,
}

/// Closed outcomes exposed by runtime endpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutcomeKind {
    /// Operation completed and may carry a receipt.
    Completed,
    /// Authorization denied the requested effect.
    Denied,
    /// The runtime could not make a safe decision.
    Indeterminate,
    /// The provider result requires explicit recovery.
    Recoverable,
    /// Requested resource does not exist.
    NotFound,
}

/// Security facts for an endpoint, represented as closed booleans.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointTrustBoundary {
    /// Maintained production clients require an HTTPS origin.
    pub production_tls_required: bool,
    /// Request bytes remain untrusted until native parsing succeeds.
    pub native_parse_required: bool,
    /// Successful transport cannot authorize an effect.
    pub transport_is_not_authority: bool,
    /// Full receipt material requires an authorized disclosure.
    pub disclosure_required: bool,
}

const READ_ONLY: EndpointTrustBoundary = EndpointTrustBoundary {
    production_tls_required: true,
    native_parse_required: false,
    transport_is_not_authority: true,
    disclosure_required: false,
};

const EFFECTFUL: EndpointTrustBoundary = EndpointTrustBoundary {
    production_tls_required: true,
    native_parse_required: true,
    transport_is_not_authority: true,
    disclosure_required: false,
};

/// V1 runtime endpoints exported without opening network, provider, custody,
/// or state-store effects.
pub const RUNTIME_ENDPOINTS_V1: &[RuntimeEndpointSpecV1] = &[
    RuntimeEndpointSpecV1 {
        id: "auths.endpoint.health/1",
        operation: None,
        page: "auths.page.reference.runtime-api/1",
        class: EndpointClass::Health,
        method: HttpMethod::Get,
        path: "/v1/health",
        max_body_bytes: 0,
        outcomes: &[OutcomeKind::Completed],
        scenario: None,
        trust: READ_ONLY,
    },
    RuntimeEndpointSpecV1 {
        id: "auths.endpoint.version/1",
        operation: None,
        page: "auths.page.reference.runtime-api/1",
        class: EndpointClass::Version,
        method: HttpMethod::Get,
        path: "/v1/version",
        max_body_bytes: 0,
        outcomes: &[OutcomeKind::Completed],
        scenario: None,
        trust: READ_ONLY,
    },
    RuntimeEndpointSpecV1 {
        id: "auths.endpoint.authorities/1",
        operation: Some("auths.operation.create/1"),
        page: "auths.page.reference.runtime-api/1",
        class: EndpointClass::Authority,
        method: HttpMethod::Post,
        path: "/v1/authorities",
        max_body_bytes: 65_536,
        outcomes: &[
            OutcomeKind::Completed,
            OutcomeKind::Denied,
            OutcomeKind::Indeterminate,
        ],
        scenario: Some("auths.scenario.rest-effect/1"),
        trust: EFFECTFUL,
    },
    RuntimeEndpointSpecV1 {
        id: "auths.endpoint.executions/1",
        operation: Some("auths.operation.execute/1"),
        page: "auths.page.reference.runtime-api/1",
        class: EndpointClass::ProfileExecution,
        method: HttpMethod::Post,
        path: "/v1/executions",
        max_body_bytes: 262_144,
        outcomes: &[
            OutcomeKind::Completed,
            OutcomeKind::Denied,
            OutcomeKind::Indeterminate,
            OutcomeKind::Recoverable,
        ],
        scenario: Some("auths.scenario.rest-effect/1"),
        trust: EFFECTFUL,
    },
    RuntimeEndpointSpecV1 {
        id: "auths.endpoint.execution-resume/1",
        operation: Some("auths.operation.resume/1"),
        page: "auths.page.reference.runtime-api/1",
        class: EndpointClass::WorkflowRecovery,
        method: HttpMethod::Post,
        path: "/v1/executions/{execution_id}/resume",
        max_body_bytes: 65_536,
        outcomes: &[
            OutcomeKind::Completed,
            OutcomeKind::Denied,
            OutcomeKind::Indeterminate,
            OutcomeKind::Recoverable,
            OutcomeKind::NotFound,
        ],
        scenario: Some("auths.scenario.rest-effect/1"),
        trust: EFFECTFUL,
    },
    RuntimeEndpointSpecV1 {
        id: "auths.endpoint.receipt-summary/1",
        operation: Some("auths.operation.verify/1"),
        page: "auths.page.reference.runtime-api/1",
        class: EndpointClass::ReceiptSummary,
        method: HttpMethod::Get,
        path: "/v1/receipts/{receipt_id}",
        max_body_bytes: 0,
        outcomes: &[OutcomeKind::Completed, OutcomeKind::NotFound],
        scenario: Some("auths.scenario.receipt-verification/1"),
        trust: READ_ONLY,
    },
    RuntimeEndpointSpecV1 {
        id: "auths.endpoint.receipt-disclosure/1",
        operation: Some("auths.operation.verify/1"),
        page: "auths.page.reference.runtime-api/1",
        class: EndpointClass::ReceiptDisclosure,
        method: HttpMethod::Post,
        path: "/v1/receipts/{receipt_id}/disclosures",
        max_body_bytes: 65_536,
        outcomes: &[
            OutcomeKind::Completed,
            OutcomeKind::Denied,
            OutcomeKind::NotFound,
        ],
        scenario: Some("auths.scenario.receipt-verification/1"),
        trust: EndpointTrustBoundary {
            disclosure_required: true,
            ..EFFECTFUL
        },
    },
];

/// Returns the immutable V1 runtime endpoint facts.
#[must_use]
pub const fn runtime_endpoint_facts_v1() -> &'static [RuntimeEndpointSpecV1] {
    RUNTIME_ENDPOINTS_V1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn endpoint_identities_and_routes_are_unique() {
        let mut identities = BTreeSet::new();
        let mut routes = BTreeSet::new();
        for endpoint in RUNTIME_ENDPOINTS_V1 {
            assert!(identities.insert(endpoint.id));
            assert!(routes.insert((endpoint.method as u8, endpoint.path)));
            if matches!(
                endpoint.class,
                EndpointClass::ProfileExecution | EndpointClass::WorkflowRecovery
            ) {
                assert!(endpoint.scenario.is_some());
            }
        }
    }
}
