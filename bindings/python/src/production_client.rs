use auths_production_client::{
    PRODUCTION_CLIENT_CONTRACT_VERSION, ProductVerb, ProductionRequest, QualifiedProfile,
    RecoveryReference, decode_request, decode_response, encode_delegation_body, encode_request,
    project_sdk_event_v2,
};
use pyo3::{prelude::*, types::PyBytes};

#[pyfunction]
fn production_client_contract_version_v1() -> u16 {
    PRODUCTION_CLIENT_CONTRACT_VERSION
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn encode_production_request_v1<'py>(
    py: Python<'py>,
    verb: &str,
    profile: &str,
    identity: &[u8],
    authority: Option<&[u8]>,
    body: Option<&[u8]>,
    recovery_reference: Option<&str>,
) -> PyResult<Bound<'py, PyBytes>> {
    let request = ProductionRequest::new(
        ProductVerb::parse(verb).map_err(value_error)?,
        QualifiedProfile::parse(profile).map_err(value_error)?,
        identity.to_vec(),
        authority.map(<[u8]>::to_vec),
        body.map(<[u8]>::to_vec),
        recovery_reference
            .map(RecoveryReference::parse)
            .transpose()
            .map_err(value_error)?,
    )
    .map_err(value_error)?;
    let encoded = encode_request(&request).map_err(value_error)?;
    Ok(PyBytes::new(py, &encoded))
}

/// Projects a response the service already produced.
///
/// A response that cannot be decoded is **not** a caller input error. The
/// service may already have applied the effect and this client simply cannot
/// read what it said, so the failure fails closed to `effect: "possible"`
/// (contract 5.3). Reporting `not-applied` here would tell a caller that a
/// possibly-committed write is safe to retry.
#[pyfunction]
fn decode_production_response_v1(input: &[u8]) -> PyResult<String> {
    decode_response(input)
        .and_then(|response| response.projection_json())
        .map_err(|error| {
            crate::errors::boundary_error(crate::errors::Boundary::Unclassified, error)
        })
}

#[pyfunction]
fn decode_production_request_v1(input: &[u8]) -> PyResult<String> {
    decode_request(input)
        .and_then(|request| request.projection_json())
        .map_err(value_error)
}

#[pyfunction]
fn encode_production_delegation_v1<'py>(
    py: Python<'py>,
    subject: &[u8],
    attenuation: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let encoded = encode_delegation_body(subject, attenuation).map_err(value_error)?;
    Ok(PyBytes::new(py, &encoded))
}

#[pyfunction]
fn project_sdk_event_json_v2(input: &str) -> PyResult<String> {
    project_sdk_event_v2(input).map_err(value_error)
}

#[allow(clippy::needless_pass_by_value)]
fn value_error(error: impl core::fmt::Display) -> PyErr {
    crate::errors::malformed_input(error)
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(
        production_client_contract_version_v1,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(encode_production_request_v1, module)?)?;
    module.add_function(wrap_pyfunction!(decode_production_response_v1, module)?)?;
    module.add_function(wrap_pyfunction!(decode_production_request_v1, module)?)?;
    module.add_function(wrap_pyfunction!(encode_production_delegation_v1, module)?)?;
    module.add_function(wrap_pyfunction!(project_sdk_event_json_v2, module)?)?;
    Ok(())
}
