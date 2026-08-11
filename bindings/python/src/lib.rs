//! Native Python boundary for Auths protocol semantics.

#![forbid(unsafe_code)]

mod application;
mod authoring;
mod http;
mod identity;
mod mcp;
mod result;
mod runtime;
mod workflow;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

type ReviewProjection<'py> = (String, Vec<(String, String)>, Bound<'py, PyBytes>);

#[pyfunction]
fn generate_challenge_v1(py: Python<'_>) -> PyResult<Bound<'_, PyBytes>> {
    let mut challenge = [0_u8; 32];
    getrandom::fill(&mut challenge)
        .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("secure randomness unavailable"))?;
    Ok(PyBytes::new(py, &challenge))
}

/// Installs the private native extension consumed by `auths`.
#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(generate_challenge_v1, module)?)?;
    authoring::register(module)?;
    application::register(module)?;
    identity::register(module)?;
    http::register(module)?;
    mcp::register(module)?;
    result::register(module)?;
    runtime::register(module)?;
    workflow::register(module)?;
    Ok(())
}
