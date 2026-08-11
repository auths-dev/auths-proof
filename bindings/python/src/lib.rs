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

#[pyfunction]
fn generate_challenge_v1<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
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
