//! Native Python boundary for Auths protocol semantics.

#![forbid(unsafe_code)]

mod authoring;
mod mcp;
mod result;
mod workflow;

use pyo3::prelude::*;

/// Installs the private native extension consumed by `auths`.
#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    authoring::register(module)?;
    mcp::register(module)?;
    result::register(module)?;
    workflow::register(module)?;
    Ok(())
}
