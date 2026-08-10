//! Native Python boundary for Auths protocol semantics.

#![forbid(unsafe_code)]

mod authoring;
mod result;

use pyo3::prelude::*;

/// Installs the private native extension consumed by `auths`.
#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    authoring::register(module)?;
    result::register(module)?;
    Ok(())
}
