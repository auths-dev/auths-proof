//! Native Python boundary for Auths protocol semantics.
//!
//! This crate is a transport, not a tier. It carries meaning that Rust already
//! owns across the pyo3 call boundary, and it defines none of its own:
//!
//! * Failures cross as native Python exceptions carrying the stable code and
//!   the registry's own effect state, retry class, and recommended action.
//! * It projects no generic reference vertical. `auths-profile-domains` is
//!   tier-1 reference Rust and is not reachable from Python, so a Python caller
//!   cannot introduce a vertical whose canonical form lives in Python.
//!
//! The boundary must also be panic-free: see `deny` below. The workspace
//! release profile sets `panic = "abort"`, so a panic here does not raise in
//! Python — it aborts the host interpreter. The lints make the panicking
//! constructs unwritable rather than relying on catching them.

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    clippy::exit
)]

#[cfg(panic = "abort")]
compile_error!(
    "the Python extension may not be built with panic = \"abort\": a panic would abort the host \
     CPython interpreter instead of raising. Build it with the `python-extension` profile \
     (`maturin build --profile python-extension`), which inherits release and restores unwinding \
     so pyo3 can convert a panic into a Python exception."
);

mod authoring;
mod development;
mod errors;
mod identity;
mod mcp;
mod observability;
mod receipts;
mod result;
mod runtime;
mod workflow;

use auths_production_client::{
    encode_qualification_client_result_frame, qualification_client_cancellation_result,
};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

type ReviewProjection<'py> = (String, Vec<(String, String)>, Bound<'py, PyBytes>);

#[pyfunction]
fn generate_challenge_v1(py: Python<'_>) -> PyResult<Bound<'_, PyBytes>> {
    let mut challenge = [0_u8; 32];
    getrandom::fill(&mut challenge).map_err(|_| {
        errors::boundary_error(
            errors::Boundary::RuntimeUnavailable,
            "secure randomness unavailable",
        )
    })?;
    Ok(PyBytes::new(py, &challenge))
}

#[pyfunction]
fn qualification_client_cancellation_result_v1<'py>(
    py: Python<'py>,
    request_id: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let request_id: &[u8; 16] = request_id
        .try_into()
        .map_err(|_| errors::malformed_input("invalid qualification request ID"))?;
    Ok(PyBytes::new(
        py,
        &qualification_client_cancellation_result(request_id),
    ))
}

#[pyfunction]
fn encode_qualification_client_result_frame_v1<'py>(
    py: Python<'py>,
    mode: u8,
    request_id: &[u8],
    result: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let request_id: &[u8; 16] = request_id
        .try_into()
        .map_err(|_| errors::malformed_input("invalid qualification request ID"))?;
    let frame = encode_qualification_client_result_frame(mode, request_id, result)
        .map_err(errors::malformed_input)?;
    Ok(PyBytes::new(py, &frame))
}

/// Installs the private native extension consumed by `auths`.
#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(generate_challenge_v1, module)?)?;
    module.add_function(wrap_pyfunction!(
        qualification_client_cancellation_result_v1,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        encode_qualification_client_result_frame_v1,
        module
    )?)?;
    errors::register(module)?;
    authoring::register(module)?;
    development::register(module)?;
    identity::register(module)?;
    mcp::register(module)?;
    observability::register(module)?;
    result::register(module)?;
    receipts::register(module)?;
    runtime::register(module)?;
    workflow::register(module)?;
    Ok(())
}
