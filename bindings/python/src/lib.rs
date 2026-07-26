//! Python extension for the bounded three-input Auths V1 engine.

#![forbid(unsafe_code)]

use pyo3::{exceptions::PyRuntimeError, prelude::*, types::PyBytes};

/// Executes the self-contained V1 verifier and returns canonical result CBOR.
#[pyfunction]
fn verify_v1<'py>(
    py: Python<'py>,
    proof_cbor: &[u8],
    canonical_action_cbor: &[u8],
    trusted_context_cbor: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let result = auths_proof_wasm::verify_self_contained_v1(
        proof_cbor,
        canonical_action_cbor,
        trusted_context_cbor,
    )
    .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    Ok(PyBytes::new(py, &result))
}

/// Installs the private native extension consumed by `auths_proof`.
#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(verify_v1, module)?)?;
    Ok(())
}
