#![allow(clippy::needless_pass_by_value, clippy::unused_self)]

use auths_model::{
    DEFAULT_MAX_ACTION_BYTES, DEFAULT_MAX_BUNDLE_BYTES, DEFAULT_MAX_CONTEXT_BYTES,
    PortableVerificationResult, VerificationDecision, VerificationStage,
};
use auths_ports::{PrincipalMethod, SignatureSuite};
use pyo3::{
    exceptions::{PyRuntimeError, PyTypeError, PyValueError},
    prelude::*,
    types::PyBytes,
};
use subtle::ConstantTimeEq as _;

pub const NATIVE_ABI_V1: u16 = 1;

#[pyclass(name = "VerifiedAction", frozen, module = "auths._native")]
pub struct PyVerifiedAction {
    pub(crate) inner: auths_verifier::VerifiedAction,
}

#[pymethods]
impl PyVerifiedAction {
    fn __repr__(&self) -> &'static str {
        "VerifiedAction(<native sealed authority>)"
    }

    fn __copy__(&self) -> PyResult<()> {
        Err(sealed_error())
    }

    fn __deepcopy__(&self, _memo: &Bound<'_, PyAny>) -> PyResult<()> {
        Err(sealed_error())
    }

    fn __reduce__(&self) -> PyResult<()> {
        Err(sealed_error())
    }

    fn __reduce_ex__(&self, _protocol: i32) -> PyResult<()> {
        Err(sealed_error())
    }

    fn __getstate__(&self) -> PyResult<()> {
        Err(sealed_error())
    }
}

#[pyclass(name = "NativeVerificationResult", frozen, module = "auths._native")]
pub struct NativeVerificationResult {
    portable: PortableVerificationResult,
    result_cbor: Vec<u8>,
    action: Option<Py<PyVerifiedAction>>,
}

#[pymethods]
impl NativeVerificationResult {
    #[getter]
    fn kind(&self) -> &'static str {
        decision_label(self.portable.decision())
    }

    #[getter]
    fn code(&self) -> &'static str {
        self.portable.code().code()
    }

    #[getter]
    fn stage(&self) -> &'static str {
        stage_label(self.portable.stage())
    }

    #[getter]
    fn metrics(&self) -> (u64, u64, u64, u64, u64, u64, u64) {
        let resources = self.portable.resources();
        (
            resources.proof_bytes(),
            resources.action_bytes(),
            resources.context_bytes(),
            resources.object_count(),
            resources.plan_leaves(),
            resources.plan_depth(),
            resources.work_units(),
        )
    }

    #[getter]
    fn required_configuration<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.portable
            .required_configuration()
            .map(|value| PyBytes::new(py, value.as_bytes()))
    }

    #[getter]
    fn local_configuration<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.portable.local_configuration().as_bytes())
    }

    #[getter]
    fn result_cbor<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.result_cbor)
    }

    #[getter]
    fn action(&self, py: Python<'_>) -> Option<Py<PyVerifiedAction>> {
        self.action.as_ref().map(|action| action.clone_ref(py))
    }
}

#[pyfunction]
fn native_abi_version_v1() -> u16 {
    NATIVE_ABI_V1
}

#[pyfunction]
fn verify_v1(
    py: Python<'_>,
    proof_cbor: &[u8],
    canonical_action_cbor: &[u8],
    trusted_context_cbor: &[u8],
) -> PyResult<NativeVerificationResult> {
    let sealed = verify_sealed(proof_cbor, canonical_action_cbor, trusted_context_cbor)?;
    native_result(py, sealed)
}

#[pyfunction]
fn decode_diagnostic_result_v1(result_cbor: &[u8]) -> PyResult<NativeVerificationResult> {
    let portable = auths_codec::decode_verification_result(result_cbor).map_err(runtime_error)?;
    Ok(NativeVerificationResult {
        portable,
        result_cbor: result_cbor.to_vec(),
        action: None,
    })
}

#[pyfunction]
fn commit_canonical_v1<'py>(
    py: Python<'py>,
    domain: &str,
    canonical: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let commitment = auths_codec::domain_commitment(domain, canonical).map_err(runtime_error)?;
    Ok(PyBytes::new(py, commitment.as_bytes()))
}

#[pyfunction]
const fn diagnostic_input_limits_v1() -> (usize, usize, usize) {
    (
        DEFAULT_MAX_BUNDLE_BYTES,
        DEFAULT_MAX_ACTION_BYTES,
        DEFAULT_MAX_CONTEXT_BYTES,
    )
}

#[pyfunction]
fn commitments_equal_v1(left: &[u8], right: &[u8]) -> PyResult<bool> {
    if left.len() != 32 || right.len() != 32 {
        return Err(PyValueError::new_err(
            "native commitments must contain 32 bytes",
        ));
    }
    Ok(bool::from(left.ct_eq(right)))
}

pub(crate) fn verify_sealed(
    proof_cbor: &[u8],
    canonical_action_cbor: &[u8],
    trusted_context_cbor: &[u8],
) -> PyResult<auths_verifier::SealedVerificationResult> {
    let raw_key = auths_raw_key::RawKeyMethod::new().map_err(runtime_error)?;
    let did_key = auths_did_key::DidKeyMethod::new().map_err(runtime_error)?;
    let did_keri = auths_did_keri::DidKeriMethod::new().map_err(runtime_error)?;
    let ed25519 = auths_signature::Ed25519Suite::new().map_err(runtime_error)?;
    let p256 = auths_signature::P256Sha256Suite::new().map_err(runtime_error)?;
    let methods: [&dyn PrincipalMethod; 3] = [&raw_key, &did_key, &did_keri];
    let suites: [&dyn SignatureSuite; 2] = [&ed25519, &p256];
    let registries =
        auths_registries::ImmutableRegistries::new(&methods, &suites).map_err(runtime_error)?;
    auths_verifier::verify_v1_sealed(
        proof_cbor,
        canonical_action_cbor,
        trusted_context_cbor,
        &registries,
    )
    .map_err(runtime_error)
}

pub(crate) fn native_result(
    py: Python<'_>,
    sealed: auths_verifier::SealedVerificationResult,
) -> PyResult<NativeVerificationResult> {
    let (portable, result_cbor, action) = sealed.into_parts();
    let action = action
        .map(|action| Py::new(py, PyVerifiedAction { inner: *action }))
        .transpose()?;
    Ok(NativeVerificationResult {
        portable,
        result_cbor,
        action,
    })
}

#[pyfunction]
fn inspect_verified_action<'py>(
    py: Python<'py>,
    action: PyRef<'_, PyVerifiedAction>,
) -> PyResult<Bound<'py, PyBytes>> {
    let cbor = auths_codec::encode_canonical_action(action.inner.canonical_action())
        .map_err(runtime_error)?;
    Ok(PyBytes::new(py, &cbor))
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyVerifiedAction>()?;
    module.add_class::<NativeVerificationResult>()?;
    module.add_function(wrap_pyfunction!(native_abi_version_v1, module)?)?;
    module.add_function(wrap_pyfunction!(verify_v1, module)?)?;
    module.add_function(wrap_pyfunction!(decode_diagnostic_result_v1, module)?)?;
    module.add_function(wrap_pyfunction!(commit_canonical_v1, module)?)?;
    module.add_function(wrap_pyfunction!(diagnostic_input_limits_v1, module)?)?;
    module.add_function(wrap_pyfunction!(commitments_equal_v1, module)?)?;
    module.add_function(wrap_pyfunction!(inspect_verified_action, module)?)?;
    Ok(())
}

fn decision_label(decision: VerificationDecision) -> &'static str {
    match decision {
        VerificationDecision::Authorized => "authorized",
        VerificationDecision::Denied => "denied",
        VerificationDecision::Indeterminate => "indeterminate",
    }
}

fn stage_label(stage: VerificationStage) -> &'static str {
    match stage {
        VerificationStage::Decode => "decode",
        VerificationStage::Resolve => "resolve",
        VerificationStage::PrincipalControl => "principal-control",
        VerificationStage::Authority => "authority",
        VerificationStage::Complete => "complete",
    }
}

fn sealed_error() -> PyErr {
    PyTypeError::new_err("VerifiedAction is a non-copyable native capability")
}

fn runtime_error(error: impl std::fmt::Display) -> PyErr {
    PyRuntimeError::new_err(error.to_string())
}
