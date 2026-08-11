use auths_raw_key::{RAW_KEY_MEDIA_TYPE, RAW_KEY_V1, RawKeyDescriptor, RawKeyType};
use ed25519_dalek::{Signer as _, SigningKey};
use pyo3::{exceptions::PyRuntimeError, prelude::*, types::PyBytes};

#[pyclass(
    name = "DevelopmentEd25519Key",
    module = "auths._native",
    skip_from_py_object
)]
pub struct PyDevelopmentEd25519Key {
    signing_key: SigningKey,
    principal: String,
    evidence: Vec<u8>,
}

#[pymethods]
impl PyDevelopmentEd25519Key {
    #[staticmethod]
    fn generate() -> PyResult<Self> {
        let mut seed = [0_u8; 32];
        getrandom::fill(&mut seed)
            .map_err(|_| PyRuntimeError::new_err("secure randomness unavailable"))?;
        let signing_key = SigningKey::from_bytes(&seed);
        seed.fill(0);
        let descriptor = RawKeyDescriptor::new(
            RawKeyType::Ed25519,
            signing_key.verifying_key().to_bytes().to_vec(),
        )
        .map_err(|_| PyRuntimeError::new_err("native raw-key descriptor rejected Ed25519 key"))?;
        let principal = descriptor
            .principal()
            .map_err(|_| PyRuntimeError::new_err("native raw-key principal derivation failed"))?
            .to_string();
        Ok(Self {
            signing_key,
            principal,
            evidence: descriptor.encode(),
        })
    }

    #[getter]
    fn principal(&self) -> &str {
        &self.principal
    }

    #[getter]
    fn principal_method(&self) -> &'static str {
        RAW_KEY_V1
    }

    #[getter]
    fn verification_method(&self) -> &str {
        &self.principal
    }

    #[getter]
    fn suite(&self) -> &'static str {
        auths_signature_ed25519::ED25519_V1
    }

    #[getter]
    fn evidence_type(&self) -> &'static str {
        RAW_KEY_V1
    }

    #[getter]
    fn media_type(&self) -> &'static str {
        RAW_KEY_MEDIA_TYPE
    }

    #[getter]
    fn evidence<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.evidence)
    }

    fn sign<'py>(&self, py: Python<'py>, preimage: &[u8]) -> Bound<'py, PyBytes> {
        let signature = self.signing_key.sign(preimage).to_bytes();
        PyBytes::new(py, &signature)
    }
}

pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyDevelopmentEd25519Key>()?;
    Ok(())
}
