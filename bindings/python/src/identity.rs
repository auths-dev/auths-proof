use auths_identity::{
    IdentityDescriptor, IdentityPacket, PublicIdentity, SignatureVerifier, SignedIdentityMessage,
    VerificationMaterial, VerificationRelationship,
};
use auths_identity_raw_key::RawKeyIdentityMethod;
use auths_signature_ed25519::Ed25519Verifier;
use pyo3::{exceptions::PyValueError, prelude::*, types::PyBytes};

#[pyclass(name = "IdentityProjection", frozen, module = "auths._native")]
pub struct PyIdentityProjection {
    method_id: String,
    identity_id: String,
    suite_id: String,
    public_key: Vec<u8>,
    packet_kind: &'static str,
    message: Option<Vec<u8>>,
    signature: Option<Vec<u8>>,
}

type RelationshipProjection = (String, String, String, Vec<(String, Vec<u8>)>);

#[pyclass(
    name = "IdentityDescriptorProjection",
    frozen,
    module = "auths._native"
)]
pub struct PyIdentityDescriptorProjection {
    method_id: String,
    identity_id: String,
    method_material: Vec<u8>,
    relationships: Vec<RelationshipProjection>,
}

#[pymethods]
impl PyIdentityDescriptorProjection {
    #[getter]
    fn method_id(&self) -> &str {
        &self.method_id
    }

    #[getter]
    fn identity_id(&self) -> &str {
        &self.identity_id
    }

    #[getter]
    fn method_material<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.method_material)
    }

    #[getter]
    fn relationships(&self) -> Vec<RelationshipProjection> {
        self.relationships.clone()
    }
}

#[pymethods]
impl PyIdentityProjection {
    #[getter]
    fn method_id(&self) -> &str {
        &self.method_id
    }

    #[getter]
    fn identity_id(&self) -> &str {
        &self.identity_id
    }

    #[getter]
    fn suite_id(&self) -> &str {
        &self.suite_id
    }

    #[getter]
    fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.public_key)
    }

    #[getter]
    fn packet_kind(&self) -> &'static str {
        self.packet_kind
    }

    #[getter]
    fn message<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.message.as_ref().map(|value| PyBytes::new(py, value))
    }

    #[getter]
    fn signature<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.signature.as_ref().map(|value| PyBytes::new(py, value))
    }
}

#[pyfunction]
fn decode_identity_v1(packet: &[u8]) -> PyResult<PyIdentityProjection> {
    let packet = IdentityPacket::decode(packet).map_err(value_error)?;
    Ok(projection(&packet))
}

#[pyfunction]
fn encode_identity_descriptor_v1<'py>(
    py: Python<'py>,
    method_id: &str,
    identity_id: &str,
    method_material: &[u8],
    relationships: Vec<RelationshipProjection>,
) -> PyResult<Bound<'py, PyBytes>> {
    let relationships = relationships
        .into_iter()
        .map(|(relationship_id, purpose, suite_id, materials)| {
            VerificationRelationship::new(
                &relationship_id,
                &purpose,
                &suite_id,
                materials
                    .into_iter()
                    .map(|(material_id, bytes)| VerificationMaterial::new(&material_id, bytes))
                    .collect::<Result<Vec<_>, _>>()?,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(value_error)?;
    let descriptor = IdentityDescriptor::new(
        method_id,
        identity_id,
        method_material.to_vec(),
        relationships,
    )
    .map_err(value_error)?;
    let encoded = descriptor.encode().map_err(value_error)?;
    Ok(PyBytes::new(py, &encoded))
}

#[pyfunction]
fn decode_identity_descriptor_v1(packet: &[u8]) -> PyResult<PyIdentityDescriptorProjection> {
    let descriptor = IdentityDescriptor::decode(packet).map_err(value_error)?;
    Ok(descriptor_projection(&descriptor))
}

#[pyfunction]
fn compact_identity_descriptor_v1<'py>(
    py: Python<'py>,
    packet: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let identity = match IdentityPacket::decode(packet).map_err(value_error)? {
        IdentityPacket::PublicIdentity(value) => value,
        IdentityPacket::SignedMessage(_) => {
            return Err(PyValueError::new_err("expected a public identity packet"));
        }
    };
    let encoded = identity
        .to_descriptor()
        .and_then(|descriptor| descriptor.encode())
        .map_err(value_error)?;
    Ok(PyBytes::new(py, &encoded))
}

#[pyfunction]
fn identity_descriptor_signing_preimage_v1<'py>(
    py: Python<'py>,
    packet: &[u8],
    relationship_id: &str,
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let descriptor = IdentityDescriptor::decode(packet).map_err(value_error)?;
    let preimage = descriptor
        .signing_preimage(relationship_id, message)
        .map_err(value_error)?;
    Ok(PyBytes::new(py, &preimage))
}

#[pyfunction]
fn encode_public_identity_v1<'py>(
    py: Python<'py>,
    method_id: &str,
    identity_id: &str,
    suite_id: &str,
    public_key: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let identity = PublicIdentity::new(method_id, identity_id, suite_id, public_key.to_vec())
        .map_err(value_error)?;
    let packet = IdentityPacket::PublicIdentity(identity)
        .encode()
        .map_err(value_error)?;
    Ok(PyBytes::new(py, &packet))
}

#[pyfunction]
fn raw_key_identity_v2<'py>(
    py: Python<'py>,
    suite_id: &str,
    public_key: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let identity = RawKeyIdentityMethod::identity(suite_id, public_key.to_vec())
        .map_err(value_error)?
        .into_public_identity();
    let packet = IdentityPacket::PublicIdentity(identity)
        .encode()
        .map_err(value_error)?;
    Ok(PyBytes::new(py, &packet))
}

#[pyfunction]
fn validate_raw_key_identity_v2(
    method_id: &str,
    identity_id: &str,
    suite_id: &str,
    public_key: &[u8],
) -> PyResult<()> {
    PublicIdentity::new(method_id, identity_id, suite_id, public_key.to_vec())
        .and_then(|identity| identity.validate(&RawKeyIdentityMethod))
        .map_err(value_error)?;
    Ok(())
}

#[pyfunction]
fn identity_signing_preimage_v1<'py>(
    py: Python<'py>,
    method_id: &str,
    identity_id: &str,
    suite_id: &str,
    public_key: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let identity = PublicIdentity::new(method_id, identity_id, suite_id, public_key.to_vec())
        .map_err(value_error)?;
    let preimage =
        SignedIdentityMessage::signing_preimage(&identity, message).map_err(value_error)?;
    Ok(PyBytes::new(py, &preimage))
}

#[pyfunction]
fn verify_ed25519_preimage_v1(
    py: Python<'_>,
    public_key: Vec<u8>,
    preimage: Vec<u8>,
    signature: Vec<u8>,
) -> PyResult<()> {
    py.detach(move || {
        Ed25519Verifier
            .verify(&public_key, &preimage, &signature)
            .map_err(value_error)
    })
}

fn projection(packet: &IdentityPacket) -> PyIdentityProjection {
    let identity = packet.identity();
    let (packet_kind, message, signature) = match &packet {
        IdentityPacket::PublicIdentity(_) => ("public-identity", None, None),
        IdentityPacket::SignedMessage(signed) => (
            "signed-message",
            Some(signed.message().to_vec()),
            Some(signed.signature().to_vec()),
        ),
    };
    PyIdentityProjection {
        method_id: identity.method_id().to_owned(),
        identity_id: identity.identity_id().to_owned(),
        suite_id: identity.suite_id().to_owned(),
        public_key: identity.public_key().to_vec(),
        packet_kind,
        message,
        signature,
    }
}

fn descriptor_projection(descriptor: &IdentityDescriptor) -> PyIdentityDescriptorProjection {
    PyIdentityDescriptorProjection {
        method_id: descriptor.method_id().to_owned(),
        identity_id: descriptor.identity_id().to_owned(),
        method_material: descriptor.method_material().to_vec(),
        relationships: descriptor
            .relationships()
            .iter()
            .map(|relationship| {
                (
                    relationship.relationship_id().to_owned(),
                    relationship.purpose().to_owned(),
                    relationship.suite_id().to_owned(),
                    relationship
                        .verification_material()
                        .iter()
                        .map(|material| {
                            (material.material_id().to_owned(), material.bytes().to_vec())
                        })
                        .collect(),
                )
            })
            .collect(),
    }
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyIdentityProjection>()?;
    module.add_class::<PyIdentityDescriptorProjection>()?;
    module.add_function(wrap_pyfunction!(decode_identity_v1, module)?)?;
    module.add_function(wrap_pyfunction!(encode_identity_descriptor_v1, module)?)?;
    module.add_function(wrap_pyfunction!(decode_identity_descriptor_v1, module)?)?;
    module.add_function(wrap_pyfunction!(compact_identity_descriptor_v1, module)?)?;
    module.add_function(wrap_pyfunction!(
        identity_descriptor_signing_preimage_v1,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(encode_public_identity_v1, module)?)?;
    module.add_function(wrap_pyfunction!(raw_key_identity_v2, module)?)?;
    module.add_function(wrap_pyfunction!(validate_raw_key_identity_v2, module)?)?;
    module.add_function(wrap_pyfunction!(identity_signing_preimage_v1, module)?)?;
    module.add_function(wrap_pyfunction!(verify_ed25519_preimage_v1, module)?)?;
    Ok(())
}

fn value_error(error: impl std::fmt::Display) -> PyErr {
    PyValueError::new_err(error.to_string())
}
