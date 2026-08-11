#![allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]

use crate::ReviewProjection;
use crate::authoring::{
    PyPrincipal, PySignedObject, PyTrustedContext, PyUnsignedObject, SignedObject, UnsignedObject,
    value_error,
};
use crate::result::{NativeVerificationResult, native_result, verify_sealed};
use auths_author::{
    ProfilePlanCommitment, ProfilePlanMember, WorkflowProofBuilder, address_evidence,
    prepare_profile_action,
};
use auths_model::{Audience, EvidenceTypeId, MediaType, ResourceId};
use auths_profile_api::ActionProfile;
use auths_profile_domains::{HttpAction, HttpCommand, HttpProfile};
use pyo3::{
    exceptions::{PyRuntimeError, PyTypeError, PyValueError},
    prelude::*,
    types::PyBytes,
};
use std::collections::{BTreeMap, HashSet};

const PROFILE_ID: &str = "auths.http";
const PROFILE_VERSION: u16 = 1;

#[pyclass(
    name = "HttpCall",
    frozen,
    module = "auths._native",
    skip_from_py_object
)]
pub struct PyHttpCall {
    inner: HttpAction,
}

#[pymethods]
impl PyHttpCall {
    #[getter]
    fn method(&self) -> &str {
        self.inner.method()
    }

    #[getter]
    fn scheme(&self) -> &str {
        self.inner.scheme()
    }

    #[getter]
    fn authority(&self) -> &str {
        self.inner.authority()
    }

    #[getter]
    fn path(&self) -> &str {
        self.inner.path()
    }
}

#[pyclass(
    name = "HttpAction",
    frozen,
    module = "auths._native",
    skip_from_py_object
)]
pub struct PyHttpPreparedAction {
    canonical: auths_model::CanonicalAction,
    envelope: auths_model::ActionEnvelope,
    audience: String,
    review_title: String,
    review_fields: Vec<(String, String)>,
}

#[pymethods]
impl PyHttpPreparedAction {
    #[getter]
    fn unsigned(&self) -> PyUnsignedObject {
        PyUnsignedObject {
            inner: UnsignedObject::Action(self.envelope.clone()),
        }
    }

    #[getter]
    fn audience(&self) -> &str {
        &self.audience
    }

    #[getter]
    fn review_title(&self) -> &str {
        &self.review_title
    }

    #[getter]
    fn review_fields(&self) -> Vec<(String, String)> {
        self.review_fields.clone()
    }
}

#[pyclass(
    name = "NativeHttpPlan",
    frozen,
    module = "auths._native",
    skip_from_py_object
)]
pub struct PyNativeHttpPlan {
    commitment: [u8; 32],
    members: Vec<[u8; 32]>,
    permissions: Vec<(String, String)>,
    resource_namespaces: Vec<String>,
    audiences: Vec<String>,
}

#[pymethods]
impl PyNativeHttpPlan {
    #[getter]
    fn commitment<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.commitment)
    }

    #[getter]
    fn members(&self) -> Vec<Vec<u8>> {
        self.members.iter().map(|value| value.to_vec()).collect()
    }

    #[getter]
    fn permissions(&self) -> Vec<(String, String)> {
        self.permissions.clone()
    }

    #[getter]
    fn resource_namespaces(&self) -> Vec<String> {
        self.resource_namespaces.clone()
    }

    #[getter]
    fn audiences(&self) -> Vec<String> {
        self.audiences.clone()
    }
}

#[pyclass(name = "HttpCommand", module = "auths._native", skip_from_py_object)]
pub struct PyHttpCommand {
    inner: Option<HttpCommand>,
    authority_commitment: [u8; 32],
    context_commitment: [u8; 32],
}

#[pymethods]
#[allow(clippy::unused_self)]
impl PyHttpCommand {
    #[getter]
    fn action_commitment<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(py, &self.action_commitment_bytes()?))
    }

    #[getter]
    fn authority_commitment<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.authority_commitment)
    }

    #[getter]
    fn context_commitment<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.context_commitment)
    }

    fn __repr__(&self) -> &'static str {
        if self.inner.is_some() {
            "HttpCommand(<native sealed command>)"
        } else {
            "HttpCommand(<consumed>)"
        }
    }

    fn __copy__(&self) -> PyResult<()> {
        Err(command_error())
    }

    fn __deepcopy__(&self, _memo: &Bound<'_, PyAny>) -> PyResult<()> {
        Err(command_error())
    }

    fn __reduce__(&self) -> PyResult<()> {
        Err(command_error())
    }

    fn __reduce_ex__(&self, _protocol: i32) -> PyResult<()> {
        Err(command_error())
    }
}

impl PyHttpCommand {
    fn command(&self) -> PyResult<&HttpCommand> {
        self.inner
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("HTTP command has already been consumed"))
    }

    fn action_commitment_bytes(&self) -> PyResult<[u8; 32]> {
        canonical_http_commitment(self.command()?.action())
    }
}

#[pyclass(
    name = "HttpPlanCommand",
    module = "auths._native",
    skip_from_py_object
)]
pub struct PyHttpPlanCommand {
    commands: Option<Vec<HttpCommand>>,
    commitment: [u8; 32],
    receipt_bindings: Vec<([u8; 32], [u8; 32], [u8; 32])>,
}

#[pymethods]
#[allow(clippy::unused_self)]
impl PyHttpPlanCommand {
    #[getter]
    fn count(&self) -> PyResult<usize> {
        Ok(self.commands()?.len())
    }

    #[getter]
    fn plan_commitment<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.commitment)
    }

    #[getter]
    fn receipt_bindings(&self) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        self.receipt_bindings
            .iter()
            .map(|(action, authority, context)| {
                (action.to_vec(), authority.to_vec(), context.to_vec())
            })
            .collect()
    }

    fn __repr__(&self) -> &'static str {
        if self.commands.is_some() {
            "HttpPlanCommand(<native sealed plan>)"
        } else {
            "HttpPlanCommand(<consumed>)"
        }
    }

    fn __copy__(&self) -> PyResult<()> {
        Err(plan_command_error())
    }

    fn __deepcopy__(&self, _memo: &Bound<'_, PyAny>) -> PyResult<()> {
        Err(plan_command_error())
    }

    fn __reduce__(&self) -> PyResult<()> {
        Err(plan_command_error())
    }
}

impl PyHttpPlanCommand {
    fn commands(&self) -> PyResult<&[HttpCommand]> {
        self.commands
            .as_deref()
            .ok_or_else(|| PyRuntimeError::new_err("HTTP plan command has already been consumed"))
    }
}

#[pyclass(name = "HttpGatewayRequest", frozen, module = "auths._native")]
pub struct PyHttpGatewayRequest {
    method: String,
    scheme: String,
    authority: String,
    path: String,
    query: Vec<(String, Vec<String>)>,
    headers: Vec<(String, String)>,
    content_type: Option<String>,
    body_digest: Option<String>,
}

#[pymethods]
impl PyHttpGatewayRequest {
    #[getter]
    fn method(&self) -> &str {
        &self.method
    }
    #[getter]
    fn scheme(&self) -> &str {
        &self.scheme
    }
    #[getter]
    fn authority(&self) -> &str {
        &self.authority
    }
    #[getter]
    fn path(&self) -> &str {
        &self.path
    }
    #[getter]
    fn query(&self) -> Vec<(String, Vec<String>)> {
        self.query.clone()
    }
    #[getter]
    fn headers(&self) -> Vec<(String, String)> {
        self.headers.clone()
    }
    #[getter]
    fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }
    #[getter]
    fn body_digest(&self) -> Option<&str> {
        self.body_digest.as_deref()
    }
}

#[pyfunction]
fn http_call(
    method: String,
    scheme: String,
    authority: String,
    path: String,
    query: Vec<(String, Vec<String>)>,
    headers: Vec<(String, String)>,
    content_type: Option<String>,
    body_digest: Option<String>,
) -> PyResult<PyHttpCall> {
    let call = HttpAction::new(
        method,
        scheme,
        authority,
        path,
        query.into_iter().collect::<BTreeMap<_, _>>(),
        headers.into_iter().collect::<BTreeMap<_, _>>(),
        content_type,
        body_digest,
    );
    canonical_http(&call)?;
    Ok(PyHttpCall { inner: call })
}

#[pyfunction]
fn review_http_call<'py>(
    py: Python<'py>,
    call: PyRef<'_, PyHttpCall>,
) -> PyResult<ReviewProjection<'py>> {
    let canonical = canonical_http(&call.inner)?;
    let display = HttpProfile::default()
        .review_display(&canonical)
        .map_err(value_error)?;
    let commitment = canonical_http_commitment(&call.inner)?;
    Ok((
        display.title().to_owned(),
        display.fields().to_vec(),
        PyBytes::new(py, &commitment),
    ))
}

#[pyfunction]
fn commit_http_plan(calls: Vec<Py<PyHttpCall>>, py: Python<'_>) -> PyResult<PyNativeHttpPlan> {
    if calls.is_empty() || calls.len() > 256 {
        return Err(PyValueError::new_err(
            "HTTP plan action count is outside native limits",
        ));
    }
    let calls = calls
        .iter()
        .map(|call| call.borrow(py).inner.clone())
        .collect::<Vec<_>>();
    let origin_value = origin(calls.first().expect("non-empty"));
    if calls.iter().any(|call| origin(call) != origin_value) {
        return Err(PyValueError::new_err(
            "HTTP plan actions must share one origin",
        ));
    }
    let members = calls
        .iter()
        .map(canonical_plan_member)
        .collect::<PyResult<Vec<_>>>()?;
    let borrowed = members.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let commitment = ProfilePlanCommitment::commit(PROFILE_ID, PROFILE_VERSION, &borrowed)
        .map_err(value_error)?;
    let permissions = calls
        .iter()
        .map(|call| {
            let canonical = canonical_http(call)?;
            Ok((
                canonical.permission().capability().as_str().to_owned(),
                canonical.permission().resource().as_str().to_owned(),
            ))
        })
        .collect::<PyResult<Vec<_>>>()?;
    Ok(PyNativeHttpPlan {
        commitment: *commitment.plan().as_bytes(),
        members: commitment
            .members()
            .iter()
            .map(|value| *value.as_bytes())
            .collect(),
        permissions,
        resource_namespaces: vec![origin_value.clone()],
        audiences: vec![origin_value],
    })
}

#[pyfunction]
fn prepare_http_action(
    call: PyRef<'_, PyHttpCall>,
    actor: PyRef<'_, PyPrincipal>,
    terminal_grant: PyRef<'_, PySignedObject>,
    challenge: &[u8],
    evaluation_time: u64,
) -> PyResult<PyHttpPreparedAction> {
    let SignedObject::Grant(terminal_grant) = &terminal_grant.inner else {
        return Err(PyTypeError::new_err(
            "terminal grant must be a signed grant",
        ));
    };
    let canonical = canonical_http(&call.inner)?;
    let display = HttpProfile::default()
        .review_display(&canonical)
        .map_err(value_error)?;
    let audience = Audience::parse(&origin(&call.inner)).map_err(value_error)?;
    let challenge: [u8; 32] = challenge
        .try_into()
        .map_err(|_| PyValueError::new_err("challenge must contain 32 bytes"))?;
    let prepared = prepare_profile_action(
        canonical,
        audience.clone(),
        actor.inner.clone(),
        terminal_grant,
        challenge,
        evaluation_time,
    )
    .map_err(value_error)?;
    let (canonical, envelope) = prepared.into_parts();
    Ok(PyHttpPreparedAction {
        canonical,
        envelope,
        audience: audience.to_string(),
        review_title: display.title().to_owned(),
        review_fields: display.fields().to_vec(),
    })
}

#[pyfunction]
fn authorize_http(
    py: Python<'_>,
    prepared: PyRef<'_, PyHttpPreparedAction>,
    signed_action: PyRef<'_, PySignedObject>,
    grants: Vec<Py<PySignedObject>>,
    grant_evidence: Vec<Vec<(String, String, Vec<u8>)>>,
    action_evidence: Vec<(String, String, Vec<u8>)>,
    context: PyRef<'_, PyTrustedContext>,
) -> PyResult<(NativeVerificationResult, Option<PyHttpCommand>)> {
    if grants.len() != grant_evidence.len() {
        return Err(PyValueError::new_err(
            "each grant requires one evidence collection",
        ));
    }
    let SignedObject::Action(action) = &signed_action.inner else {
        return Err(PyTypeError::new_err("signed action must be an action"));
    };
    if action.envelope() != &prepared.envelope {
        return Err(PyValueError::new_err(
            "signed action does not match its native preparation",
        ));
    }
    let mut builder = WorkflowProofBuilder::new();
    for (grant, evidence) in grants.iter().zip(grant_evidence) {
        let grant = grant.borrow(py);
        let SignedObject::Grant(grant) = &grant.inner else {
            return Err(PyTypeError::new_err("grant chain contains a non-grant"));
        };
        let index = builder.push_grant(grant.clone()).map_err(value_error)?;
        for (evidence_type, media_type, bytes) in evidence {
            builder
                .bind_grant_evidence(index, evidence_object(&evidence_type, &media_type, bytes)?)
                .map_err(value_error)?;
        }
    }
    for (evidence_type, media_type, bytes) in action_evidence {
        builder
            .bind_action_evidence(evidence_object(&evidence_type, &media_type, bytes)?)
            .map_err(value_error)?;
    }
    let artifacts = builder
        .finish(action, &prepared.canonical, &context.inner)
        .map_err(value_error)?;
    let proof = auths_codec::encode_bundle(artifacts.proof()).map_err(value_error)?;
    let canonical =
        auths_codec::encode_canonical_action(&prepared.canonical).map_err(value_error)?;
    let context = auths_codec::encode_verifier_context(artifacts.context()).map_err(value_error)?;
    let authority_commitment = *auths_codec::proof_digest(artifacts.proof())
        .map_err(value_error)?
        .as_bytes();
    let context_commitment = *auths_codec::context_digest(artifacts.context())
        .map_err(value_error)?
        .as_bytes();
    let sealed = verify_sealed(&proof, &canonical, &context)?;
    let command = sealed
        .action()
        .map(|action| HttpProfile::default().decode_verified(action))
        .transpose()
        .map_err(value_error)?
        .map(|inner| PyHttpCommand {
            inner: Some(inner),
            authority_commitment,
            context_commitment,
        });
    Ok((native_result(py, sealed)?, command))
}

#[pyfunction]
fn inspect_http_action<'py>(
    py: Python<'py>,
    action: PyRef<'_, PyHttpPreparedAction>,
) -> PyResult<Bound<'py, PyBytes>> {
    let bytes = auths_codec::encode_canonical_action(&action.canonical).map_err(value_error)?;
    Ok(PyBytes::new(py, &bytes))
}

#[pyfunction]
fn consume_http_command(
    mut command: PyRefMut<'_, PyHttpCommand>,
    expected_origin: &str,
) -> PyResult<PyHttpGatewayRequest> {
    if origin(command.command()?.action()) != expected_origin {
        return Err(PyTypeError::new_err(
            "HTTP command does not belong to this gateway",
        ));
    }
    let command = command
        .inner
        .take()
        .ok_or_else(|| PyRuntimeError::new_err("HTTP command has already been consumed"))?;
    Ok(gateway_request(command.action()))
}

#[pyfunction]
fn seal_http_plan_command(
    py: Python<'_>,
    commands: Vec<Py<PyHttpCommand>>,
    expected_origin: &str,
    expected_commitment: &[u8],
) -> PyResult<PyHttpPlanCommand> {
    if commands.is_empty() || commands.len() > 256 {
        return Err(PyValueError::new_err(
            "HTTP plan command count is outside native limits",
        ));
    }
    let expected: [u8; 32] = expected_commitment
        .try_into()
        .map_err(|_| PyValueError::new_err("plan commitment must contain 32 bytes"))?;
    let mut identities = HashSet::with_capacity(commands.len());
    if commands
        .iter()
        .any(|command| !identities.insert(command.as_ptr() as usize))
    {
        return Err(PyValueError::new_err(
            "HTTP plan contains a duplicate command handle",
        ));
    }
    let members = commands
        .iter()
        .map(|command| {
            let command = command.borrow(py);
            if origin(command.command()?.action()) != expected_origin {
                return Err(PyTypeError::new_err(
                    "HTTP command does not belong to this plan",
                ));
            }
            canonical_plan_member(command.command()?.action())
        })
        .collect::<PyResult<Vec<_>>>()?;
    let borrowed = members.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let commitment = ProfilePlanCommitment::commit(PROFILE_ID, PROFILE_VERSION, &borrowed)
        .map_err(value_error)?;
    if commitment.plan().as_bytes() != &expected {
        return Err(PyValueError::new_err(
            "verified commands do not match the exact HTTP plan",
        ));
    }
    let receipt_bindings = commands
        .iter()
        .map(|command| {
            let command = command.borrow(py);
            Ok((
                command.action_commitment_bytes()?,
                command.authority_commitment,
                command.context_commitment,
            ))
        })
        .collect::<PyResult<Vec<_>>>()?;
    let inner =
        commands
            .iter()
            .map(|command| {
                command.borrow_mut(py).inner.take().ok_or_else(|| {
                    PyRuntimeError::new_err("HTTP command has already been consumed")
                })
            })
            .collect::<PyResult<Vec<_>>>()?;
    Ok(PyHttpPlanCommand {
        commands: Some(inner),
        commitment: expected,
        receipt_bindings,
    })
}

#[pyfunction]
fn consume_http_plan_command(
    mut command: PyRefMut<'_, PyHttpPlanCommand>,
    expected_origin: &str,
) -> PyResult<Vec<PyHttpGatewayRequest>> {
    if command
        .commands()?
        .iter()
        .any(|value| origin(value.action()) != expected_origin)
    {
        return Err(PyTypeError::new_err(
            "HTTP plan command does not belong to this gateway",
        ));
    }
    command
        .commands
        .take()
        .ok_or_else(|| PyRuntimeError::new_err("HTTP plan command has already been consumed"))?
        .iter()
        .map(|value| Ok(gateway_request(value.action())))
        .collect()
}

fn canonical_http(action: &HttpAction) -> PyResult<auths_model::CanonicalAction> {
    let bytes = serde_json_canonicalizer::to_vec(action).map_err(value_error)?;
    HttpProfile::default()
        .canonicalize(&bytes)
        .map_err(value_error)
}

fn canonical_http_commitment(action: &HttpAction) -> PyResult<[u8; 32]> {
    let encoded =
        auths_codec::encode_canonical_action(&canonical_http(action)?).map_err(value_error)?;
    Ok(
        *auths_codec::domain_commitment("auths.canonical-action.v1", &encoded)
            .map_err(value_error)?
            .as_bytes(),
    )
}

fn canonical_plan_member(action: &HttpAction) -> PyResult<Vec<u8>> {
    ProfilePlanMember::encode(
        &canonical_http(action)?,
        &ResourceId::parse(&origin(action)).map_err(value_error)?,
        &Audience::parse(&origin(action)).map_err(value_error)?,
    )
    .map_err(value_error)
}

fn origin(action: &HttpAction) -> String {
    format!("{}://{}", action.scheme(), action.authority())
}

fn gateway_request(action: &HttpAction) -> PyHttpGatewayRequest {
    PyHttpGatewayRequest {
        method: action.method().to_owned(),
        scheme: action.scheme().to_owned(),
        authority: action.authority().to_owned(),
        path: action.path().to_owned(),
        query: action
            .query()
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        headers: action
            .headers()
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        content_type: action.content_type().map(str::to_owned),
        body_digest: action.body_digest().map(str::to_owned),
    }
}

fn evidence_object(
    evidence_type: &str,
    media_type: &str,
    bytes: Vec<u8>,
) -> PyResult<auths_model::EvidenceObject> {
    address_evidence(
        EvidenceTypeId::parse(evidence_type).map_err(value_error)?,
        MediaType::parse(media_type).map_err(value_error)?,
        bytes,
    )
    .map_err(value_error)
}

fn command_error() -> PyErr {
    PyTypeError::new_err("HttpCommand is a non-copyable native capability")
}

fn plan_command_error() -> PyErr {
    PyTypeError::new_err("HttpPlanCommand is a non-copyable native capability")
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyHttpCall>()?;
    module.add_class::<PyHttpPreparedAction>()?;
    module.add_class::<PyNativeHttpPlan>()?;
    module.add_class::<PyHttpCommand>()?;
    module.add_class::<PyHttpPlanCommand>()?;
    module.add_class::<PyHttpGatewayRequest>()?;
    module.add_function(wrap_pyfunction!(http_call, module)?)?;
    module.add_function(wrap_pyfunction!(review_http_call, module)?)?;
    module.add_function(wrap_pyfunction!(commit_http_plan, module)?)?;
    module.add_function(wrap_pyfunction!(prepare_http_action, module)?)?;
    module.add_function(wrap_pyfunction!(authorize_http, module)?)?;
    module.add_function(wrap_pyfunction!(inspect_http_action, module)?)?;
    module.add_function(wrap_pyfunction!(consume_http_command, module)?)?;
    module.add_function(wrap_pyfunction!(seal_http_plan_command, module)?)?;
    module.add_function(wrap_pyfunction!(consume_http_plan_command, module)?)?;
    Ok(())
}
