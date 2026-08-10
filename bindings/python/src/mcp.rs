#![allow(
    clippy::needless_pass_by_value,
    clippy::too_many_arguments,
    clippy::unused_self
)]

use crate::authoring::{
    PyMcpAction, PyPrincipal, PySignedObject, PyTrustedContext, SignedObject, value_error,
};
use crate::result::{NativeVerificationResult, native_result, verify_sealed};
use auths_author::{
    ProfilePlanCommitment, ProfilePlanMember, WorkflowProofBuilder, address_evidence,
    prepare_profile_action,
};
use auths_model::{EvidenceTypeId, MediaType, ResourceId};
use auths_profile_api::ActionProfile;
use auths_profile_mcp::{
    MAX_CANONICAL_CALL_BYTES, McpCommand, McpProfile, McpToolCall, PROFILE_ID, PROFILE_VERSION,
};
use pyo3::{
    exceptions::{PyRuntimeError, PyTypeError, PyValueError},
    prelude::*,
    types::PyBytes,
};
use serde_json::{Map, Value};

#[pyclass(
    name = "McpCall",
    frozen,
    module = "auths._native",
    skip_from_py_object
)]
pub struct PyMcpCall {
    inner: McpToolCall,
}

#[pymethods]
impl PyMcpCall {
    #[getter]
    fn service(&self) -> &str {
        self.inner.service()
    }

    #[getter]
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn __repr__(&self) -> String {
        format!(
            "McpCall(service={:?}, name={:?})",
            self.inner.service(),
            self.inner.name()
        )
    }
}

#[pyclass(
    name = "NativeMcpPlan",
    frozen,
    module = "auths._native",
    skip_from_py_object
)]
pub struct PyNativeMcpPlan {
    commitment: [u8; 32],
    members: Vec<[u8; 32]>,
    permissions: Vec<(String, String)>,
    resource_namespaces: Vec<String>,
    audiences: Vec<String>,
}

#[pymethods]
impl PyNativeMcpPlan {
    #[getter]
    fn commitment<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.commitment)
    }

    #[getter]
    fn members(&self) -> Vec<Vec<u8>> {
        self.members.iter().map(|member| member.to_vec()).collect()
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

#[pyclass(name = "McpCommand", module = "auths._native", skip_from_py_object)]
pub struct PyMcpCommand {
    inner: Option<McpCommand>,
}

#[pymethods]
impl PyMcpCommand {
    #[getter]
    fn service(&self) -> PyResult<&str> {
        Ok(self.command()?.call().service())
    }

    #[getter]
    fn name(&self) -> PyResult<&str> {
        Ok(self.command()?.name())
    }

    fn __repr__(&self) -> &'static str {
        if self.inner.is_some() {
            "McpCommand(<native sealed command>)"
        } else {
            "McpCommand(<consumed>)"
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

    fn __getstate__(&self) -> PyResult<()> {
        Err(command_error())
    }
}

#[pyclass(name = "McpPlanCommand", module = "auths._native", skip_from_py_object)]
pub struct PyMcpPlanCommand {
    commands: Option<Vec<McpCommand>>,
    commitment: [u8; 32],
}

#[pymethods]
impl PyMcpPlanCommand {
    #[getter]
    fn count(&self) -> PyResult<usize> {
        Ok(self.commands()?.len())
    }

    #[getter]
    fn plan_commitment<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.commitment)
    }

    fn __repr__(&self) -> &'static str {
        if self.commands.is_some() {
            "McpPlanCommand(<native sealed plan>)"
        } else {
            "McpPlanCommand(<consumed>)"
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

    fn __reduce_ex__(&self, _protocol: i32) -> PyResult<()> {
        Err(plan_command_error())
    }

    fn __getstate__(&self) -> PyResult<()> {
        Err(plan_command_error())
    }
}

impl PyMcpPlanCommand {
    fn commands(&self) -> PyResult<&[McpCommand]> {
        self.commands
            .as_deref()
            .ok_or_else(|| PyRuntimeError::new_err("MCP plan command has already been consumed"))
    }
}

impl PyMcpCommand {
    fn command(&self) -> PyResult<&McpCommand> {
        self.inner
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("MCP command has already been consumed"))
    }
}

#[pyclass(name = "McpGatewayCall", frozen, module = "auths._native")]
pub struct PyMcpGatewayCall {
    service: String,
    name: String,
    arguments_json: Vec<u8>,
}

#[pymethods]
impl PyMcpGatewayCall {
    #[getter]
    fn service(&self) -> &str {
        &self.service
    }

    #[getter]
    fn name(&self) -> &str {
        &self.name
    }

    #[getter]
    fn arguments_json<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.arguments_json)
    }
}

#[pyfunction]
fn validate_mcp_service(service: &str) -> PyResult<()> {
    McpToolCall::new(service, "profile-binding", Map::new()).map_err(value_error)?;
    Ok(())
}

#[pyfunction]
fn mcp_call(service: &str, name: &str, arguments_json: &[u8]) -> PyResult<PyMcpCall> {
    if arguments_json.is_empty() || arguments_json.len() > MAX_CANONICAL_CALL_BYTES {
        return Err(PyValueError::new_err("MCP arguments exceed native limits"));
    }
    let Value::Object(arguments) =
        serde_json::from_slice::<Value>(arguments_json).map_err(value_error)?
    else {
        return Err(PyValueError::new_err("MCP arguments must be a JSON object"));
    };
    Ok(PyMcpCall {
        inner: McpToolCall::new(service, name, arguments).map_err(value_error)?,
    })
}

#[pyfunction]
fn commit_mcp_plan(py: Python<'_>, calls: Vec<Py<PyMcpCall>>) -> PyResult<PyNativeMcpPlan> {
    if calls.is_empty() || calls.len() > 256 {
        return Err(PyValueError::new_err(
            "MCP plan action count is outside native limits",
        ));
    }
    let calls = calls
        .iter()
        .map(|call| call.borrow(py).inner.clone())
        .collect::<Vec<_>>();
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
            let canonical = McpProfile
                .canonicalize(&call.canonical_bytes().map_err(value_error)?)
                .map_err(value_error)?;
            Ok((
                canonical.permission().capability().as_str().to_owned(),
                canonical.permission().resource().as_str().to_owned(),
            ))
        })
        .collect::<PyResult<Vec<_>>>()?;
    let first = calls
        .first()
        .ok_or_else(|| PyValueError::new_err("MCP plan action count is outside native limits"))?;
    let resource_namespaces = vec![format!("mcp://{}", first.service())];
    let audiences = vec![first.audience().map_err(value_error)?.to_string()];
    Ok(PyNativeMcpPlan {
        commitment: *commitment.plan().as_bytes(),
        members: commitment
            .members()
            .iter()
            .map(|member| *member.as_bytes())
            .collect(),
        permissions,
        resource_namespaces,
        audiences,
    })
}

#[pyfunction]
fn prepare_mcp_call_action(
    call: PyRef<'_, PyMcpCall>,
    actor: PyRef<'_, PyPrincipal>,
    terminal_grant: PyRef<'_, PySignedObject>,
    challenge: &[u8],
    evaluation_time: u64,
) -> PyResult<PyMcpAction> {
    let SignedObject::Grant(terminal_grant) = &terminal_grant.inner else {
        return Err(PyTypeError::new_err(
            "terminal grant must be a signed grant",
        ));
    };
    let profile = McpProfile;
    let canonical = profile
        .canonicalize(&call.inner.canonical_bytes().map_err(value_error)?)
        .map_err(value_error)?;
    let display = profile.review_display(&canonical).map_err(value_error)?;
    let challenge: [u8; 32] = challenge
        .try_into()
        .map_err(|_| PyValueError::new_err("challenge must contain 32 bytes"))?;
    let prepared = prepare_profile_action(
        canonical,
        call.inner.audience().map_err(value_error)?,
        actor.inner.clone(),
        terminal_grant,
        challenge,
        evaluation_time,
    )
    .map_err(value_error)?;
    let (canonical, envelope) = prepared.into_parts();
    Ok(PyMcpAction {
        arguments_json: serde_json_canonicalizer::to_vec(call.inner.arguments())
            .map_err(value_error)?,
        audience: call.inner.audience().map_err(value_error)?.to_string(),
        resource: canonical.permission().resource().to_string(),
        display_digest_hex: display.canonical_digest_hex().to_owned(),
        review_title: display.title().to_owned(),
        review_fields: display.fields().to_vec(),
        canonical,
        envelope,
    })
}

#[pyfunction]
fn authorize_mcp(
    py: Python<'_>,
    prepared: PyRef<'_, PyMcpAction>,
    signed_action: PyRef<'_, PySignedObject>,
    grants: Vec<Py<PySignedObject>>,
    grant_evidence: Vec<Vec<(String, String, Vec<u8>)>>,
    action_evidence: Vec<(String, String, Vec<u8>)>,
    context: PyRef<'_, PyTrustedContext>,
) -> PyResult<(NativeVerificationResult, Option<PyMcpCommand>)> {
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
    let proof_cbor = auths_codec::encode_bundle(artifacts.proof()).map_err(value_error)?;
    let action_cbor =
        auths_codec::encode_canonical_action(&prepared.canonical).map_err(value_error)?;
    let context_cbor =
        auths_codec::encode_verifier_context(artifacts.context()).map_err(value_error)?;
    let sealed = verify_sealed(&proof_cbor, &action_cbor, &context_cbor)?;
    let command = sealed
        .action()
        .map(|action| McpProfile.decode_verified(action))
        .transpose()
        .map_err(value_error)?
        .map(|inner| PyMcpCommand { inner: Some(inner) });
    Ok((native_result(py, sealed)?, command))
}

#[pyfunction]
fn consume_mcp_command(
    mut command: PyRefMut<'_, PyMcpCommand>,
    expected_service: &str,
) -> PyResult<PyMcpGatewayCall> {
    if command.command()?.call().service() != expected_service {
        return Err(PyTypeError::new_err(
            "MCP command does not belong to this gateway",
        ));
    }
    let command = command
        .inner
        .take()
        .ok_or_else(|| PyRuntimeError::new_err("MCP command has already been consumed"))?;
    Ok(PyMcpGatewayCall {
        service: command.call().service().to_owned(),
        name: command.name().to_owned(),
        arguments_json: serde_json_canonicalizer::to_vec(command.arguments())
            .map_err(value_error)?,
    })
}

#[pyfunction]
fn seal_mcp_plan_command(
    py: Python<'_>,
    commands: Vec<Py<PyMcpCommand>>,
    expected_service: &str,
    expected_commitment: &[u8],
) -> PyResult<PyMcpPlanCommand> {
    if commands.is_empty() || commands.len() > 256 {
        return Err(PyValueError::new_err(
            "MCP plan command count is outside native limits",
        ));
    }
    let expected: [u8; 32] = expected_commitment
        .try_into()
        .map_err(|_| PyValueError::new_err("plan commitment must contain 32 bytes"))?;
    let mut identities = std::collections::HashSet::with_capacity(commands.len());
    if commands
        .iter()
        .any(|command| !identities.insert(command.as_ptr() as usize))
    {
        return Err(PyValueError::new_err(
            "MCP plan contains a duplicate command handle",
        ));
    }
    let members = commands
        .iter()
        .map(|command| {
            let command = command.borrow(py);
            if command.command()?.call().service() != expected_service {
                return Err(PyTypeError::new_err(
                    "MCP command does not belong to this plan",
                ));
            }
            canonical_plan_member(command.command()?.call())
        })
        .collect::<PyResult<Vec<_>>>()?;
    let borrowed = members.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let commitment = ProfilePlanCommitment::commit(PROFILE_ID, PROFILE_VERSION, &borrowed)
        .map_err(value_error)?;
    if commitment.plan().as_bytes() != &expected {
        return Err(PyValueError::new_err(
            "verified commands do not match the exact MCP plan",
        ));
    }
    let inner = commands
        .iter()
        .map(|command| {
            command
                .borrow_mut(py)
                .inner
                .take()
                .ok_or_else(|| PyRuntimeError::new_err("MCP command has already been consumed"))
        })
        .collect::<PyResult<Vec<_>>>()?;
    Ok(PyMcpPlanCommand {
        commands: Some(inner),
        commitment: expected,
    })
}

#[pyfunction]
fn consume_mcp_plan_command(
    mut command: PyRefMut<'_, PyMcpPlanCommand>,
    expected_service: &str,
) -> PyResult<Vec<PyMcpGatewayCall>> {
    if command
        .commands()?
        .iter()
        .any(|member| member.call().service() != expected_service)
    {
        return Err(PyTypeError::new_err(
            "MCP plan command does not belong to this gateway",
        ));
    }
    let commands = command
        .commands
        .take()
        .ok_or_else(|| PyRuntimeError::new_err("MCP plan command has already been consumed"))?;
    commands
        .into_iter()
        .map(|member| {
            Ok(PyMcpGatewayCall {
                service: member.call().service().to_owned(),
                name: member.name().to_owned(),
                arguments_json: serde_json_canonicalizer::to_vec(member.arguments())
                    .map_err(value_error)?,
            })
        })
        .collect()
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
    PyTypeError::new_err("McpCommand is a non-copyable native capability")
}

fn plan_command_error() -> PyErr {
    PyTypeError::new_err("McpPlanCommand is a non-copyable native capability")
}

fn canonical_plan_member(call: &McpToolCall) -> PyResult<Vec<u8>> {
    let canonical = McpProfile
        .canonicalize(&call.canonical_bytes().map_err(value_error)?)
        .map_err(value_error)?;
    ProfilePlanMember::encode(
        &canonical,
        &ResourceId::parse(&format!("mcp://{}", call.service())).map_err(value_error)?,
        &call.audience().map_err(value_error)?,
    )
    .map_err(value_error)
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyMcpCall>()?;
    module.add_class::<PyNativeMcpPlan>()?;
    module.add_class::<PyMcpCommand>()?;
    module.add_class::<PyMcpPlanCommand>()?;
    module.add_class::<PyMcpGatewayCall>()?;
    module.add_function(wrap_pyfunction!(validate_mcp_service, module)?)?;
    module.add_function(wrap_pyfunction!(mcp_call, module)?)?;
    module.add_function(wrap_pyfunction!(commit_mcp_plan, module)?)?;
    module.add_function(wrap_pyfunction!(prepare_mcp_call_action, module)?)?;
    module.add_function(wrap_pyfunction!(authorize_mcp, module)?)?;
    module.add_function(wrap_pyfunction!(consume_mcp_command, module)?)?;
    module.add_function(wrap_pyfunction!(seal_mcp_plan_command, module)?)?;
    module.add_function(wrap_pyfunction!(consume_mcp_plan_command, module)?)?;
    Ok(())
}
