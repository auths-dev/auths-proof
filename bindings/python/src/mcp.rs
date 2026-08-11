#![allow(
    clippy::needless_pass_by_value,
    clippy::too_many_arguments,
    clippy::unused_self
)]

use crate::ReviewProjection;
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
    MAX_CANONICAL_CALL_BYTES, McpCause, McpCommand, McpExecutionSession, McpHandlerEffect,
    McpHandlerResult, McpProfile, McpReservationResult, McpSessionKey, McpSessionStep, McpTerminal,
    McpToolCall, PROFILE_ID, PROFILE_VERSION,
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
    authority_commitment: [u8; 32],
    context_commitment: [u8; 32],
}

#[pymethods]
impl PyMcpCommand {
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
    receipt_bindings: Vec<([u8; 32], [u8; 32], [u8; 32])>,
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

    fn action_commitment_bytes(&self) -> PyResult<[u8; 32]> {
        canonical_action_commitment(self.command()?.call())
    }
}

#[pyclass(name = "McpGatewayCall", frozen, module = "auths._native")]
pub struct PyMcpGatewayCall {
    service: String,
    name: String,
    arguments_json: Vec<u8>,
}

#[pyclass(
    name = "McpSessionStep",
    frozen,
    module = "auths._native",
    skip_from_py_object
)]
pub struct PyMcpSessionStep {
    kind: &'static str,
    execution_id: String,
    service: Option<String>,
    tool: Option<String>,
    bytes: Option<Vec<u8>>,
}

#[pymethods]
impl PyMcpSessionStep {
    #[getter]
    fn kind(&self) -> &'static str {
        self.kind
    }

    #[getter]
    fn execution_id(&self) -> &str {
        &self.execution_id
    }

    #[getter]
    fn service(&self) -> Option<&str> {
        self.service.as_deref()
    }

    #[getter]
    fn tool(&self) -> Option<&str> {
        self.tool.as_deref()
    }

    #[getter]
    fn bytes<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.bytes.as_ref().map(|value| PyBytes::new(py, value))
    }
}

#[pyclass(
    name = "McpSessionTerminal",
    frozen,
    module = "auths._native",
    skip_from_py_object
)]
pub struct PyMcpSessionTerminal {
    kind: &'static str,
    execution_id: String,
    output_json: Option<Vec<u8>>,
    receipt_json: Option<Vec<u8>>,
    reference: Option<String>,
    record_json: Option<Vec<u8>>,
}

#[pymethods]
impl PyMcpSessionTerminal {
    #[getter]
    fn kind(&self) -> &'static str {
        self.kind
    }

    #[getter]
    fn execution_id(&self) -> &str {
        &self.execution_id
    }

    #[getter]
    fn output_json<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.output_json
            .as_ref()
            .map(|value| PyBytes::new(py, value))
    }

    #[getter]
    fn receipt_json<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.receipt_json
            .as_ref()
            .map(|value| PyBytes::new(py, value))
    }

    #[getter]
    fn reference(&self) -> Option<&str> {
        self.reference.as_deref()
    }

    #[getter]
    fn record_json<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.record_json
            .as_ref()
            .map(|value| PyBytes::new(py, value))
    }
}

#[pyclass(
    name = "McpExecutionSession",
    module = "auths._native",
    skip_from_py_object
)]
pub struct PyMcpExecutionSession {
    inner: McpExecutionSession,
}

#[pymethods]
impl PyMcpExecutionSession {
    #[getter]
    fn execution_id(&self) -> &str {
        self.inner.execution_id()
    }

    fn next_step(&mut self) -> PyResult<PyMcpSessionStep> {
        self.inner
            .next_step()
            .map(session_step)
            .map_err(session_error)
    }

    fn accept_reservation(&mut self, result: &str) -> PyResult<()> {
        let result = match result {
            "acquired" => McpReservationResult::Acquired,
            "exact-replay" => McpReservationResult::ExactReplay,
            "conflict" => McpReservationResult::Conflict,
            _ => return Err(PyValueError::new_err("invalid MCP reservation result")),
        };
        self.inner.accept_reservation(result).map_err(session_error)
    }

    fn accept_provider_entry(&mut self) -> PyResult<()> {
        self.inner.accept_provider_entry().map_err(session_error)
    }

    fn cancel_before_provider(&mut self) -> PyResult<()> {
        self.inner.cancel_before_provider().map_err(session_error)
    }

    #[pyo3(signature = (effect, output_json=None, cause=None))]
    fn accept_handler(
        &mut self,
        effect: &str,
        output_json: Option<&[u8]>,
        cause: Option<&str>,
    ) -> PyResult<()> {
        let effect = match effect {
            "not-applied" => McpHandlerEffect::NotApplied,
            "applied" => McpHandlerEffect::Applied,
            "possible" => McpHandlerEffect::Possible,
            _ => return Err(PyValueError::new_err("invalid MCP handler effect")),
        };
        let cause = cause.map(parse_cause).transpose()?;
        let result = McpHandlerResult::parse(effect, output_json, cause).map_err(session_error)?;
        self.inner.accept_handler(result).map_err(session_error)
    }

    fn accept_receipt(&mut self, persisted: bool) -> PyResult<()> {
        self.inner.accept_receipt(persisted).map_err(session_error)
    }

    fn terminal(&self) -> Option<PyMcpSessionTerminal> {
        self.inner.terminal().map(session_terminal)
    }

    fn __repr__(&self) -> &'static str {
        "McpExecutionSession(<native closed session>)"
    }

    fn __copy__(&self) -> PyResult<()> {
        Err(session_capability_error())
    }

    fn __deepcopy__(&self, _memo: &Bound<'_, PyAny>) -> PyResult<()> {
        Err(session_capability_error())
    }

    fn __reduce__(&self) -> PyResult<()> {
        Err(session_capability_error())
    }

    fn __reduce_ex__(&self, _protocol: i32) -> PyResult<()> {
        Err(session_capability_error())
    }

    fn __getstate__(&self) -> PyResult<()> {
        Err(session_capability_error())
    }
}

#[pyfunction]
#[pyo3(signature = (command, session_key, request_id=None))]
fn begin_mcp_execution(
    mut command: PyRefMut<'_, PyMcpCommand>,
    session_key: &[u8],
    request_id: Option<&str>,
) -> PyResult<PyMcpExecutionSession> {
    let key: [u8; 32] = session_key
        .try_into()
        .map_err(|_| PyValueError::new_err("MCP session key must contain 32 bytes"))?;
    let action_commitment = command.action_commitment_bytes()?;
    let authority_commitment = command.authority_commitment;
    let context_commitment = command.context_commitment;
    let inner = command
        .inner
        .take()
        .ok_or_else(|| PyRuntimeError::new_err("MCP command has already been consumed"))?;
    let session = McpExecutionSession::begin(
        inner,
        action_commitment,
        authority_commitment,
        context_commitment,
        request_id,
        McpSessionKey::new(key),
    )
    .map_err(session_error)?;
    Ok(PyMcpExecutionSession { inner: session })
}

#[pyfunction]
fn resume_mcp_execution(
    session_key: &[u8],
    reference: &str,
    record_json: &[u8],
) -> PyResult<PyMcpExecutionSession> {
    let key: [u8; 32] = session_key
        .try_into()
        .map_err(|_| PyValueError::new_err("MCP session key must contain 32 bytes"))?;
    let inner = McpExecutionSession::resume(McpSessionKey::new(key), reference, record_json)
        .map_err(session_error)?;
    Ok(PyMcpExecutionSession { inner })
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
fn review_mcp_call<'py>(
    py: Python<'py>,
    call: PyRef<'_, PyMcpCall>,
) -> PyResult<ReviewProjection<'py>> {
    let canonical = McpProfile
        .canonicalize(&call.inner.canonical_bytes().map_err(value_error)?)
        .map_err(value_error)?;
    let display = McpProfile.review_display(&canonical).map_err(value_error)?;
    let commitment = canonical_action_commitment(&call.inner)?;
    Ok((
        display.title().to_owned(),
        display.fields().to_vec(),
        PyBytes::new(py, &commitment),
    ))
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
    let authority_commitment = *auths_codec::proof_digest(artifacts.proof())
        .map_err(value_error)?
        .as_bytes();
    let context_commitment = *auths_codec::context_digest(artifacts.context())
        .map_err(value_error)?
        .as_bytes();
    let sealed = verify_sealed(&proof_cbor, &action_cbor, &context_cbor)?;
    let command = sealed
        .action()
        .map(|action| McpProfile.decode_verified(action))
        .transpose()
        .map_err(value_error)?
        .map(|inner| PyMcpCommand {
            inner: Some(inner),
            authority_commitment,
            context_commitment,
        });
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
        receipt_bindings,
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

fn canonical_action_commitment(call: &McpToolCall) -> PyResult<[u8; 32]> {
    let canonical = McpProfile
        .canonicalize(&call.canonical_bytes().map_err(value_error)?)
        .map_err(value_error)?;
    let encoded = auths_codec::encode_canonical_action(&canonical).map_err(value_error)?;
    Ok(
        *auths_codec::domain_commitment("auths.canonical-action.v1", &encoded)
            .map_err(value_error)?
            .as_bytes(),
    )
}

fn session_step(step: McpSessionStep) -> PyMcpSessionStep {
    match step {
        McpSessionStep::Reserve { execution_id } => PyMcpSessionStep {
            kind: "reserve",
            execution_id,
            service: None,
            tool: None,
            bytes: None,
        },
        McpSessionStep::MarkProviderEntry { execution_id } => PyMcpSessionStep {
            kind: "mark-provider-entry",
            execution_id,
            service: None,
            tool: None,
            bytes: None,
        },
        McpSessionStep::Invoke {
            execution_id,
            service,
            tool,
            arguments_json,
        } => PyMcpSessionStep {
            kind: "invoke",
            execution_id,
            service: Some(service),
            tool: Some(tool),
            bytes: Some(arguments_json),
        },
        McpSessionStep::PersistReceipt {
            execution_id,
            receipt_json,
        } => PyMcpSessionStep {
            kind: "persist-receipt",
            execution_id,
            service: None,
            tool: None,
            bytes: Some(receipt_json),
        },
        McpSessionStep::Reconcile {
            execution_id,
            service,
        } => PyMcpSessionStep {
            kind: "reconcile",
            execution_id,
            service: Some(service),
            tool: None,
            bytes: None,
        },
    }
}

fn session_terminal(value: &McpTerminal) -> PyMcpSessionTerminal {
    match value {
        McpTerminal::Completed {
            execution_id,
            output_json,
            receipt_json,
        } => PyMcpSessionTerminal {
            kind: "completed",
            execution_id: execution_id.clone(),
            output_json: Some(output_json.clone()),
            receipt_json: Some(receipt_json.clone()),
            reference: None,
            record_json: None,
        },
        McpTerminal::NotApplied { execution_id } => PyMcpSessionTerminal {
            kind: "not-applied",
            execution_id: execution_id.clone(),
            output_json: None,
            receipt_json: None,
            reference: None,
            record_json: None,
        },
        McpTerminal::ExactReplay { execution_id } => PyMcpSessionTerminal {
            kind: "exact-replay",
            execution_id: execution_id.clone(),
            output_json: None,
            receipt_json: None,
            reference: None,
            record_json: None,
        },
        McpTerminal::Conflict { execution_id } => PyMcpSessionTerminal {
            kind: "conflict",
            execution_id: execution_id.clone(),
            output_json: None,
            receipt_json: None,
            reference: None,
            record_json: None,
        },
        McpTerminal::Recoverable {
            execution_id,
            reference,
            record_json,
        } => PyMcpSessionTerminal {
            kind: "recoverable",
            execution_id: execution_id.clone(),
            output_json: None,
            receipt_json: None,
            reference: Some(reference.as_str().to_owned()),
            record_json: Some(record_json.clone()),
        },
    }
}

fn parse_cause(value: &str) -> PyResult<McpCause> {
    match value {
        "cancelled" => Ok(McpCause::Cancelled),
        "invalid-output" => Ok(McpCause::InvalidOutput),
        "limit-exceeded" => Ok(McpCause::LimitExceeded),
        "timeout" => Ok(McpCause::Timeout),
        "unavailable" => Ok(McpCause::Unavailable),
        "unknown" => Ok(McpCause::Unknown),
        _ => Err(PyValueError::new_err("invalid MCP cause category")),
    }
}

fn session_error(error: auths_profile_mcp::McpSessionError) -> PyErr {
    PyRuntimeError::new_err(format!("MCP session rejected transition: {error:?}"))
}

fn session_capability_error() -> PyErr {
    PyTypeError::new_err("MCP execution sessions are non-copyable native capabilities")
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyMcpCall>()?;
    module.add_class::<PyNativeMcpPlan>()?;
    module.add_class::<PyMcpCommand>()?;
    module.add_class::<PyMcpPlanCommand>()?;
    module.add_class::<PyMcpGatewayCall>()?;
    module.add_class::<PyMcpSessionStep>()?;
    module.add_class::<PyMcpSessionTerminal>()?;
    module.add_class::<PyMcpExecutionSession>()?;
    module.add_function(wrap_pyfunction!(validate_mcp_service, module)?)?;
    module.add_function(wrap_pyfunction!(mcp_call, module)?)?;
    module.add_function(wrap_pyfunction!(review_mcp_call, module)?)?;
    module.add_function(wrap_pyfunction!(commit_mcp_plan, module)?)?;
    module.add_function(wrap_pyfunction!(prepare_mcp_call_action, module)?)?;
    module.add_function(wrap_pyfunction!(authorize_mcp, module)?)?;
    module.add_function(wrap_pyfunction!(consume_mcp_command, module)?)?;
    module.add_function(wrap_pyfunction!(seal_mcp_plan_command, module)?)?;
    module.add_function(wrap_pyfunction!(consume_mcp_plan_command, module)?)?;
    module.add_function(wrap_pyfunction!(begin_mcp_execution, module)?)?;
    module.add_function(wrap_pyfunction!(resume_mcp_execution, module)?)?;
    Ok(())
}
