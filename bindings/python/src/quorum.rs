//! Thin projection of `auths-approval-quorum` for one exact MCP action: the
//! actor's envelope, one approval statement per listed approver, and
//! assembly. Every check, identifier, and window is native.

#![allow(clippy::needless_pass_by_value)]

use crate::authoring::{
    PySignedObject, PyUnsignedObject, SignedObject, UnsignedObject, signing_descriptor, value_error,
};
use crate::mcp::evidence_object;
use auths_approval_quorum::{
    MAX_APPROVER_EVIDENCE, MAX_APPROVERS, QuorumAction, QuorumActor, QuorumProposal,
};
use auths_author::{ExternalSigningRequest, prepare_approval};
use auths_model::{
    ApprovalStatement, EvidenceObject, PrincipalId, SignatureBytes, SignedApproval, SignedGrant,
};
use auths_profile_api::ActionProfile;
use auths_profile_mcp::{McpProfile, McpToolCall};
use pyo3::{
    exceptions::{PyRuntimeError, PyTypeError},
    prelude::*,
    types::PyBytes,
};
use serde_json::Value;

pub(crate) type Evidence = (String, String, Vec<u8>);

#[pyclass(name = "McpQuorum", frozen, module = "auths._native")]
pub struct PyMcpQuorum {
    proposal: QuorumProposal,
    canonical_action: Vec<u8>,
    arguments_json: Vec<u8>,
    audience: String,
    resource: String,
    review_fields: Vec<(String, String)>,
}

impl PyMcpQuorum {
    pub(crate) const fn proposal(&self) -> &QuorumProposal {
        &self.proposal
    }
}

#[pymethods]
impl PyMcpQuorum {
    #[getter]
    fn required(&self) -> u16 {
        self.proposal.required()
    }

    /// The listed approvers, in ascending order.
    #[getter]
    fn approvers(&self) -> Vec<String> {
        self.proposal
            .approvers()
            .iter()
            .map(|approver| approver.as_str().to_owned())
            .collect()
    }

    #[getter]
    fn actor(&self) -> &str {
        self.proposal.actor().as_str()
    }

    #[getter]
    fn requirement_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.proposal.requirement_id().as_bytes())
    }

    #[getter]
    fn canonical_action<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.canonical_action)
    }

    #[getter]
    fn arguments_json<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.arguments_json)
    }

    #[getter]
    fn audience(&self) -> &str {
        &self.audience
    }

    #[getter]
    fn resource(&self) -> &str {
        &self.resource
    }

    #[getter]
    fn review_fields(&self) -> Vec<(String, String)> {
        self.review_fields.clone()
    }

    /// `(not_before, expires_at)`, shared by the envelope and every statement.
    #[getter]
    fn validity(&self) -> (u64, u64) {
        let validity = self.proposal.envelope().validity();
        (validity.not_before().get(), validity.expires_at().get())
    }

    /// The actor's unsigned envelope, for `prepare_signing`.
    fn unsigned_action(&self) -> PyUnsignedObject {
        PyUnsignedObject {
            inner: UnsignedObject::Action(self.proposal.envelope().clone()),
        }
    }

    /// The custody request for `approver`'s statement, bound to the action's
    /// profile. Refuses an approver the proposal does not list.
    fn prepare_approval(
        &self,
        approver: &str,
        principal_method: &str,
        verification_method: &str,
        suite: &str,
    ) -> PyResult<PyApprovalSigningRequest> {
        let approver = PrincipalId::parse(approver).map_err(value_error)?;
        let statement = self
            .proposal
            .statement(&approver)
            .ok_or_else(|| value_error("approver is not listed by this proposal"))?;
        let signing = prepare_approval(
            statement.clone(),
            signing_descriptor(principal_method, verification_method, suite)?,
            self.proposal.canonical().profile(),
        )
        .map_err(value_error)?;
        Ok(PyApprovalSigningRequest {
            inner: Some(signing),
            expires_at: statement.validity().expires_at().get(),
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "McpQuorum(required={}, approvers={})",
            self.proposal.required(),
            self.proposal.approvers().len()
        )
    }
}

/// The custody request for one approval statement, completed once.
#[pyclass(name = "ApprovalSigningRequest", module = "auths._native")]
pub struct PyApprovalSigningRequest {
    inner: Option<ExternalSigningRequest<ApprovalStatement>>,
    expires_at: u64,
}

impl PyApprovalSigningRequest {
    fn request(&self) -> PyResult<&ExternalSigningRequest<ApprovalStatement>> {
        self.inner
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("approval was already completed"))
    }
}

#[pymethods]
impl PyApprovalSigningRequest {
    #[getter]
    fn object_kind(&self) -> PyResult<&'static str> {
        Ok(self.request()?.object_id().label())
    }

    #[getter]
    fn request_id(&self) -> PyResult<String> {
        Ok(self.request()?.request_id())
    }

    #[getter]
    fn object_id<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(py, self.request()?.object_id().as_bytes()))
    }

    #[getter]
    fn transaction_digest<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(
            py,
            self.request()?.transaction_digest().as_bytes(),
        ))
    }

    #[getter]
    fn signing_preimage<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(py, self.request()?.signing_preimage()))
    }

    /// The end of the approval window.
    #[getter]
    const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Completes the approval with the custody signature and the one to four
    /// evidence objects controlling it.
    fn complete(
        &mut self,
        signature: &[u8],
        evidence: Vec<Evidence>,
    ) -> PyResult<PySignedApproval> {
        let signature = SignatureBytes::new(signature.to_vec()).map_err(value_error)?;
        if evidence.is_empty() || evidence.len() > MAX_APPROVER_EVIDENCE {
            return Err(value_error("approval evidence count is outside bounds"));
        }
        let evidence = evidence_objects(evidence)?;
        let signing = self
            .inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("approval was already completed"))?;
        Ok(PySignedApproval {
            inner: signing.complete(signature, evidence).map_err(value_error)?,
        })
    }
}

/// One signed approval, ready for assembly.
#[pyclass(name = "SignedApproval", frozen, module = "auths._native")]
pub struct PySignedApproval {
    inner: SignedApproval,
}

#[pymethods]
impl PySignedApproval {
    #[getter]
    fn approver(&self) -> &str {
        self.inner.statement().approver().as_str()
    }

    fn __repr__(&self) -> String {
        format!(
            "SignedApproval(approver={:?})",
            self.inner.statement().approver().as_str()
        )
    }
}

/// The actor's signed envelope with its grant chain, root first, and the
/// public evidence controlling each grant and the action.
#[pyclass(name = "QuorumAction", frozen, module = "auths._native")]
pub struct PyQuorumAction {
    pub(crate) inner: QuorumAction,
}

#[pymethods]
impl PyQuorumAction {
    #[new]
    fn new(
        py: Python<'_>,
        signed_action: PyRef<'_, PySignedObject>,
        grants: Vec<Py<PySignedObject>>,
        grant_evidence: Vec<Vec<Evidence>>,
        action_evidence: Vec<Evidence>,
    ) -> PyResult<Self> {
        let SignedObject::Action(action) = signed_action.inner.clone() else {
            return Err(PyTypeError::new_err(
                "quorum action must be a signed action",
            ));
        };
        if grants.len() != grant_evidence.len() {
            return Err(crate::errors::malformed_input(
                "each grant requires one evidence collection",
            ));
        }
        let chain = grants
            .iter()
            .zip(grant_evidence)
            .map(|(grant, evidence)| {
                let SignedObject::Grant(grant) = grant.borrow(py).inner.clone() else {
                    return Err(PyTypeError::new_err("grant chain contains a non-grant"));
                };
                Ok((grant, evidence_objects(evidence)?))
            })
            .collect::<PyResult<Vec<_>>>()?;
        Ok(Self {
            inner: QuorumAction::new(action, chain, evidence_objects(action_evidence)?)
                .map_err(value_error)?,
        })
    }

    #[getter]
    fn actor(&self) -> &str {
        self.inner.action().envelope().actor().as_str()
    }
}

#[pyfunction]
#[pyo3(signature = (
    service, name, arguments_json, required, approvers, actor, actor_grant, challenge,
    evaluation_time, validity_seconds = None
))]
#[allow(clippy::too_many_arguments)]
fn prepare_mcp_quorum(
    service: &str,
    name: &str,
    arguments_json: &[u8],
    required: u16,
    approvers: Vec<String>,
    actor: &str,
    actor_grant: Option<PyRef<'_, PySignedObject>>,
    challenge: &[u8],
    evaluation_time: u64,
    validity_seconds: Option<u64>,
) -> PyResult<PyMcpQuorum> {
    let Value::Object(arguments) =
        serde_json::from_slice::<Value>(arguments_json).map_err(value_error)?
    else {
        return Err(crate::errors::malformed_input(
            "MCP arguments must be a JSON object",
        ));
    };
    let canonical_arguments = serde_json_canonicalizer::to_vec(&arguments).map_err(value_error)?;
    if canonical_arguments != arguments_json {
        return Err(crate::errors::malformed_input(
            "MCP arguments must use canonical JSON encoding",
        ));
    }
    let challenge: [u8; 32] = challenge
        .try_into()
        .map_err(|_| crate::errors::malformed_input("challenge must contain 32 bytes"))?;
    if approvers.len() > MAX_APPROVERS {
        return Err(value_error(
            "approval quorum threshold or approver count is invalid",
        ));
    }
    let approvers = approvers
        .iter()
        .map(|value| PrincipalId::parse(value).map_err(value_error))
        .collect::<PyResult<Vec<_>>>()?;
    let terminal: Option<SignedGrant> = match actor_grant.as_ref().map(|value| &value.inner) {
        None => None,
        Some(SignedObject::Grant(grant)) => Some(grant.clone()),
        Some(_) => {
            return Err(PyTypeError::new_err(
                "actor terminal grant must be a signed grant",
            ));
        }
    };
    let actor = QuorumActor::new(
        PrincipalId::parse(actor).map_err(value_error)?,
        terminal.as_ref(),
    )
    .map_err(value_error)?;
    let call = McpToolCall::new(service, name, arguments).map_err(value_error)?;
    let canonical = McpProfile
        .canonicalize(&call.canonical_bytes().map_err(value_error)?)
        .map_err(value_error)?;
    let display = McpProfile.review_display(&canonical).map_err(value_error)?;
    let canonical_action = auths_codec::encode_canonical_action(&canonical).map_err(value_error)?;
    let resource = canonical.permission().resource().to_string();
    let audience = call.audience().map_err(value_error)?;
    let proposal = QuorumProposal::new(
        canonical,
        &audience,
        challenge,
        evaluation_time,
        validity_seconds,
        required,
        &approvers,
        &actor,
    )
    .map_err(value_error)?;
    Ok(PyMcpQuorum {
        proposal,
        canonical_action,
        arguments_json: canonical_arguments,
        audience: audience.to_string(),
        resource,
        review_fields: display.fields().to_vec(),
    })
}

/// Assembles the proof from the actor's signed action and the approvals of
/// at least `required` distinct listed approvers.
#[pyfunction]
fn assemble_mcp_quorum_proof<'py>(
    py: Python<'py>,
    quorum: PyRef<'_, PyMcpQuorum>,
    action: PyRef<'_, PyQuorumAction>,
    approvals: Vec<Py<PySignedApproval>>,
) -> PyResult<Bound<'py, PyBytes>> {
    if approvals.len() > MAX_APPROVERS {
        return Err(value_error(
            "approval was supplied twice for the same approver",
        ));
    }
    let approvals: Vec<SignedApproval> = approvals
        .iter()
        .map(|approval| approval.get().inner.clone())
        .collect();
    let bundle = quorum
        .proposal
        .assemble(&action.inner, &approvals)
        .map_err(value_error)?;
    let proof = auths_codec::encode_bundle(&bundle).map_err(value_error)?;
    Ok(PyBytes::new(py, &proof))
}

pub(crate) fn evidence_objects(values: Vec<Evidence>) -> PyResult<Vec<EvidenceObject>> {
    values
        .into_iter()
        .map(|(evidence_type, media_type, bytes)| {
            evidence_object(&evidence_type, &media_type, bytes)
        })
        .collect()
}

pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyMcpQuorum>()?;
    module.add_class::<PyApprovalSigningRequest>()?;
    module.add_class::<PySignedApproval>()?;
    module.add_class::<PyQuorumAction>()?;
    module.add_function(wrap_pyfunction!(prepare_mcp_quorum, module)?)?;
    module.add_function(wrap_pyfunction!(assemble_mcp_quorum_proof, module)?)?;
    Ok(())
}
