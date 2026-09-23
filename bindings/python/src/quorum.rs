//! Thin projection of `auths-approval-quorum` for one exact MCP action.

#![allow(clippy::needless_pass_by_value)]

use crate::authoring::{
    PyPrincipal, PySignedObject, PyUnsignedObject, SignedObject, UnsignedObject, value_error,
};
use crate::mcp::evidence_object;
use auths_approval_quorum::{QuorumApproval, QuorumApprover, QuorumProposal};
use auths_model::{Timestamp, ValidityWindow};
use auths_profile_api::ActionProfile;
use auths_profile_mcp::{McpProfile, McpToolCall};
use pyo3::{exceptions::PyTypeError, prelude::*, types::PyBytes};
use serde_json::Value;

type Evidence = (String, String, Vec<u8>);
type Approval = (
    Py<PySignedObject>,
    Vec<Py<PySignedObject>>,
    Vec<Vec<Evidence>>,
    Vec<Evidence>,
);

#[pyclass(name = "McpQuorum", frozen, module = "auths._native")]
pub struct PyMcpQuorum {
    proposal: QuorumProposal,
    canonical_action: Vec<u8>,
    arguments_json: Vec<u8>,
    audience: String,
    resource: String,
    review_fields: Vec<(String, String)>,
}

#[pymethods]
impl PyMcpQuorum {
    #[getter]
    fn required(&self) -> u16 {
        self.proposal.required()
    }

    #[getter]
    fn approver_count(&self) -> usize {
        self.proposal.envelopes().len()
    }

    #[getter]
    fn approvers(&self) -> Vec<String> {
        self.proposal
            .envelopes()
            .iter()
            .map(|envelope| envelope.actor().as_str().to_owned())
            .collect()
    }

    #[getter]
    fn plan_id<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let id = auths_codec::plan_id(self.proposal.plan()).map_err(value_error)?;
        Ok(PyBytes::new(py, id.as_bytes()))
    }

    #[getter]
    fn canonical_plan<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes =
            auths_codec::encode_authorization_plan(self.proposal.plan()).map_err(value_error)?;
        Ok(PyBytes::new(py, &bytes))
    }

    #[getter]
    fn proof_references(&self) -> Vec<[u8; 32]> {
        self.proposal
            .envelopes()
            .iter()
            .map(|envelope| *envelope.proof_ref().as_bytes())
            .collect()
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

    fn unsigned(&self, index: usize) -> PyResult<PyUnsignedObject> {
        let envelope = self
            .proposal
            .envelopes()
            .get(index)
            .ok_or_else(|| crate::errors::malformed_input("approver index is out of range"))?;
        Ok(PyUnsignedObject {
            inner: UnsignedObject::Action(envelope.clone()),
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "McpQuorum(required={}, approvers={})",
            self.proposal.required(),
            self.proposal.envelopes().len()
        )
    }
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn prepare_mcp_quorum(
    py: Python<'_>,
    service: &str,
    name: &str,
    arguments_json: &[u8],
    approvers: Vec<(Py<PyPrincipal>, Option<Py<PySignedObject>>)>,
    required: u16,
    challenge: &[u8],
    not_before: u64,
    expires_at: u64,
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
    let members = approvers
        .iter()
        .map(|(actor, grant)| {
            let grant = grant.as_ref().map(|value| value.borrow(py));
            let terminal = match grant.as_ref().map(|value| &value.inner) {
                None => None,
                Some(SignedObject::Grant(grant)) => Some(grant),
                Some(_) => {
                    return Err(PyTypeError::new_err(
                        "terminal grant must be a signed grant",
                    ));
                }
            };
            QuorumApprover::new(actor.borrow(py).inner.clone(), terminal).map_err(value_error)
        })
        .collect::<PyResult<Vec<_>>>()?;
    let call = McpToolCall::new(service, name, arguments).map_err(value_error)?;
    let canonical = McpProfile
        .canonicalize(&call.canonical_bytes().map_err(value_error)?)
        .map_err(value_error)?;
    let display = McpProfile.review_display(&canonical).map_err(value_error)?;
    let validity = ValidityWindow::new(Timestamp::new(not_before), Timestamp::new(expires_at))
        .map_err(value_error)?;
    let canonical_action = auths_codec::encode_canonical_action(&canonical).map_err(value_error)?;
    let resource = canonical.permission().resource().to_string();
    let audience = call.audience().map_err(value_error)?;
    let proposal = QuorumProposal::new(
        canonical, &audience, challenge, validity, required, &members,
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

#[pyfunction]
fn assemble_mcp_quorum_proof<'py>(
    py: Python<'py>,
    quorum: PyRef<'_, PyMcpQuorum>,
    approvals: Vec<Approval>,
) -> PyResult<Bound<'py, PyBytes>> {
    let approvals = approvals
        .into_iter()
        .map(|(action, grants, grant_evidence, action_evidence)| {
            if grants.len() != grant_evidence.len() {
                return Err(crate::errors::malformed_input(
                    "each grant requires one evidence collection",
                ));
            }
            let SignedObject::Action(action) = action.borrow(py).inner.clone() else {
                return Err(PyTypeError::new_err("approval must be a signed action"));
            };
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
            QuorumApproval::new(action, chain, evidence_objects(action_evidence)?)
                .map_err(value_error)
        })
        .collect::<PyResult<Vec<_>>>()?;
    let bundle = quorum.proposal.assemble(&approvals).map_err(value_error)?;
    let proof = auths_codec::encode_bundle(&bundle).map_err(value_error)?;
    Ok(PyBytes::new(py, &proof))
}

fn evidence_objects(values: Vec<Evidence>) -> PyResult<Vec<auths_model::EvidenceObject>> {
    values
        .into_iter()
        .map(|(evidence_type, media_type, bytes)| {
            evidence_object(&evidence_type, &media_type, bytes)
        })
        .collect()
}

pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyMcpQuorum>()?;
    module.add_function(wrap_pyfunction!(prepare_mcp_quorum, module)?)?;
    module.add_function(wrap_pyfunction!(assemble_mcp_quorum_proof, module)?)?;
    Ok(())
}
