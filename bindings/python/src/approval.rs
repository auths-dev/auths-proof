//! Thin projection of the remote approval operations in
//! `auths-approval-quorum`: requests, opening, approval, decline, and
//! collection. Every check, code, and review string is native.

#![allow(clippy::needless_pass_by_value)]

use crate::authoring::{PySignedObject, SignedObject, signing_descriptor, value_error};
use crate::mcp::evidence_object;
use crate::quorum::PyMcpQuorum;
use auths_approval_quorum::remote::{
    ApprovalCode, ApproverStatus, Collection, DECLINE_OBJECT_KIND, PendingApproval, PendingDecline,
    RegisteredProfile, ReviewProfile, ReviewedRequest, collect, open_request, requests,
};
use auths_model::{EvidenceObject, PrincipalId, ProfileId, ProfileRef, SignedGrant};
use auths_profile_mcp::{McpProfile, PROFILE_ID, PROFILE_VERSION};
use pyo3::{
    create_exception,
    exceptions::{PyRuntimeError, PyTypeError, PyValueError},
    prelude::*,
    types::PyBytes,
};

create_exception!(
    auths._native,
    ApprovalRefusal,
    PyValueError,
    "A remote approval operation refused its input; args[0] is the stable code."
);

type Evidence = (String, String, Vec<u8>);
type Status = (String, &'static str, Option<&'static str>, Option<u64>);
type IssuedRequest<'py> = (String, Bound<'py, PyBytes>, String, Bound<'py, PyBytes>);

fn refusal(code: ApprovalCode) -> PyErr {
    ApprovalRefusal::new_err(code.as_str())
}

fn mcp_profile() -> PyResult<RegisteredProfile<McpProfile>> {
    let profile = ProfileRef::new(
        ProfileId::parse(PROFILE_ID).map_err(value_error)?,
        PROFILE_VERSION,
    )
    .map_err(value_error)?;
    Ok(RegisteredProfile::new(profile, McpProfile))
}

fn principal(value: &str) -> PyResult<PrincipalId> {
    PrincipalId::parse(value).map_err(value_error)
}

fn evidence_objects(values: Vec<Evidence>) -> PyResult<Vec<EvidenceObject>> {
    values
        .into_iter()
        .map(|(evidence_type, media_type, bytes)| {
            evidence_object(&evidence_type, &media_type, bytes)
        })
        .collect()
}

fn grant_chain(
    py: Python<'_>,
    grants: Vec<Py<PySignedObject>>,
    evidence: Vec<Vec<Evidence>>,
) -> PyResult<Vec<(SignedGrant, Vec<EvidenceObject>)>> {
    if grants.len() != evidence.len() {
        return Err(crate::errors::malformed_input(
            "each grant requires one evidence collection",
        ));
    }
    grants
        .iter()
        .zip(evidence)
        .map(|(grant, evidence)| {
            let SignedObject::Grant(grant) = grant.borrow(py).inner.clone() else {
                return Err(PyTypeError::new_err("grant chain contains a non-grant"));
            };
            Ok((grant, evidence_objects(evidence)?))
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Returns `(approver, request bytes, printable form, request id)` for each
/// listed approver, in proposal order.
#[pyfunction]
fn approval_requests<'py>(
    py: Python<'py>,
    quorum: PyRef<'_, PyMcpQuorum>,
    requester: &str,
) -> PyResult<Vec<IssuedRequest<'py>>> {
    requests(quorum.proposal(), &principal(requester)?)
        .map_err(refusal)?
        .into_iter()
        .map(|request| {
            let bytes = request.encode().map_err(refusal)?;
            Ok((
                request.approver().as_str().to_owned(),
                PyBytes::new(py, &bytes),
                request.to_text().map_err(refusal)?,
                PyBytes::new(py, &request.request_id()),
            ))
        })
        .collect()
}

#[pyclass(name = "ReviewedApprovalRequest", frozen, module = "auths._native")]
pub struct PyReviewedApprovalRequest {
    inner: ReviewedRequest,
}

#[pymethods]
impl PyReviewedApprovalRequest {
    #[getter]
    fn title(&self) -> &str {
        self.inner.title()
    }

    #[getter]
    fn fields(&self) -> Vec<(String, String)> {
        self.inner.fields().to_vec()
    }

    #[getter]
    fn display_digest_hex(&self) -> &str {
        self.inner.display_digest_hex()
    }

    #[getter]
    fn requester(&self) -> &str {
        self.inner.requester().as_str()
    }

    #[getter]
    fn approvers(&self) -> Vec<String> {
        self.inner
            .approvers()
            .iter()
            .map(|approver| approver.as_str().to_owned())
            .collect()
    }

    #[getter]
    fn required(&self) -> u16 {
        self.inner.required()
    }

    #[getter]
    fn approver(&self) -> &str {
        self.inner.approver().as_str()
    }

    #[getter]
    fn window(&self) -> (u64, u64) {
        let window = self.inner.window();
        (window.not_before(), window.expires_at())
    }

    #[getter]
    fn request_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.request_id())
    }

    #[getter]
    fn canonical_action<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.canonical_action())
    }

    fn prepare_approval(
        &self,
        signer: &str,
        principal_method: &str,
        verification_method: &str,
        suite: &str,
    ) -> PyResult<PyPendingApproval> {
        let pending = self
            .inner
            .prepare_approval(
                &principal(signer)?,
                signing_descriptor(principal_method, verification_method, suite)?,
            )
            .map_err(refusal)?;
        Ok(PyPendingApproval {
            inner: Some(Pending::Approve(Box::new(pending))),
        })
    }

    fn prepare_decline(
        &self,
        signer: &str,
        principal_method: &str,
        verification_method: &str,
        suite: &str,
        decided_at: u64,
    ) -> PyResult<PyPendingApproval> {
        let pending = self
            .inner
            .prepare_decline(
                &principal(signer)?,
                signing_descriptor(principal_method, verification_method, suite)?,
                decided_at,
            )
            .map_err(refusal)?;
        Ok(PyPendingApproval {
            inner: Some(Pending::Decline(pending)),
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "ReviewedApprovalRequest(approver={:?}, request_id={})",
            self.inner.approver().as_str(),
            hex(&self.inner.request_id())
        )
    }
}

enum Pending {
    Approve(Box<PendingApproval>),
    Decline(PendingDecline),
}

/// The custody request for one approval or decline. Every field is native;
/// the SDK copies them into its custody signing request unchanged.
#[pyclass(name = "PendingApproval", module = "auths._native")]
pub struct PyPendingApproval {
    inner: Option<Pending>,
}

impl PyPendingApproval {
    fn pending(&self) -> PyResult<&Pending> {
        self.inner
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("approval was already completed"))
    }
}

#[pymethods]
impl PyPendingApproval {
    #[getter]
    fn decision(&self) -> PyResult<&'static str> {
        Ok(match self.pending()? {
            Pending::Approve(_) => "approve",
            Pending::Decline(_) => "decline",
        })
    }

    #[getter]
    fn object_kind(&self) -> PyResult<&'static str> {
        Ok(match self.pending()? {
            Pending::Approve(value) => value.signing().object_id().label(),
            Pending::Decline(_) => DECLINE_OBJECT_KIND,
        })
    }

    #[getter]
    fn request_id(&self) -> PyResult<String> {
        Ok(match self.pending()? {
            Pending::Approve(value) => value.signing().request_id(),
            Pending::Decline(value) => value.custody_request_id(),
        })
    }

    #[getter]
    fn object_id<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(match self.pending()? {
            Pending::Approve(value) => PyBytes::new(py, value.signing().object_id().as_bytes()),
            Pending::Decline(value) => PyBytes::new(py, &value.object_id()),
        })
    }

    #[getter]
    fn transaction_digest<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(match self.pending()? {
            Pending::Approve(value) => {
                PyBytes::new(py, value.signing().transaction_digest().as_bytes())
            }
            Pending::Decline(value) => PyBytes::new(py, &value.transaction_digest()),
        })
    }

    #[getter]
    fn signing_preimage<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(match self.pending()? {
            Pending::Approve(value) => PyBytes::new(py, value.signing().signing_preimage()),
            Pending::Decline(value) => PyBytes::new(py, value.signing_preimage()),
        })
    }

    #[getter]
    fn expires_at(&self) -> PyResult<u64> {
        Ok(match self.pending()? {
            Pending::Approve(value) => value.expires_at(),
            Pending::Decline(value) => value.expires_at(),
        })
    }

    #[getter]
    fn display(&self) -> PyResult<Vec<(String, String)>> {
        Ok(match self.pending()? {
            Pending::Approve(value) => value.display().to_vec(),
            Pending::Decline(value) => value.display().to_vec(),
        })
    }

    /// Completes the response. Returns `(bytes, printable form)`.
    fn complete<'py>(
        &mut self,
        py: Python<'py>,
        signature: &[u8],
        grants: Vec<Py<PySignedObject>>,
        grant_evidence: Vec<Vec<Evidence>>,
        action_evidence: Vec<Evidence>,
    ) -> PyResult<(Bound<'py, PyBytes>, String)> {
        let chain = grant_chain(py, grants, grant_evidence)?;
        let evidence = evidence_objects(action_evidence)?;
        let response = match self
            .inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("approval was already completed"))?
        {
            Pending::Approve(value) => value.complete(signature, chain, evidence),
            Pending::Decline(value) => value.complete(signature, chain, evidence),
        }
        .map_err(refusal)?;
        let bytes = response.encode().map_err(refusal)?;
        Ok((
            PyBytes::new(py, &bytes),
            response.to_text().map_err(refusal)?,
        ))
    }
}

/// Opens one request given as CBOR bytes or its printable form (UTF-8).
#[pyfunction]
fn open_approval_request(data: &[u8], now: u64) -> PyResult<PyReviewedApprovalRequest> {
    let mcp = mcp_profile()?;
    let profiles: [&dyn ReviewProfile; 1] = [&mcp];
    Ok(PyReviewedApprovalRequest {
        inner: open_request(data, &profiles, now).map_err(refusal)?,
    })
}

#[pyclass(name = "ApprovalCollection", frozen, module = "auths._native")]
pub struct PyApprovalCollection {
    statuses: Vec<Status>,
    unattributed: Vec<(usize, &'static str)>,
    proof: Result<Vec<u8>, ApprovalCode>,
}

#[pymethods]
impl PyApprovalCollection {
    /// `(approver, status, code, decided_at)` per listed approver.
    #[getter]
    fn statuses(&self) -> Vec<Status> {
        self.statuses.clone()
    }

    #[getter]
    fn unattributed(&self) -> Vec<(usize, &'static str)> {
        self.unattributed.clone()
    }

    fn assemble<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        match &self.proof {
            Ok(proof) => Ok(PyBytes::new(py, proof)),
            Err(code) => Err(refusal(*code)),
        }
    }
}

fn project(collection: &Collection<'_>) -> PyResult<PyApprovalCollection> {
    let statuses = collection
        .statuses()
        .iter()
        .zip(collection.approvers())
        .map(|(status, approver)| {
            let approver = approver.as_str().to_owned();
            match status {
                ApproverStatus::Pending => (approver, "pending", None, None),
                ApproverStatus::Approved => (approver, "approved", None, None),
                ApproverStatus::Declined(decline) => {
                    (approver, "declined", None, Some(decline.decided_at()))
                }
                ApproverStatus::Rejected(code) => (approver, "rejected", Some(code.as_str()), None),
            }
        })
        .collect();
    let proof = match collection.assemble() {
        Ok(bundle) => Ok(auths_codec::encode_bundle(&bundle).map_err(value_error)?),
        Err(code) => Err(code),
    };
    Ok(PyApprovalCollection {
        statuses,
        unattributed: collection
            .unattributed()
            .iter()
            .map(|(index, code)| (*index, code.as_str()))
            .collect(),
        proof,
    })
}

#[pyfunction]
fn collect_approvals(
    quorum: PyRef<'_, PyMcpQuorum>,
    responses: Vec<Vec<u8>>,
) -> PyResult<PyApprovalCollection> {
    project(&collect(quorum.proposal(), &responses).map_err(refusal)?)
}

pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("ApprovalRefusal", module.py().get_type::<ApprovalRefusal>())?;
    module.add_class::<PyReviewedApprovalRequest>()?;
    module.add_class::<PyPendingApproval>()?;
    module.add_class::<PyApprovalCollection>()?;
    module.add_function(wrap_pyfunction!(approval_requests, module)?)?;
    module.add_function(wrap_pyfunction!(open_approval_request, module)?)?;
    module.add_function(wrap_pyfunction!(collect_approvals, module)?)?;
    Ok(())
}
