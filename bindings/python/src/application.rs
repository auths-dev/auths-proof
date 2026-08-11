#![allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]

use crate::authoring::{
    PyPrincipal, PySignedObject, PyTrustedContext, PyUnsignedObject, SignedObject, UnsignedObject,
    value_error,
};
use crate::result::{NativeVerificationResult, native_result, verify_sealed};
use auths_author::{
    ProfilePlanCommitment, ProfilePlanMember, WorkflowProofBuilder, address_evidence,
    prepare_profile_action,
};
use auths_model::{
    Audience, BudgetAlgebraId, BudgetCeiling, CanonicalAction, CapabilityId, EvidenceTypeId,
    MediaType, Permission, ProfileId, ProfileRef, ResourceId,
};
use pyo3::{
    exceptions::{PyRuntimeError, PyTypeError, PyValueError},
    prelude::*,
    types::PyBytes,
};
use std::collections::HashSet;

#[derive(Clone)]
#[pyclass(
    name = "ApplicationAction",
    frozen,
    module = "auths._native",
    skip_from_py_object
)]
pub struct PyApplicationAction {
    canonical: CanonicalAction,
    resource_namespace: ResourceId,
    audience: Audience,
}

#[pymethods]
impl PyApplicationAction {
    #[getter]
    fn profile_id(&self) -> &str {
        self.canonical.profile().id().as_str()
    }

    #[getter]
    fn profile_version(&self) -> u16 {
        self.canonical.profile().version()
    }

    #[getter]
    fn media_type(&self) -> &str {
        self.canonical.media_type().as_str()
    }

    #[getter]
    fn body<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.canonical.body())
    }

    #[getter]
    fn permission(&self) -> (String, String) {
        (
            self.canonical.permission().capability().as_str().to_owned(),
            self.canonical.permission().resource().as_str().to_owned(),
        )
    }

    #[getter]
    fn resource_namespace(&self) -> &str {
        self.resource_namespace.as_str()
    }

    #[getter]
    fn audience(&self) -> &str {
        self.audience.as_str()
    }

    #[getter]
    fn budget(&self) -> Option<(String, u64)> {
        self.canonical
            .requested_budget()
            .map(|value| (value.algebra().as_str().to_owned(), value.value()))
    }
}

#[pyclass(
    name = "ApplicationActionPreparation",
    frozen,
    module = "auths._native",
    skip_from_py_object
)]
pub struct PyApplicationActionPreparation {
    action: PyApplicationAction,
    envelope: auths_model::ActionEnvelope,
}

#[pymethods]
impl PyApplicationActionPreparation {
    #[getter]
    fn unsigned(&self) -> PyUnsignedObject {
        PyUnsignedObject {
            inner: UnsignedObject::Action(self.envelope.clone()),
        }
    }
}

#[pyclass(
    name = "ApplicationCommand",
    module = "auths._native",
    skip_from_py_object
)]
pub struct PyApplicationCommand {
    action: Option<PyApplicationAction>,
    authority_commitment: [u8; 32],
    context_commitment: [u8; 32],
}

#[pymethods]
impl PyApplicationCommand {
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
    fn profile_id(&self) -> PyResult<&str> {
        Ok(self.action()?.canonical.profile().id().as_str())
    }

    #[getter]
    fn profile_version(&self) -> PyResult<u16> {
        Ok(self.action()?.canonical.profile().version())
    }

    fn __repr__(&self) -> &'static str {
        if self.action.is_some() {
            "ApplicationCommand(<native sealed command>)"
        } else {
            "ApplicationCommand(<consumed>)"
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

impl PyApplicationCommand {
    fn action(&self) -> PyResult<&PyApplicationAction> {
        self.action
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("application command has already been consumed"))
    }

    fn action_commitment_bytes(&self) -> PyResult<[u8; 32]> {
        application_action_commitment(self.action()?)
    }
}

#[pyclass(
    name = "ApplicationPlanCommand",
    module = "auths._native",
    skip_from_py_object
)]
pub struct PyApplicationPlanCommand {
    actions: Option<Vec<PyApplicationAction>>,
    commitment: [u8; 32],
    receipt_bindings: Vec<([u8; 32], [u8; 32], [u8; 32])>,
}

#[pymethods]
impl PyApplicationPlanCommand {
    #[getter]
    fn count(&self) -> PyResult<usize> {
        Ok(self.actions()?.len())
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
        if self.actions.is_some() {
            "ApplicationPlanCommand(<native sealed plan>)"
        } else {
            "ApplicationPlanCommand(<consumed>)"
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

impl PyApplicationPlanCommand {
    fn actions(&self) -> PyResult<&[PyApplicationAction]> {
        self.actions.as_deref().ok_or_else(|| {
            PyRuntimeError::new_err("application plan command has already been consumed")
        })
    }
}

#[pyclass(name = "NativeApplicationPlan", frozen, module = "auths._native")]
pub struct PyNativeApplicationPlan {
    commitment: [u8; 32],
    members: Vec<[u8; 32]>,
}

#[pymethods]
impl PyNativeApplicationPlan {
    #[getter]
    fn commitment<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.commitment)
    }

    #[getter]
    fn members(&self) -> Vec<Vec<u8>> {
        self.members.iter().map(|value| value.to_vec()).collect()
    }
}

#[pyclass(name = "ApplicationGatewayCall", frozen, module = "auths._native")]
pub struct PyApplicationGatewayCall {
    profile_id: String,
    profile_version: u16,
    media_type: String,
    body: Vec<u8>,
    permission: (String, String),
    resource_namespace: String,
    audience: String,
    budget: Option<(String, u64)>,
}

#[pymethods]
impl PyApplicationGatewayCall {
    #[getter]
    fn profile_id(&self) -> &str {
        &self.profile_id
    }
    #[getter]
    fn profile_version(&self) -> u16 {
        self.profile_version
    }
    #[getter]
    fn media_type(&self) -> &str {
        &self.media_type
    }
    #[getter]
    fn body<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.body)
    }
    #[getter]
    fn permission(&self) -> (String, String) {
        self.permission.clone()
    }
    #[getter]
    fn resource_namespace(&self) -> &str {
        &self.resource_namespace
    }
    #[getter]
    fn audience(&self) -> &str {
        &self.audience
    }
    #[getter]
    fn budget(&self) -> Option<(String, u64)> {
        self.budget.clone()
    }
}

#[pyfunction]
fn application_action(
    profile_id: &str,
    profile_version: u16,
    media_type: &str,
    body: &[u8],
    capability: &str,
    resource: &str,
    budget: Option<(String, u64)>,
    resource_namespace: &str,
    audience: &str,
) -> PyResult<PyApplicationAction> {
    let canonical = CanonicalAction::new(
        ProfileRef::new(
            ProfileId::parse(profile_id).map_err(value_error)?,
            profile_version,
        )
        .map_err(value_error)?,
        MediaType::parse(media_type).map_err(value_error)?,
        body.to_vec(),
        Permission::new(
            CapabilityId::parse(capability).map_err(value_error)?,
            ResourceId::parse(resource).map_err(value_error)?,
        ),
        budget
            .map(|(algebra, value)| {
                Ok::<BudgetCeiling, PyErr>(BudgetCeiling::new(
                    BudgetAlgebraId::parse(&algebra).map_err(value_error)?,
                    value,
                ))
            })
            .transpose()?,
    )
    .map_err(value_error)?;
    Ok(PyApplicationAction {
        canonical,
        resource_namespace: ResourceId::parse(resource_namespace).map_err(value_error)?,
        audience: Audience::parse(audience).map_err(value_error)?,
    })
}

#[pyfunction]
fn application_action_commitment_v1<'py>(
    py: Python<'py>,
    action: PyRef<'_, PyApplicationAction>,
) -> PyResult<Bound<'py, PyBytes>> {
    Ok(PyBytes::new(py, &application_action_commitment(&action)?))
}

#[pyfunction]
fn commit_application_plan(
    py: Python<'_>,
    actions: Vec<Py<PyApplicationAction>>,
) -> PyResult<PyNativeApplicationPlan> {
    if actions.is_empty() || actions.len() > 256 {
        return Err(PyValueError::new_err(
            "application plan action count is outside native limits",
        ));
    }
    let actions = actions
        .iter()
        .map(|value| value.borrow(py).clone())
        .collect::<Vec<_>>();
    compatible(&actions)?;
    let members = actions
        .iter()
        .map(plan_member)
        .collect::<PyResult<Vec<_>>>()?;
    let borrowed = members.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let first = actions.first().expect("non-empty");
    let commitment = ProfilePlanCommitment::commit(
        first.canonical.profile().id().as_str(),
        first.canonical.profile().version(),
        &borrowed,
    )
    .map_err(value_error)?;
    Ok(PyNativeApplicationPlan {
        commitment: *commitment.plan().as_bytes(),
        members: commitment
            .members()
            .iter()
            .map(|value| *value.as_bytes())
            .collect(),
    })
}

#[pyfunction]
fn prepare_application_action(
    action: PyRef<'_, PyApplicationAction>,
    actor: PyRef<'_, PyPrincipal>,
    terminal_grant: PyRef<'_, PySignedObject>,
    challenge: &[u8],
    evaluation_time: u64,
) -> PyResult<PyApplicationActionPreparation> {
    let SignedObject::Grant(grant) = &terminal_grant.inner else {
        return Err(PyTypeError::new_err(
            "terminal grant must be a signed grant",
        ));
    };
    let challenge: [u8; 32] = challenge
        .try_into()
        .map_err(|_| PyValueError::new_err("challenge must contain 32 bytes"))?;
    let prepared = prepare_profile_action(
        action.canonical.clone(),
        action.audience.clone(),
        actor.inner.clone(),
        grant,
        challenge,
        evaluation_time,
    )
    .map_err(value_error)?;
    let (canonical, envelope) = prepared.into_parts();
    Ok(PyApplicationActionPreparation {
        action: PyApplicationAction {
            canonical,
            resource_namespace: action.resource_namespace.clone(),
            audience: action.audience.clone(),
        },
        envelope,
    })
}

#[pyfunction]
fn authorize_application(
    py: Python<'_>,
    prepared: PyRef<'_, PyApplicationActionPreparation>,
    signed_action: PyRef<'_, PySignedObject>,
    grants: Vec<Py<PySignedObject>>,
    grant_evidence: Vec<Vec<(String, String, Vec<u8>)>>,
    action_evidence: Vec<(String, String, Vec<u8>)>,
    context: PyRef<'_, PyTrustedContext>,
) -> PyResult<(NativeVerificationResult, Option<PyApplicationCommand>)> {
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
        .finish(action, &prepared.action.canonical, &context.inner)
        .map_err(value_error)?;
    let proof = auths_codec::encode_bundle(artifacts.proof()).map_err(value_error)?;
    let canonical =
        auths_codec::encode_canonical_action(&prepared.action.canonical).map_err(value_error)?;
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
        .map(|verified| {
            if verified.canonical_action() != &prepared.action.canonical {
                return Err(PyValueError::new_err(
                    "verified application action changed meaning",
                ));
            }
            Ok(PyApplicationCommand {
                action: Some(prepared.action.clone()),
                authority_commitment,
                context_commitment,
            })
        })
        .transpose()?;
    Ok((native_result(py, sealed)?, command))
}

#[pyfunction]
fn seal_application_plan_command(
    py: Python<'_>,
    commands: Vec<Py<PyApplicationCommand>>,
    expected_profile_id: &str,
    expected_profile_version: u16,
    expected_commitment: &[u8],
) -> PyResult<PyApplicationPlanCommand> {
    if commands.is_empty() || commands.len() > 256 {
        return Err(PyValueError::new_err(
            "application plan command count is outside native limits",
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
            "application plan contains duplicate command handles",
        ));
    }
    let actions = commands
        .iter()
        .map(|command| {
            let command = command.borrow(py);
            let action = command.action()?;
            if action.canonical.profile().id().as_str() != expected_profile_id
                || action.canonical.profile().version() != expected_profile_version
            {
                return Err(PyTypeError::new_err(
                    "application command belongs to another profile",
                ));
            }
            Ok(action.clone())
        })
        .collect::<PyResult<Vec<_>>>()?;
    let members = actions
        .iter()
        .map(plan_member)
        .collect::<PyResult<Vec<_>>>()?;
    let borrowed = members.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let commitment =
        ProfilePlanCommitment::commit(expected_profile_id, expected_profile_version, &borrowed)
            .map_err(value_error)?;
    if commitment.plan().as_bytes() != &expected {
        return Err(PyValueError::new_err(
            "verified commands do not match the application plan",
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
    for command in &commands {
        command.borrow_mut(py).action.take();
    }
    Ok(PyApplicationPlanCommand {
        actions: Some(actions),
        commitment: expected,
        receipt_bindings,
    })
}

#[pyfunction]
fn consume_application_command(
    mut command: PyRefMut<'_, PyApplicationCommand>,
    expected_profile_id: &str,
    expected_profile_version: u16,
) -> PyResult<PyApplicationGatewayCall> {
    let action = command.action()?;
    matching_profile(action, expected_profile_id, expected_profile_version)?;
    let action = command
        .action
        .take()
        .ok_or_else(|| PyRuntimeError::new_err("application command has already been consumed"))?;
    Ok(gateway_call(action))
}

#[pyfunction]
fn consume_application_plan_command(
    mut command: PyRefMut<'_, PyApplicationPlanCommand>,
    expected_profile_id: &str,
    expected_profile_version: u16,
) -> PyResult<Vec<PyApplicationGatewayCall>> {
    for action in command.actions()? {
        matching_profile(action, expected_profile_id, expected_profile_version)?;
    }
    command
        .actions
        .take()
        .ok_or_else(|| {
            PyRuntimeError::new_err("application plan command has already been consumed")
        })?
        .into_iter()
        .map(|value| Ok(gateway_call(value)))
        .collect()
}

fn compatible(actions: &[PyApplicationAction]) -> PyResult<()> {
    let first = actions
        .first()
        .ok_or_else(|| PyValueError::new_err("application plan is empty"))?;
    if actions.iter().any(|action| {
        action.canonical.profile() != first.canonical.profile()
            || action.resource_namespace != first.resource_namespace
            || action.audience != first.audience
            || action
                .canonical
                .requested_budget()
                .map(|value| value.algebra())
                != first
                    .canonical
                    .requested_budget()
                    .map(|value| value.algebra())
    }) {
        return Err(PyValueError::new_err(
            "application plan members have incompatible authority",
        ));
    }
    actions.iter().try_fold(0_u64, |total, action| {
        total
            .checked_add(
                action
                    .canonical
                    .requested_budget()
                    .map_or(0, BudgetCeiling::value),
            )
            .ok_or_else(|| {
                PyValueError::new_err("application plan aggregate budget exceeds bounds")
            })
    })?;
    Ok(())
}

fn matching_profile(action: &PyApplicationAction, id: &str, version: u16) -> PyResult<()> {
    if action.canonical.profile().id().as_str() != id
        || action.canonical.profile().version() != version
    {
        return Err(PyTypeError::new_err(
            "application command belongs to another profile",
        ));
    }
    Ok(())
}

fn plan_member(action: &PyApplicationAction) -> PyResult<Vec<u8>> {
    ProfilePlanMember::encode(
        &action.canonical,
        &action.resource_namespace,
        &action.audience,
    )
    .map_err(value_error)
}

fn application_action_commitment(action: &PyApplicationAction) -> PyResult<[u8; 32]> {
    let encoded = auths_codec::encode_canonical_action(&action.canonical).map_err(value_error)?;
    Ok(
        *auths_codec::domain_commitment("auths.canonical-action.v1", &encoded)
            .map_err(value_error)?
            .as_bytes(),
    )
}

fn gateway_call(action: PyApplicationAction) -> PyApplicationGatewayCall {
    PyApplicationGatewayCall {
        profile_id: action.canonical.profile().id().as_str().to_owned(),
        profile_version: action.canonical.profile().version(),
        media_type: action.canonical.media_type().as_str().to_owned(),
        body: action.canonical.body().to_vec(),
        permission: (
            action
                .canonical
                .permission()
                .capability()
                .as_str()
                .to_owned(),
            action.canonical.permission().resource().as_str().to_owned(),
        ),
        resource_namespace: action.resource_namespace.as_str().to_owned(),
        audience: action.audience.as_str().to_owned(),
        budget: action
            .canonical
            .requested_budget()
            .map(|value| (value.algebra().as_str().to_owned(), value.value())),
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
    PyTypeError::new_err("ApplicationCommand is a non-copyable native capability")
}

fn plan_command_error() -> PyErr {
    PyTypeError::new_err("ApplicationPlanCommand is a non-copyable native capability")
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyApplicationAction>()?;
    module.add_class::<PyApplicationActionPreparation>()?;
    module.add_class::<PyApplicationCommand>()?;
    module.add_class::<PyApplicationPlanCommand>()?;
    module.add_class::<PyNativeApplicationPlan>()?;
    module.add_class::<PyApplicationGatewayCall>()?;
    module.add_function(wrap_pyfunction!(application_action, module)?)?;
    module.add_function(wrap_pyfunction!(application_action_commitment_v1, module)?)?;
    module.add_function(wrap_pyfunction!(commit_application_plan, module)?)?;
    module.add_function(wrap_pyfunction!(prepare_application_action, module)?)?;
    module.add_function(wrap_pyfunction!(authorize_application, module)?)?;
    module.add_function(wrap_pyfunction!(seal_application_plan_command, module)?)?;
    module.add_function(wrap_pyfunction!(consume_application_command, module)?)?;
    module.add_function(wrap_pyfunction!(consume_application_plan_command, module)?)?;
    Ok(())
}
