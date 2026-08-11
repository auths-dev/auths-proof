#![allow(
    clippy::needless_pass_by_value,
    clippy::too_many_arguments,
    clippy::unused_self
)]

use crate::authoring::{
    PyGrantPlan, PyPrincipal, PySignedObject, PyTrustedContext, PyUnsignedObject, SignedObject,
    UnsignedObject, configuration, signing_descriptor, value_error,
};
use auths_author::{
    ApprovalPolicyCommitment, AuthorityDimension, ExternalSigningRequest, GrantRequest,
    PlanningError, plan_child_grant, prepare_action, prepare_grant, prepare_grant_status,
    prepare_principal_status,
};
use auths_custody::{ProviderSigningResponse, validate_provider_response};
use auths_model::{
    ActionConstraint, ActionEnvelope, AssurancePolicyId, Audience, AudienceSet, BodyDigestSet,
    BudgetAlgebraId, BudgetCeiling, Digest, FreshnessLimit, GrantStatement, GrantStatusStatement,
    Permission, PermissionSet, PrincipalId, PrincipalStatusStatement, ProfileId, ProfileRef,
    ResourceId, SignatureBytes, SignatureDescriptor, SignedGrant, StatusMethodId, StatusPolicy,
    Timestamp, ValidityWindow,
};
use pyo3::{
    create_exception,
    exceptions::{PyRuntimeError, PyValueError},
    prelude::*,
    types::PyBytes,
};
use subtle::ConstantTimeEq as _;

create_exception!(auths._native, NativeDelegationExpandedError, PyValueError);

const MAX_IDENTIFIER_BYTES: usize = 128;

#[derive(Clone)]
#[pyclass(
    name = "PrincipalDescriptor",
    frozen,
    module = "auths._native",
    skip_from_py_object
)]
pub struct PyPrincipalDescriptor {
    principal: PrincipalId,
    descriptor: SignatureDescriptor,
}

#[pymethods]
impl PyPrincipalDescriptor {
    #[new]
    fn new(
        principal: PyRef<'_, PyPrincipal>,
        principal_method: &str,
        verification_method: &str,
        suite: &str,
    ) -> PyResult<Self> {
        Ok(Self {
            principal: principal.inner.clone(),
            descriptor: signing_descriptor(principal_method, verification_method, suite)?,
        })
    }

    #[getter]
    fn principal(&self) -> PyPrincipal {
        PyPrincipal {
            inner: self.principal.clone(),
        }
    }

    #[getter]
    fn principal_method(&self) -> &str {
        self.descriptor.principal_method().as_str()
    }

    #[getter]
    fn verification_method(&self) -> &str {
        self.descriptor.verification_method().as_str()
    }

    #[getter]
    fn suite(&self) -> &str {
        self.descriptor.suite().as_str()
    }

    fn matches(&self, other: PyRef<'_, Self>) -> bool {
        self.principal == other.principal && self.descriptor == other.descriptor
    }

    fn __repr__(&self) -> String {
        format!(
            "PrincipalDescriptor(principal={:?}, principal_method={:?}, verification_method={:?}, suite={:?})",
            self.principal.as_str(),
            self.descriptor.principal_method().as_str(),
            self.descriptor.verification_method().as_str(),
            self.descriptor.suite().as_str()
        )
    }
}

#[derive(Clone)]
#[pyclass(
    name = "ApprovalPolicyReference",
    frozen,
    module = "auths._native",
    skip_from_py_object
)]
pub struct PyApprovalPolicyReference {
    policy_id: String,
    evaluator_version: String,
    configuration_digest: [u8; 32],
}

#[pymethods]
impl PyApprovalPolicyReference {
    #[new]
    fn new(
        policy_id: &str,
        evaluator_version: &str,
        configuration_digest: &[u8],
    ) -> PyResult<Self> {
        Ok(Self {
            policy_id: bounded_identifier(policy_id, "approval policy")?,
            evaluator_version: bounded_identifier(evaluator_version, "evaluator version")?,
            configuration_digest: array32(configuration_digest, "approval configuration")?,
        })
    }

    #[getter]
    fn policy_id(&self) -> &str {
        &self.policy_id
    }

    #[getter]
    fn evaluator_version(&self) -> &str {
        &self.evaluator_version
    }

    #[getter]
    fn configuration_digest<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.configuration_digest)
    }

    fn matches(&self, other: PyRef<'_, Self>) -> bool {
        policy_references_equal(self, &other)
    }

    fn __repr__(&self) -> String {
        format!(
            "ApprovalPolicyReference(policy_id={:?}, evaluator_version={:?})",
            self.policy_id, self.evaluator_version
        )
    }
}

#[pyfunction]
fn approval_policy_reference(
    policy_id: &str,
    evaluator_version: &str,
    mode: &str,
    max_uses: u32,
    expires_in_seconds: u32,
    requirements: Vec<String>,
) -> PyResult<PyApprovalPolicyReference> {
    let policy_id = bounded_identifier(policy_id, "approval policy")?;
    let evaluator_version = bounded_identifier(evaluator_version, "evaluator version")?;
    for requirement in &requirements {
        bounded_identifier(requirement, "approval requirement")?;
    }
    let borrowed: Vec<&str> = requirements.iter().map(String::as_str).collect();
    let digest = ApprovalPolicyCommitment::commit(
        bounded_identifier(mode, "approval mode")?.as_str(),
        max_uses,
        expires_in_seconds,
        &borrowed,
    )
    .map_err(value_error)?;
    Ok(PyApprovalPolicyReference {
        policy_id,
        evaluator_version,
        configuration_digest: *digest.as_bytes(),
    })
}

#[derive(Clone, Copy)]
enum AuthorityBinding {
    Root,
    Delegated,
}

#[pyclass(name = "GrantAuthority", frozen, module = "auths._native")]
pub struct PyGrantAuthority {
    grant: SignedGrant,
    binding: AuthorityBinding,
}

#[pymethods]
impl PyGrantAuthority {
    #[getter]
    fn binding(&self) -> &'static str {
        match self.binding {
            AuthorityBinding::Root => "root",
            AuthorityBinding::Delegated => "delegated",
        }
    }

    #[getter]
    fn grant_id<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let id = auths_codec::grant_id(self.grant.statement()).map_err(value_error)?;
        Ok(PyBytes::new(py, id.as_bytes()))
    }

    #[getter]
    fn issuer(&self) -> PyPrincipal {
        PyPrincipal {
            inner: self.grant.statement().issuer().clone(),
        }
    }

    #[getter]
    fn subject(&self) -> PyPrincipal {
        PyPrincipal {
            inner: self.grant.statement().subject().clone(),
        }
    }

    #[getter]
    fn profile(&self) -> (String, u16) {
        (
            self.grant.statement().profile().id().as_str().to_owned(),
            self.grant.statement().profile().version(),
        )
    }

    #[getter]
    fn permissions(&self) -> Vec<(String, String)> {
        self.grant
            .statement()
            .permissions()
            .as_slice()
            .iter()
            .map(|permission| {
                (
                    permission.capability().as_str().to_owned(),
                    permission.resource().as_str().to_owned(),
                )
            })
            .collect()
    }

    #[getter]
    fn validity(&self) -> (u64, u64) {
        let validity = self.grant.statement().validity();
        (validity.not_before().get(), validity.expires_at().get())
    }

    #[getter]
    fn audiences(&self) -> Vec<String> {
        self.grant
            .statement()
            .audiences()
            .as_slice()
            .iter()
            .map(|audience| audience.as_str().to_owned())
            .collect()
    }

    #[getter]
    fn action_constraint(&self) -> (&'static str, usize) {
        match self.grant.statement().action_constraint() {
            ActionConstraint::AnyBody => ("any-body", 0),
            ActionConstraint::ExactBodyDigest(_) => ("exact-body", 1),
            ActionConstraint::AllowedBodyDigests(digests) => {
                ("allowed-bodies", digests.as_slice().len())
            }
        }
    }

    #[getter]
    fn budget(&self) -> Option<(String, u64)> {
        self.grant
            .statement()
            .budget_ceiling()
            .map(|budget| (budget.algebra().as_str().to_owned(), budget.value()))
    }

    #[getter]
    fn remaining_depth(&self) -> u16 {
        self.grant.statement().remaining_depth()
    }

    #[getter]
    fn parent_id<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.grant
            .statement()
            .parent()
            .map(|parent| PyBytes::new(py, parent.as_bytes()))
    }

    #[getter]
    fn status(&self) -> (&'static str, Option<String>, Option<u64>) {
        match self.grant.statement().status_policy() {
            StatusPolicy::ExpiryOnly => ("expiry-only", None, None),
            StatusPolicy::SnapshotRequired { method, max_age } => (
                "snapshot-required",
                Some(method.as_str().to_owned()),
                Some(max_age.get()),
            ),
        }
    }

    #[getter]
    fn assurance_floor(&self) -> &str {
        self.grant.statement().assurance_floor().as_str()
    }

    #[getter]
    fn critical_extensions(&self) -> Vec<String> {
        self.grant
            .statement()
            .extensions()
            .as_slice()
            .iter()
            .map(|extension| extension.id().as_str().to_owned())
            .collect()
    }

    #[getter]
    fn signature(&self) -> (String, String, String) {
        let descriptor = self.grant.signature().descriptor();
        (
            descriptor.principal_method().as_str().to_owned(),
            descriptor.verification_method().as_str().to_owned(),
            descriptor.suite().as_str().to_owned(),
        )
    }

    fn __repr__(&self) -> String {
        format!(
            "GrantAuthority(binding={:?}, issuer={:?}, subject={:?})",
            self.binding(),
            self.grant.statement().issuer().as_str(),
            self.grant.statement().subject().as_str()
        )
    }
}

#[pyfunction]
fn validate_trusted_authority(
    context: PyRef<'_, PyTrustedContext>,
    root: PyRef<'_, PyPrincipal>,
) -> PyResult<()> {
    if context.inner.configuration().as_bytes() != &configuration()? {
        return Err(PyValueError::new_err(
            "trusted authority requires a different verifier configuration",
        ));
    }
    if !context
        .inner
        .trust_anchors()
        .iter()
        .any(|anchor| anchor.principal() == &root.inner)
    {
        return Err(PyValueError::new_err(
            "trusted context does not contain the configured root",
        ));
    }
    Ok(())
}

#[pyfunction]
fn validate_root_authority(
    signed: PyRef<'_, PySignedObject>,
    root: PyRef<'_, PyPrincipal>,
    subject: PyRef<'_, PyPrincipalDescriptor>,
    profile_id: &str,
    profile_version: u16,
) -> PyResult<PyGrantAuthority> {
    let SignedObject::Grant(grant) = &signed.inner else {
        return Err(PyValueError::new_err(
            "root authority must be a signed grant",
        ));
    };
    let profile = ProfileRef::new(
        ProfileId::parse(profile_id).map_err(value_error)?,
        profile_version,
    )
    .map_err(value_error)?;
    let statement = grant.statement();
    if statement.parent().is_some()
        || statement.issuer() != &root.inner
        || statement.subject() != &subject.principal
        || statement.profile() != &profile
    {
        return Err(PyValueError::new_err(
            "signed grant does not bind the trusted root, agent, and profile",
        ));
    }
    Ok(PyGrantAuthority {
        grant: grant.clone(),
        binding: AuthorityBinding::Root,
    })
}

#[pyfunction]
fn bind_delegated_authority(
    signed: PyRef<'_, PySignedObject>,
    parent: PyRef<'_, PyGrantAuthority>,
    subject: PyRef<'_, PyPrincipalDescriptor>,
    issuer: PyRef<'_, PyPrincipalDescriptor>,
    profile_id: &str,
    profile_version: u16,
) -> PyResult<PyGrantAuthority> {
    let SignedObject::Grant(grant) = &signed.inner else {
        return Err(PyValueError::new_err(
            "delegated authority must be a signed grant",
        ));
    };
    let profile = ProfileRef::new(
        ProfileId::parse(profile_id).map_err(value_error)?,
        profile_version,
    )
    .map_err(value_error)?;
    let expected_parent = auths_codec::grant_id(parent.grant.statement()).map_err(value_error)?;
    let statement = grant.statement();
    if statement.issuer() != &issuer.principal
        || statement.subject() != &subject.principal
        || statement.profile() != &profile
        || statement.parent() != Some(expected_parent)
        || grant.signature().descriptor() != &issuer.descriptor
    {
        return Err(PyValueError::new_err(
            "signed child grant does not match its native delegation plan",
        ));
    }
    Ok(PyGrantAuthority {
        grant: grant.clone(),
        binding: AuthorityBinding::Delegated,
    })
}

#[pyfunction]
fn plan_child_fields(
    parent: PyRef<'_, PyGrantAuthority>,
    subject: PyRef<'_, PyPrincipalDescriptor>,
    permissions: Vec<(String, String)>,
    not_before: u64,
    expires_at: u64,
    audiences: Vec<String>,
    action_mode: &str,
    action_digests: Vec<Vec<u8>>,
    budget_mode: &str,
    budget: Option<(String, u64)>,
    remaining_depth: u16,
    status_mode: &str,
    status: Option<(String, u64)>,
    assurance_floor: Option<String>,
) -> PyResult<PyGrantPlan> {
    let statement = parent.grant.statement();
    let permissions = PermissionSet::new(
        permissions
            .into_iter()
            .map(|(capability, resource)| {
                Ok(Permission::new(
                    auths_model::CapabilityId::parse(&capability).map_err(value_error)?,
                    ResourceId::parse(&resource).map_err(value_error)?,
                ))
            })
            .collect::<PyResult<Vec<_>>>()?,
    )
    .map_err(value_error)?;
    let audiences = AudienceSet::new(
        audiences
            .into_iter()
            .map(|audience| Audience::parse(&audience).map_err(value_error))
            .collect::<PyResult<Vec<_>>>()?,
    )
    .map_err(value_error)?;
    let action_constraint = match action_mode {
        "inherit" if action_digests.is_empty() => statement.action_constraint().clone(),
        "any-body" if action_digests.is_empty() => ActionConstraint::AnyBody,
        "exact-body" if action_digests.len() == 1 => ActionConstraint::ExactBodyDigest(
            Digest::new(array32(&action_digests[0], "exact body digest")?),
        ),
        "allowed-bodies" if !action_digests.is_empty() => {
            let values = action_digests
                .iter()
                .map(|digest| array32(digest, "allowed body digest").map(Digest::new))
                .collect::<PyResult<Vec<_>>>()?;
            ActionConstraint::AllowedBodyDigests(BodyDigestSet::new(values).map_err(value_error)?)
        }
        _ => {
            return Err(PyValueError::new_err("invalid delegated action constraint"));
        }
    };
    let budget_ceiling = match (budget_mode, budget) {
        ("inherit", None) => statement.budget_ceiling().cloned(),
        ("none", None) => None,
        ("ceiling", Some((algebra, value))) => Some(BudgetCeiling::new(
            BudgetAlgebraId::parse(&algebra).map_err(value_error)?,
            value,
        )),
        _ => return Err(PyValueError::new_err("invalid delegated budget")),
    };
    let status_policy = match (status_mode, status) {
        ("inherit", None) => statement.status_policy().clone(),
        ("expiry-only", None) => StatusPolicy::ExpiryOnly,
        ("snapshot-required", Some((method, maximum_age))) => StatusPolicy::SnapshotRequired {
            method: StatusMethodId::parse(&method).map_err(value_error)?,
            max_age: FreshnessLimit::new(maximum_age).map_err(value_error)?,
        },
        _ => return Err(PyValueError::new_err("invalid delegated status policy")),
    };
    let assurance_floor = assurance_floor.map_or_else(
        || Ok(statement.assurance_floor().clone()),
        |value| AssurancePolicyId::parse(&value).map_err(value_error),
    )?;
    let request = GrantRequest::new(
        subject.principal.clone(),
        statement.profile().clone(),
        permissions,
        ValidityWindow::new(Timestamp::new(not_before), Timestamp::new(expires_at))
            .map_err(value_error)?,
        audiences,
        action_constraint,
        budget_ceiling,
        remaining_depth,
        status_policy,
        assurance_floor,
        statement.extensions().clone(),
    );
    let inner = plan_child_grant(statement, request).map_err(planning_error)?;
    Ok(PyGrantPlan { inner })
}

enum WorkflowSigningRequest {
    Grant(ExternalSigningRequest<GrantStatement>),
    Action(ExternalSigningRequest<ActionEnvelope>),
    PrincipalStatus(ExternalSigningRequest<PrincipalStatusStatement>),
    GrantStatus(ExternalSigningRequest<GrantStatusStatement>),
}

impl WorkflowSigningRequest {
    fn request_id(&self) -> String {
        match self {
            Self::Grant(value) => value.request_id(),
            Self::Action(value) => value.request_id(),
            Self::PrincipalStatus(value) => value.request_id(),
            Self::GrantStatus(value) => value.request_id(),
        }
    }

    fn object_kind(&self) -> &'static str {
        match self {
            Self::Grant(value) => value.object_id().label(),
            Self::Action(value) => value.object_id().label(),
            Self::PrincipalStatus(value) => value.object_id().label(),
            Self::GrantStatus(value) => value.object_id().label(),
        }
    }

    fn object_id(&self) -> [u8; 32] {
        match self {
            Self::Grant(value) => *value.object_id().as_bytes(),
            Self::Action(value) => *value.object_id().as_bytes(),
            Self::PrincipalStatus(value) => *value.object_id().as_bytes(),
            Self::GrantStatus(value) => *value.object_id().as_bytes(),
        }
    }

    fn signing_preimage(&self) -> &[u8] {
        match self {
            Self::Grant(value) => value.signing_preimage(),
            Self::Action(value) => value.signing_preimage(),
            Self::PrincipalStatus(value) => value.signing_preimage(),
            Self::GrantStatus(value) => value.signing_preimage(),
        }
    }

    fn transaction_digest(&self) -> [u8; 32] {
        match self {
            Self::Grant(value) => *value.transaction_digest().as_bytes(),
            Self::Action(value) => *value.transaction_digest().as_bytes(),
            Self::PrincipalStatus(value) => *value.transaction_digest().as_bytes(),
            Self::GrantStatus(value) => *value.transaction_digest().as_bytes(),
        }
    }

    fn complete_response(
        self,
        expected_principal: &PrincipalId,
        response: ProviderSigningResponse,
    ) -> PyResult<SignedObject> {
        match self {
            Self::Grant(value) => {
                let (signature, _) =
                    validate_provider_response(&value, expected_principal, response)
                        .map_err(value_error)?
                        .into_parts();
                Ok(SignedObject::Grant(value.complete(signature)))
            }
            Self::Action(value) => {
                let (signature, _) =
                    validate_provider_response(&value, expected_principal, response)
                        .map_err(value_error)?
                        .into_parts();
                Ok(SignedObject::Action(value.complete(signature)))
            }
            Self::PrincipalStatus(value) => {
                let (signature, _) =
                    validate_provider_response(&value, expected_principal, response)
                        .map_err(value_error)?
                        .into_parts();
                Ok(SignedObject::PrincipalStatus(value.complete(signature)))
            }
            Self::GrantStatus(value) => {
                let (signature, _) =
                    validate_provider_response(&value, expected_principal, response)
                        .map_err(value_error)?
                        .into_parts();
                Ok(SignedObject::GrantStatus(value.complete(signature)))
            }
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TransactionPhase {
    AwaitingApproval,
    AwaitingSignature,
    Terminal,
}

#[pyclass(name = "SigningTransaction", module = "auths._native")]
pub struct PySigningTransaction {
    request: Option<WorkflowSigningRequest>,
    principal: PyPrincipalDescriptor,
    policy: PyApprovalPolicyReference,
    expires_at: u64,
    phase: TransactionPhase,
}

#[pymethods]
impl PySigningTransaction {
    #[getter]
    fn object_kind(&self) -> PyResult<&'static str> {
        Ok(self.request()?.object_kind())
    }

    #[getter]
    fn request_id(&self) -> PyResult<String> {
        Ok(self.request()?.request_id())
    }

    #[getter]
    fn object_id<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(py, &self.request()?.object_id()))
    }

    #[getter]
    fn signing_preimage<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(py, self.request()?.signing_preimage()))
    }

    #[getter]
    fn transaction_digest<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(py, &self.request()?.transaction_digest()))
    }

    #[getter]
    fn principal(&self) -> PyPrincipalDescriptor {
        self.principal.clone()
    }

    #[getter]
    fn policy(&self) -> PyApprovalPolicyReference {
        self.policy.clone()
    }

    #[getter]
    fn expires_at(&self) -> u64 {
        self.expires_at
    }

    #[getter]
    fn phase(&self) -> &'static str {
        match self.phase {
            TransactionPhase::AwaitingApproval => "awaiting-approval",
            TransactionPhase::AwaitingSignature => "awaiting-signature",
            TransactionPhase::Terminal => "terminal",
        }
    }

    fn accept_approval(
        &mut self,
        request_id: &str,
        transaction_digest: &[u8],
        policy: PyRef<'_, PyApprovalPolicyReference>,
        decision: &str,
        now: u64,
    ) -> PyResult<bool> {
        if self.phase != TransactionPhase::AwaitingApproval {
            return Err(PyRuntimeError::new_err(
                "signing transaction is not awaiting approval",
            ));
        }
        let request = self
            .request
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("signing transaction is terminal"))?;
        self.phase = TransactionPhase::Terminal;
        if now > self.expires_at {
            return Err(PyRuntimeError::new_err("signing transaction expired"));
        }
        let response_digest = array32(transaction_digest, "approval transaction digest")?;
        if request.request_id() != request_id
            || !constant_time_equal(&request.transaction_digest(), &response_digest)
            || !policy_references_equal(&self.policy, &policy)
        {
            return Err(PyValueError::new_err(
                "approval response is not bound to the exact transaction",
            ));
        }
        match decision {
            "approved" => {
                self.request = Some(request);
                self.phase = TransactionPhase::AwaitingSignature;
                Ok(true)
            }
            "rejected" => Ok(false),
            _ => Err(PyValueError::new_err("invalid approval decision")),
        }
    }

    fn complete_response(
        &mut self,
        request_id: &str,
        principal: PyRef<'_, PyPrincipalDescriptor>,
        transaction_digest: &[u8],
        signature: &[u8],
        now: u64,
    ) -> PyResult<PySignedObject> {
        if self.phase != TransactionPhase::AwaitingSignature {
            return Err(PyRuntimeError::new_err(
                "signing transaction is not awaiting a signature",
            ));
        }
        let request = self
            .request
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("signing transaction is terminal"))?;
        self.phase = TransactionPhase::Terminal;
        if now > self.expires_at {
            return Err(PyRuntimeError::new_err("signing transaction expired"));
        }
        let signature = SignatureBytes::new(signature.to_vec()).map_err(value_error)?;
        let response = ProviderSigningResponse::new(
            request_id.to_owned(),
            principal.principal.clone(),
            principal.descriptor.clone(),
            signature,
            Vec::new(),
            array32(transaction_digest, "signer transaction digest")?,
        );
        Ok(PySignedObject {
            inner: request.complete_response(&self.principal.principal, response)?,
        })
    }

    fn discard(&mut self) {
        self.request = None;
        self.phase = TransactionPhase::Terminal;
    }

    fn __repr__(&self) -> String {
        format!("SigningTransaction(phase={:?})", self.phase())
    }
}

impl PySigningTransaction {
    fn request(&self) -> PyResult<&WorkflowSigningRequest> {
        self.request
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("signing transaction is terminal"))
    }
}

#[pyfunction]
fn prepare_signing_transaction(
    unsigned: PyRef<'_, PyUnsignedObject>,
    principal: PyRef<'_, PyPrincipalDescriptor>,
    policy: PyRef<'_, PyApprovalPolicyReference>,
    expires_at: u64,
) -> PyResult<PySigningTransaction> {
    let descriptor = principal.descriptor.clone();
    let request = match &unsigned.inner {
        UnsignedObject::Grant(value) => WorkflowSigningRequest::Grant(
            prepare_grant(value.clone(), descriptor).map_err(value_error)?,
        ),
        UnsignedObject::Action(value) => WorkflowSigningRequest::Action(
            prepare_action(value.clone(), descriptor).map_err(value_error)?,
        ),
        UnsignedObject::PrincipalStatus(value) => WorkflowSigningRequest::PrincipalStatus(
            prepare_principal_status(value.clone(), descriptor).map_err(value_error)?,
        ),
        UnsignedObject::GrantStatus(value) => WorkflowSigningRequest::GrantStatus(
            prepare_grant_status(value.clone(), descriptor).map_err(value_error)?,
        ),
    };
    Ok(PySigningTransaction {
        request: Some(request),
        principal: principal.clone(),
        policy: policy.clone(),
        expires_at,
        phase: TransactionPhase::AwaitingApproval,
    })
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add(
        "NativeDelegationExpandedError",
        module.py().get_type::<NativeDelegationExpandedError>(),
    )?;
    module.add_class::<PyPrincipalDescriptor>()?;
    module.add_class::<PyApprovalPolicyReference>()?;
    module.add_class::<PyGrantAuthority>()?;
    module.add_class::<PySigningTransaction>()?;
    module.add_function(wrap_pyfunction!(approval_policy_reference, module)?)?;
    module.add_function(wrap_pyfunction!(validate_trusted_authority, module)?)?;
    module.add_function(wrap_pyfunction!(validate_root_authority, module)?)?;
    module.add_function(wrap_pyfunction!(bind_delegated_authority, module)?)?;
    module.add_function(wrap_pyfunction!(plan_child_fields, module)?)?;
    module.add_function(wrap_pyfunction!(prepare_signing_transaction, module)?)?;
    Ok(())
}

fn bounded_identifier(value: &str, label: &str) -> PyResult<String> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(PyValueError::new_err(format!("invalid {label}")));
    }
    Ok(value.to_owned())
}

fn policy_references_equal(
    left: &PyApprovalPolicyReference,
    right: &PyApprovalPolicyReference,
) -> bool {
    left.policy_id == right.policy_id
        && left.evaluator_version == right.evaluator_version
        && constant_time_equal(&left.configuration_digest, &right.configuration_digest)
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    bool::from(left.ct_eq(right))
}

fn planning_error(error: PlanningError) -> PyErr {
    match error {
        PlanningError::Expanded(dimension) => {
            PyErr::new::<NativeDelegationExpandedError, _>(authority_dimension(dimension))
        }
        other => value_error(other),
    }
}

const fn authority_dimension(value: AuthorityDimension) -> &'static str {
    match value {
        AuthorityDimension::Profile => "profile",
        AuthorityDimension::Permissions => "permissions",
        AuthorityDimension::Validity => "validity",
        AuthorityDimension::Audiences => "audiences",
        AuthorityDimension::ActionConstraint => "action-constraint",
        AuthorityDimension::Budget => "budget",
        AuthorityDimension::DelegationDepth => "delegation-depth",
        AuthorityDimension::Status => "status",
        AuthorityDimension::Assurance => "assurance",
        AuthorityDimension::Extensions => "critical-extensions",
    }
}

fn array32(value: &[u8], label: &str) -> PyResult<[u8; 32]> {
    value
        .try_into()
        .map_err(|_| PyValueError::new_err(format!("{label} must contain 32 bytes")))
}
