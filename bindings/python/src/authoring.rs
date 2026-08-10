#![allow(
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_excessive_bools,
    clippy::unused_self
)]

use auths_author::{
    AuthorityDiff, ExternalSigningRequest, GrantPlan, GrantRequest, OverGrantingWarning,
    PlanBuilder, plan_child_grant, prepare_action, prepare_grant, prepare_grant_status,
    prepare_principal_status,
};
use auths_model::{
    ActionConstraint, ActionEnvelope, AssuranceClaimId, AssurancePolicy, AssurancePolicyId,
    AssuranceQuantifier, AssuranceRequirement, Audience, AudienceSet, AuthorizationPlan,
    BudgetAlgebraId, BudgetCeiling, CanonicalAction, Challenge, ChannelBindingId,
    CompositionRequirement, CriticalExtension, CriticalExtensions, Digest, EvidenceId,
    FreshnessLimit, GrantId, GrantState, GrantStatusSnapshot, GrantStatusStatement,
    ParticipantRole, Permission, PermissionSet, PrincipalId, PrincipalMethodId, PrincipalState,
    PrincipalStatusSnapshot, PrincipalStatusStatement, ProfileId, ProfileRef, ProofRef, PurposeId,
    ResourceId, SignatureBytes, SignatureDescriptor, SignatureSuiteId, SignedAction, SignedGrant,
    SignedGrantStatus, SignedPrincipalStatus, StatusMethodId, StatusPolicy, StatusSnapshotId,
    StatusTrustRule, Timestamp, TrustAnchor, TrustAnchorId, ValidityWindow, VerificationMethod,
    VerifierConfigurationId, VerifierContext, VerifierLimits,
};
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_profile_api::ActionProfile;
use auths_profile_mcp::{McpProfile, McpToolCall};
use pyo3::{
    exceptions::{PyRuntimeError, PyTypeError, PyValueError},
    prelude::*,
    types::PyBytes,
};
use serde_json::Value;

#[derive(Clone)]
#[pyclass(
    name = "Principal",
    frozen,
    module = "auths._native",
    skip_from_py_object
)]
pub struct PyPrincipal {
    pub(crate) inner: PrincipalId,
}

#[pymethods]
impl PyPrincipal {
    #[new]
    fn new(value: &str) -> PyResult<Self> {
        Ok(Self {
            inner: PrincipalId::parse(value).map_err(value_error)?,
        })
    }

    #[getter]
    fn value(&self) -> &str {
        self.inner.as_str()
    }

    fn __str__(&self) -> &str {
        self.inner.as_str()
    }

    fn __repr__(&self) -> String {
        format!("Principal({:?})", self.inner.as_str())
    }
}

#[derive(Clone)]
pub(crate) enum UnsignedObject {
    Grant(auths_model::GrantStatement),
    Action(ActionEnvelope),
    PrincipalStatus(PrincipalStatusStatement),
    GrantStatus(GrantStatusStatement),
}

impl UnsignedObject {
    const fn kind(&self) -> &'static str {
        match self {
            Self::Grant(_) => "grant",
            Self::Action(_) => "action",
            Self::PrincipalStatus(_) => "principal-status",
            Self::GrantStatus(_) => "grant-status",
        }
    }
}

#[pyclass(name = "UnsignedObject", frozen, module = "auths._native")]
pub struct PyUnsignedObject {
    pub(crate) inner: UnsignedObject,
}

#[pymethods]
impl PyUnsignedObject {
    #[getter]
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }

    fn __repr__(&self) -> String {
        format!("UnsignedObject(kind={:?})", self.inner.kind())
    }
}

#[derive(Clone)]
pub(crate) enum SignedObject {
    Grant(SignedGrant),
    Action(SignedAction),
    PrincipalStatus(SignedPrincipalStatus),
    GrantStatus(SignedGrantStatus),
}

impl SignedObject {
    const fn kind(&self) -> &'static str {
        match self {
            Self::Grant(_) => "grant",
            Self::Action(_) => "action",
            Self::PrincipalStatus(_) => "principal-status",
            Self::GrantStatus(_) => "grant-status",
        }
    }
}

#[pyclass(name = "SignedObject", frozen, module = "auths._native")]
pub struct PySignedObject {
    pub(crate) inner: SignedObject,
}

#[pymethods]
impl PySignedObject {
    #[getter]
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }

    fn __repr__(&self) -> String {
        format!("SignedObject(kind={:?})", self.inner.kind())
    }
}

#[derive(Clone)]
struct ScopeParts {
    subject: PrincipalId,
    profile: ProfileRef,
    permissions: PermissionSet,
    validity: ValidityWindow,
    audiences: AudienceSet,
    action_constraint: ActionConstraint,
    budget_ceiling: Option<BudgetCeiling>,
    remaining_depth: u16,
    status_policy: StatusPolicy,
    assurance_floor: AssurancePolicyId,
    extensions: CriticalExtensions,
}

impl ScopeParts {
    fn request(&self) -> GrantRequest {
        GrantRequest::new(
            self.subject.clone(),
            self.profile.clone(),
            self.permissions.clone(),
            self.validity,
            self.audiences.clone(),
            self.action_constraint.clone(),
            self.budget_ceiling.clone(),
            self.remaining_depth,
            self.status_policy.clone(),
            self.assurance_floor.clone(),
            self.extensions.clone(),
        )
    }

    fn statement(&self, issuer: PrincipalId) -> auths_model::GrantStatement {
        auths_model::GrantStatement::new(
            issuer,
            self.subject.clone(),
            self.profile.clone(),
            self.permissions.clone(),
            self.validity,
            self.audiences.clone(),
            self.action_constraint.clone(),
            self.budget_ceiling.clone(),
            self.remaining_depth,
            None,
            self.status_policy.clone(),
            self.assurance_floor.clone(),
            self.extensions.clone(),
        )
    }
}

#[pyclass(name = "GrantRequest", frozen, module = "auths._native")]
pub struct PyGrantRequest {
    scope: ScopeParts,
}

#[pymethods]
impl PyGrantRequest {
    #[new]
    #[allow(clippy::too_many_arguments)]
    fn new(
        subject: PyRef<'_, PyPrincipal>,
        profile_id: &str,
        profile_version: u16,
        permissions: Vec<(String, String)>,
        not_before: u64,
        expires_at: u64,
        audiences: Vec<String>,
        body_digests: Option<Vec<Vec<u8>>>,
        budget: Option<(String, u64)>,
        remaining_depth: u16,
        status: Option<(String, u64)>,
        assurance_floor: &str,
        extensions: Vec<(String, Vec<u8>)>,
    ) -> PyResult<Self> {
        Ok(Self {
            scope: scope_parts(
                subject.inner.clone(),
                profile_id,
                profile_version,
                permissions,
                not_before,
                expires_at,
                audiences,
                body_digests,
                budget,
                remaining_depth,
                status,
                assurance_floor,
                extensions,
            )?,
        })
    }
}

#[pyclass(name = "AuthorityDiff", frozen, module = "auths._native")]
pub struct PyAuthorityDiff {
    removed_permissions: usize,
    removed_audiences: usize,
    validity_shortened: bool,
    action_narrowed: bool,
    budget_narrowed: bool,
    status_narrowed: bool,
    parent_depth: u16,
    child_depth: u16,
}

#[pymethods]
impl PyAuthorityDiff {
    #[getter]
    fn removed_permissions(&self) -> usize {
        self.removed_permissions
    }

    #[getter]
    fn removed_audiences(&self) -> usize {
        self.removed_audiences
    }

    #[getter]
    fn validity_shortened(&self) -> bool {
        self.validity_shortened
    }

    #[getter]
    fn action_narrowed(&self) -> bool {
        self.action_narrowed
    }

    #[getter]
    fn budget_narrowed(&self) -> bool {
        self.budget_narrowed
    }

    #[getter]
    fn status_narrowed(&self) -> bool {
        self.status_narrowed
    }

    #[getter]
    fn delegation_depth(&self) -> (u16, u16) {
        (self.parent_depth, self.child_depth)
    }
}

#[pyclass(name = "GrantPlan", frozen, module = "auths._native")]
pub struct PyGrantPlan {
    pub(crate) inner: GrantPlan,
}

#[pymethods]
impl PyGrantPlan {
    #[getter]
    fn diff(&self) -> PyAuthorityDiff {
        authority_diff(self.inner.diff())
    }

    #[getter]
    fn warnings(&self) -> Vec<&'static str> {
        self.inner
            .warnings()
            .iter()
            .copied()
            .map(warning_label)
            .collect()
    }

    #[getter]
    fn unsigned(&self) -> PyUnsignedObject {
        PyUnsignedObject {
            inner: UnsignedObject::Grant(self.inner.statement().clone()),
        }
    }
}

#[pyfunction]
fn root_grant(
    issuer: PyRef<'_, PyPrincipal>,
    request: PyRef<'_, PyGrantRequest>,
) -> PyUnsignedObject {
    PyUnsignedObject {
        inner: UnsignedObject::Grant(request.scope.statement(issuer.inner.clone())),
    }
}

#[pyfunction]
fn plan_child(
    parent: PyRef<'_, PySignedObject>,
    request: PyRef<'_, PyGrantRequest>,
) -> PyResult<PyGrantPlan> {
    let SignedObject::Grant(parent) = &parent.inner else {
        return Err(PyTypeError::new_err("parent must be a signed grant"));
    };
    Ok(PyGrantPlan {
        inner: plan_child_grant(parent.statement(), request.scope.request())
            .map_err(value_error)?,
    })
}

#[pyfunction]
fn plan_child_statement(
    parent: PyRef<'_, PyUnsignedObject>,
    request: PyRef<'_, PyGrantRequest>,
) -> PyResult<PyGrantPlan> {
    let UnsignedObject::Grant(parent) = &parent.inner else {
        return Err(PyTypeError::new_err("parent must be an unsigned grant"));
    };
    Ok(PyGrantPlan {
        inner: plan_child_grant(parent, request.scope.request()).map_err(value_error)?,
    })
}

#[pyfunction]
fn grant_request_from_statement(
    statement: PyRef<'_, PyUnsignedObject>,
) -> PyResult<PyGrantRequest> {
    let UnsignedObject::Grant(statement) = &statement.inner else {
        return Err(PyTypeError::new_err("statement must be an unsigned grant"));
    };
    Ok(PyGrantRequest {
        scope: scope_from_statement(statement),
    })
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn principal_status_statement(
    method: &str,
    principal: PyRef<'_, PyPrincipal>,
    purpose: &str,
    state: &str,
    sequence: u64,
    observed_at: u64,
    valid_until: u64,
    issuer: PyRef<'_, PyPrincipal>,
    extensions: Vec<(String, Vec<u8>)>,
) -> PyResult<PyUnsignedObject> {
    let statement = PrincipalStatusStatement::new(
        StatusMethodId::parse(method).map_err(value_error)?,
        principal.inner.clone(),
        PurposeId::parse(purpose).map_err(value_error)?,
        principal_state(state)?,
        sequence,
        Timestamp::new(observed_at),
        Timestamp::new(valid_until),
        issuer.inner.clone(),
        critical_extensions(extensions)?,
    )
    .map_err(value_error)?;
    Ok(PyUnsignedObject {
        inner: UnsignedObject::PrincipalStatus(statement),
    })
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn grant_status_statement(
    method: &str,
    grant_id: &[u8],
    state: &str,
    sequence: u64,
    observed_at: u64,
    valid_until: u64,
    issuer: PyRef<'_, PyPrincipal>,
    extensions: Vec<(String, Vec<u8>)>,
) -> PyResult<PyUnsignedObject> {
    let statement = GrantStatusStatement::new(
        StatusMethodId::parse(method).map_err(value_error)?,
        GrantId::new(array32(grant_id, "grant id")?),
        grant_state(state)?,
        sequence,
        Timestamp::new(observed_at),
        Timestamp::new(valid_until),
        issuer.inner.clone(),
        critical_extensions(extensions)?,
    )
    .map_err(value_error)?;
    Ok(PyUnsignedObject {
        inner: UnsignedObject::GrantStatus(statement),
    })
}

enum SigningRequest {
    Grant(ExternalSigningRequest<auths_model::GrantStatement>),
    Action(ExternalSigningRequest<ActionEnvelope>),
    PrincipalStatus(ExternalSigningRequest<PrincipalStatusStatement>),
    GrantStatus(ExternalSigningRequest<GrantStatusStatement>),
}

impl SigningRequest {
    fn request_id(&self) -> String {
        match self {
            Self::Grant(value) => value.request_id(),
            Self::Action(value) => value.request_id(),
            Self::PrincipalStatus(value) => value.request_id(),
            Self::GrantStatus(value) => value.request_id(),
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

    fn object_kind(&self) -> &'static str {
        match self {
            Self::Grant(value) => value.object_id().label(),
            Self::Action(value) => value.object_id().label(),
            Self::PrincipalStatus(value) => value.object_id().label(),
            Self::GrantStatus(value) => value.object_id().label(),
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

    fn transaction_digest(&self) -> Digest {
        match self {
            Self::Grant(value) => value.transaction_digest(),
            Self::Action(value) => value.transaction_digest(),
            Self::PrincipalStatus(value) => value.transaction_digest(),
            Self::GrantStatus(value) => value.transaction_digest(),
        }
    }
}

#[pyclass(name = "SigningRequest", module = "auths._native")]
pub struct PySigningRequest {
    inner: Option<SigningRequest>,
}

#[pymethods]
impl PySigningRequest {
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
        Ok(PyBytes::new(
            py,
            self.request()?.transaction_digest().as_bytes(),
        ))
    }

    fn complete(&mut self, signature: &[u8]) -> PyResult<PySignedObject> {
        let signature = SignatureBytes::new(signature.to_vec()).map_err(value_error)?;
        let request = self
            .inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("signing request was already completed"))?;
        let inner = match request {
            SigningRequest::Grant(value) => SignedObject::Grant(value.complete(signature)),
            SigningRequest::Action(value) => SignedObject::Action(value.complete(signature)),
            SigningRequest::PrincipalStatus(value) => {
                SignedObject::PrincipalStatus(value.complete(signature))
            }
            SigningRequest::GrantStatus(value) => {
                SignedObject::GrantStatus(value.complete(signature))
            }
        };
        Ok(PySignedObject { inner })
    }
}

impl PySigningRequest {
    fn request(&self) -> PyResult<&SigningRequest> {
        self.inner
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("signing request was already completed"))
    }
}

#[pyfunction]
fn prepare_signing(
    unsigned: PyRef<'_, PyUnsignedObject>,
    principal_method: &str,
    verification_method: &str,
    suite: &str,
) -> PyResult<PySigningRequest> {
    let descriptor = signing_descriptor(principal_method, verification_method, suite)?;
    let inner = match &unsigned.inner {
        UnsignedObject::Grant(value) => {
            SigningRequest::Grant(prepare_grant(value.clone(), descriptor).map_err(value_error)?)
        }
        UnsignedObject::Action(value) => {
            SigningRequest::Action(prepare_action(value.clone(), descriptor).map_err(value_error)?)
        }
        UnsignedObject::PrincipalStatus(value) => SigningRequest::PrincipalStatus(
            prepare_principal_status(value.clone(), descriptor).map_err(value_error)?,
        ),
        UnsignedObject::GrantStatus(value) => SigningRequest::GrantStatus(
            prepare_grant_status(value.clone(), descriptor).map_err(value_error)?,
        ),
    };
    Ok(PySigningRequest { inner: Some(inner) })
}

#[pyclass(name = "AuthorizationPlan", frozen, module = "auths._native")]
pub struct PyAuthorizationPlan {
    inner: AuthorizationPlan,
}

#[pymethods]
impl PyAuthorizationPlan {
    #[getter]
    fn plan_id<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let id = auths_codec::plan_id(&self.inner).map_err(value_error)?;
        Ok(PyBytes::new(py, id.as_bytes()))
    }

    #[getter]
    fn shape(&self) -> PyResult<(usize, usize)> {
        let shape = self
            .inner
            .validate(&VerifierLimits::default_deployment())
            .map_err(value_error)?;
        Ok((shape.leaves().len(), shape.maximum_depth()))
    }
}

#[pyclass(name = "AuthorizationPlanBuilder", frozen, module = "auths._native")]
pub struct PyAuthorizationPlanBuilder;

#[pymethods]
impl PyAuthorizationPlanBuilder {
    #[new]
    fn new() -> Self {
        Self
    }

    fn proof(&self, reference: &[u8]) -> PyResult<PyAuthorizationPlan> {
        let limits = VerifierLimits::default_deployment();
        Ok(PyAuthorizationPlan {
            inner: PlanBuilder::new(&limits)
                .proof(ProofRef::new(array32(reference, "proof reference")?)),
        })
    }

    fn all_of(
        &self,
        py: Python<'_>,
        members: Vec<Py<PyAuthorizationPlan>>,
    ) -> PyResult<PyAuthorizationPlan> {
        build_plan(py, members, |builder, values| builder.all_of(values))
    }

    fn any_of(
        &self,
        py: Python<'_>,
        members: Vec<Py<PyAuthorizationPlan>>,
    ) -> PyResult<PyAuthorizationPlan> {
        build_plan(py, members, |builder, values| builder.any_of(values))
    }

    fn threshold(
        &self,
        py: Python<'_>,
        required: u16,
        members: Vec<Py<PyAuthorizationPlan>>,
    ) -> PyResult<PyAuthorizationPlan> {
        build_plan(py, members, |builder, values| {
            builder.k_of_n(required, values)
        })
    }
}

#[pyclass(name = "McpAction", frozen, module = "auths._native")]
pub struct PyMcpAction {
    canonical: CanonicalAction,
    envelope: ActionEnvelope,
    arguments_json: Vec<u8>,
    audience: String,
    resource: String,
    display_digest_hex: String,
}

#[pymethods]
impl PyMcpAction {
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
    fn resource(&self) -> &str {
        &self.resource
    }

    #[getter]
    fn display_digest_hex(&self) -> &str {
        &self.display_digest_hex
    }
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn prepare_mcp_action(
    service: &str,
    name: &str,
    arguments_json: &[u8],
    actor: PyRef<'_, PyPrincipal>,
    terminal_grant: PyRef<'_, PySignedObject>,
    challenge: &[u8],
    evaluation_time: u64,
) -> PyResult<PyMcpAction> {
    let Value::Object(arguments) =
        serde_json::from_slice::<Value>(arguments_json).map_err(value_error)?
    else {
        return Err(PyValueError::new_err("MCP arguments must be a JSON object"));
    };
    let canonical_arguments = serde_json_canonicalizer::to_vec(&arguments).map_err(value_error)?;
    if canonical_arguments != arguments_json {
        return Err(PyValueError::new_err(
            "MCP arguments must use canonical JSON encoding",
        ));
    }
    let SignedObject::Grant(terminal_grant) = &terminal_grant.inner else {
        return Err(PyTypeError::new_err(
            "terminal grant must be a signed grant",
        ));
    };
    let call = McpToolCall::new(service, name, arguments).map_err(value_error)?;
    let profile = McpProfile;
    let canonical = profile
        .canonicalize(&call.canonical_bytes().map_err(value_error)?)
        .map_err(value_error)?;
    let display = profile.review_display(&canonical).map_err(value_error)?;
    let challenge = array32(challenge, "challenge")?;
    let proof_ref = ProofRef::new(challenge);
    let plan = AuthorizationPlan::proof(proof_ref);
    let envelope = ActionEnvelope::new(
        canonical.profile().clone(),
        canonical.media_type().clone(),
        auths_codec::body_digest(canonical.body()),
        canonical.permission().clone(),
        canonical.requested_budget().cloned(),
        call.audience().map_err(value_error)?,
        Challenge::new(challenge),
        ValidityWindow::new(
            Timestamp::new(evaluation_time),
            Timestamp::new(evaluation_time),
        )
        .map_err(value_error)?,
        actor.inner.clone(),
        Some(auths_codec::grant_id(terminal_grant.statement()).map_err(value_error)?),
        auths_codec::plan_id(&plan).map_err(value_error)?,
        ChannelBindingId::parse("none-v1").map_err(value_error)?,
        proof_ref,
        Vec::new(),
        CriticalExtensions::empty(),
    );
    Ok(PyMcpAction {
        arguments_json: canonical_arguments,
        audience: call.audience().map_err(value_error)?.to_string(),
        resource: canonical.permission().resource().to_string(),
        display_digest_hex: display.canonical_digest_hex().to_owned(),
        canonical,
        envelope,
    })
}

#[pyclass(name = "AssurancePolicy", frozen, module = "auths._native")]
pub struct PyAssurancePolicy {
    inner: AssurancePolicy,
}

#[pymethods]
impl PyAssurancePolicy {
    #[new]
    fn new(
        identifier: &str,
        requirements: Vec<(String, String, String, Option<u64>)>,
    ) -> PyResult<Self> {
        let requirements = requirements
            .into_iter()
            .map(|(role, quantifier, claim, maximum_age)| {
                Ok(AssuranceRequirement::new(
                    participant_role(&role)?,
                    assurance_quantifier(&quantifier)?,
                    AssuranceClaimId::parse(&claim).map_err(value_error)?,
                    maximum_age
                        .map(FreshnessLimit::new)
                        .transpose()
                        .map_err(value_error)?,
                ))
            })
            .collect::<PyResult<Vec<_>>>()?;
        Ok(Self {
            inner: AssurancePolicy::new(
                AssurancePolicyId::parse(identifier).map_err(value_error)?,
                requirements,
            )
            .map_err(value_error)?,
        })
    }
}

#[pyclass(name = "TrustAnchor", frozen, module = "auths._native")]
pub struct PyTrustAnchor {
    inner: TrustAnchor,
}

#[pymethods]
impl PyTrustAnchor {
    #[new]
    #[allow(clippy::too_many_arguments)]
    fn new(
        identifier: &str,
        principal: PyRef<'_, PyPrincipal>,
        accepted_methods: Vec<String>,
        profiles: Vec<(String, u16)>,
        permissions: Vec<(String, String)>,
        resource_namespaces: Vec<String>,
        audiences: Vec<String>,
        not_before: u64,
        expires_at: u64,
        budget: Option<(String, u64)>,
        max_delegation_depth: u16,
        assurance_policy: &str,
        status: Option<(String, u64)>,
    ) -> PyResult<Self> {
        Ok(Self {
            inner: TrustAnchor::new(
                TrustAnchorId::parse(identifier).map_err(value_error)?,
                principal.inner.clone(),
                accepted_methods
                    .into_iter()
                    .map(|value| PrincipalMethodId::parse(&value).map_err(value_error))
                    .collect::<PyResult<Vec<_>>>()?,
                profiles
                    .into_iter()
                    .map(|(identifier, version)| {
                        ProfileRef::new(
                            ProfileId::parse(&identifier).map_err(value_error)?,
                            version,
                        )
                        .map_err(value_error)
                    })
                    .collect::<PyResult<Vec<_>>>()?,
                permission_set(permissions)?,
                resource_namespaces
                    .into_iter()
                    .map(|value| ResourceId::parse(&value).map_err(value_error))
                    .collect::<PyResult<Vec<_>>>()?,
                audience_set(audiences)?,
                ValidityWindow::new(Timestamp::new(not_before), Timestamp::new(expires_at))
                    .map_err(value_error)?,
                budget_ceiling(budget)?,
                max_delegation_depth,
                AssurancePolicyId::parse(assurance_policy).map_err(value_error)?,
                status_policy(status)?,
            )
            .map_err(value_error)?,
        })
    }
}

#[derive(Clone)]
enum StatusSnapshot {
    Principal(PrincipalStatusSnapshot),
    Grant(GrantStatusSnapshot),
}

#[pyclass(name = "StatusSnapshot", frozen, module = "auths._native")]
pub struct PyStatusSnapshot {
    inner: StatusSnapshot,
}

#[pymethods]
impl PyStatusSnapshot {
    #[getter]
    fn kind(&self) -> &'static str {
        match self.inner {
            StatusSnapshot::Principal(_) => "principal",
            StatusSnapshot::Grant(_) => "grant",
        }
    }
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn status_snapshot(
    py: Python<'_>,
    kind: &str,
    identifier: &[u8],
    observed_at: u64,
    valid_until: u64,
    statements: Vec<Py<PySignedObject>>,
    checkpoints: Vec<Vec<u8>>,
    trust: Vec<(String, String, u64)>,
) -> PyResult<PyStatusSnapshot> {
    let id = StatusSnapshotId::new(array32(identifier, "status snapshot id")?);
    let checkpoints = checkpoints
        .into_iter()
        .map(|value| array32(&value, "status checkpoint").map(EvidenceId::new))
        .collect::<PyResult<Vec<_>>>()?;
    let trust = trust
        .into_iter()
        .map(|(method, issuer, sequence_floor)| {
            Ok(StatusTrustRule::new(
                StatusMethodId::parse(&method).map_err(value_error)?,
                PrincipalId::parse(&issuer).map_err(value_error)?,
                sequence_floor,
            ))
        })
        .collect::<PyResult<Vec<_>>>()?;
    let inner = match kind {
        "principal" => StatusSnapshot::Principal(
            PrincipalStatusSnapshot::with_trust(
                id,
                Timestamp::new(observed_at),
                Timestamp::new(valid_until),
                statements
                    .iter()
                    .map(|value| match &value.borrow(py).inner {
                        SignedObject::PrincipalStatus(statement) => Ok(statement.clone()),
                        _ => Err(PyTypeError::new_err(
                            "principal snapshot requires principal-status statements",
                        )),
                    })
                    .collect::<PyResult<Vec<_>>>()?,
                checkpoints,
                trust,
            )
            .map_err(value_error)?,
        ),
        "grant" => StatusSnapshot::Grant(
            GrantStatusSnapshot::with_trust(
                id,
                Timestamp::new(observed_at),
                Timestamp::new(valid_until),
                statements
                    .iter()
                    .map(|value| match &value.borrow(py).inner {
                        SignedObject::GrantStatus(statement) => Ok(statement.clone()),
                        _ => Err(PyTypeError::new_err(
                            "grant snapshot requires grant-status statements",
                        )),
                    })
                    .collect::<PyResult<Vec<_>>>()?,
                checkpoints,
                trust,
            )
            .map_err(value_error)?,
        ),
        _ => {
            return Err(PyValueError::new_err(
                "status kind must be principal or grant",
            ));
        }
    };
    Ok(PyStatusSnapshot { inner })
}

#[pyclass(name = "TrustedContext", frozen, module = "auths._native")]
pub struct PyTrustedContext {
    pub(crate) inner: VerifierContext,
}

#[pymethods]
impl PyTrustedContext {
    #[getter]
    fn configuration<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.configuration().as_bytes())
    }

    fn bind_request(
        &self,
        audience: &str,
        challenge: &[u8],
        evaluation_time: u64,
    ) -> PyResult<Self> {
        Ok(Self {
            inner: self
                .inner
                .for_request(
                    Audience::parse(audience).map_err(value_error)?,
                    Challenge::new(array32(challenge, "challenge")?),
                    Timestamp::new(evaluation_time),
                )
                .map_err(value_error)?,
        })
    }
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn compile_trusted_context(
    py: Python<'_>,
    configuration: &[u8],
    expected_plan: Option<Py<PyAuthorizationPlan>>,
    minimum_authorized_branches: u16,
    minimum_distinct_actors: u16,
    minimum_distinct_roots: u16,
    anchors: Vec<Py<PyTrustAnchor>>,
    assurance_policy: PyRef<'_, PyAssurancePolicy>,
    principal_status: Option<Py<PyStatusSnapshot>>,
    grant_status: Option<Py<PyStatusSnapshot>>,
    channel_policy: &str,
    evidence_types: Vec<String>,
    critical_extensions: Vec<String>,
) -> PyResult<PyTrustedContext> {
    let expected_plan = expected_plan
        .as_ref()
        .map(|plan| auths_codec::plan_id(&plan.borrow(py).inner).map_err(value_error))
        .transpose()?;
    let composition = CompositionRequirement::new(
        expected_plan,
        minimum_authorized_branches,
        minimum_distinct_actors,
        minimum_distinct_roots,
    )
    .map_err(value_error)?;
    let anchors = anchors
        .iter()
        .map(|anchor| anchor.borrow(py).inner.clone())
        .collect();
    let mut builder = auths_sdk::TrustedContextBuilder::new(
        VerifierConfigurationId::new(array32(configuration, "configuration")?),
        composition,
        anchors,
        assurance_policy.inner.clone(),
    )
    .map_err(value_error)?;
    if let Some(snapshot) = principal_status {
        match &snapshot.borrow(py).inner {
            StatusSnapshot::Principal(value) => {
                builder = builder.with_principal_status(value.clone());
            }
            StatusSnapshot::Grant(_) => {
                return Err(PyTypeError::new_err(
                    "principal_status must contain a principal snapshot",
                ));
            }
        }
    }
    if let Some(snapshot) = grant_status {
        match &snapshot.borrow(py).inner {
            StatusSnapshot::Grant(value) => {
                builder = builder.with_grant_status(value.clone());
            }
            StatusSnapshot::Principal(_) => {
                return Err(PyTypeError::new_err(
                    "grant_status must contain a grant snapshot",
                ));
            }
        }
    }
    builder =
        builder.with_channel_policy(ChannelBindingId::parse(channel_policy).map_err(value_error)?);
    for identifier in evidence_types {
        builder = builder.accept_evidence_type(
            auths_model::EvidenceTypeId::parse(&identifier).map_err(value_error)?,
        );
    }
    for identifier in critical_extensions {
        builder = builder.accept_critical_extension(
            auths_model::ExtensionId::parse(&identifier).map_err(value_error)?,
        );
    }
    Ok(PyTrustedContext {
        inner: builder.build().map_err(value_error)?,
    })
}

#[pyfunction]
fn self_contained_configuration(py: Python<'_>) -> PyResult<Bound<'_, PyBytes>> {
    Ok(PyBytes::new(py, &configuration()?))
}

#[pyfunction]
fn inspect_unsigned<'py>(
    py: Python<'py>,
    value: PyRef<'_, PyUnsignedObject>,
) -> PyResult<Bound<'py, PyBytes>> {
    let bytes = match &value.inner {
        UnsignedObject::Grant(value) => auths_codec::encode_grant_statement(value),
        UnsignedObject::Action(value) => auths_codec::encode_action_envelope(value),
        UnsignedObject::PrincipalStatus(value) => {
            auths_codec::encode_principal_status_statement(value)
        }
        UnsignedObject::GrantStatus(value) => auths_codec::encode_grant_status_statement(value),
    }
    .map_err(value_error)?;
    Ok(PyBytes::new(py, &bytes))
}

#[pyfunction]
fn inspect_signed<'py>(
    py: Python<'py>,
    value: PyRef<'_, PySignedObject>,
) -> PyResult<Bound<'py, PyBytes>> {
    let bytes = match &value.inner {
        SignedObject::Grant(value) => auths_codec::encode_signed_grant(value),
        SignedObject::Action(value) => auths_codec::encode_signed_action(value),
        SignedObject::PrincipalStatus(value) => auths_codec::encode_signed_principal_status(value),
        SignedObject::GrantStatus(value) => auths_codec::encode_signed_grant_status(value),
    }
    .map_err(value_error)?;
    Ok(PyBytes::new(py, &bytes))
}

#[pyfunction]
fn inspect_plan<'py>(
    py: Python<'py>,
    value: PyRef<'_, PyAuthorizationPlan>,
) -> PyResult<Bound<'py, PyBytes>> {
    let bytes = auths_codec::encode_authorization_plan(&value.inner).map_err(value_error)?;
    Ok(PyBytes::new(py, &bytes))
}

#[pyfunction]
fn inspect_mcp_action<'py>(
    py: Python<'py>,
    value: PyRef<'_, PyMcpAction>,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    Ok((
        PyBytes::new(
            py,
            &auths_codec::encode_canonical_action(&value.canonical).map_err(value_error)?,
        ),
        PyBytes::new(py, &value.arguments_json),
    ))
}

#[pyfunction]
fn inspect_trusted_context<'py>(
    py: Python<'py>,
    value: PyRef<'_, PyTrustedContext>,
) -> PyResult<Bound<'py, PyBytes>> {
    let bytes = auths_codec::encode_verifier_context(&value.inner).map_err(value_error)?;
    Ok(PyBytes::new(py, &bytes))
}

#[pyfunction]
fn parse_signed(kind: &str, value: &[u8]) -> PyResult<PySignedObject> {
    let limits = VerifierLimits::default_deployment();
    let inner = match kind {
        "grant" => SignedObject::Grant(
            auths_codec::decode_signed_grant(value, &limits).map_err(value_error)?,
        ),
        "action" => SignedObject::Action(
            auths_codec::decode_signed_action(value, &limits).map_err(value_error)?,
        ),
        "principal-status" => SignedObject::PrincipalStatus(
            auths_codec::decode_signed_principal_status(value, &limits).map_err(value_error)?,
        ),
        "grant-status" => SignedObject::GrantStatus(
            auths_codec::decode_signed_grant_status(value, &limits).map_err(value_error)?,
        ),
        _ => return Err(PyValueError::new_err("unsupported signed object kind")),
    };
    Ok(PySignedObject { inner })
}

#[pyfunction]
fn parse_unsigned(kind: &str, value: &[u8]) -> PyResult<PyUnsignedObject> {
    let limits = VerifierLimits::default_deployment();
    let inner = match kind {
        "grant" => UnsignedObject::Grant(
            auths_codec::decode_grant_statement(value, &limits).map_err(value_error)?,
        ),
        "action" => UnsignedObject::Action(
            auths_codec::decode_action_envelope(value, &limits).map_err(value_error)?,
        ),
        "principal-status" => UnsignedObject::PrincipalStatus(
            auths_codec::decode_principal_status_statement(value, &limits).map_err(value_error)?,
        ),
        "grant-status" => UnsignedObject::GrantStatus(
            auths_codec::decode_grant_status_statement(value, &limits).map_err(value_error)?,
        ),
        _ => return Err(PyValueError::new_err("unsupported unsigned object kind")),
    };
    Ok(PyUnsignedObject { inner })
}

#[pyfunction]
fn unsigned_from_signed(value: PyRef<'_, PySignedObject>) -> PyUnsignedObject {
    let inner = match &value.inner {
        SignedObject::Grant(value) => UnsignedObject::Grant(value.statement().clone()),
        SignedObject::Action(value) => UnsignedObject::Action(value.envelope().clone()),
        SignedObject::PrincipalStatus(value) => {
            UnsignedObject::PrincipalStatus(value.statement().clone())
        }
        SignedObject::GrantStatus(value) => UnsignedObject::GrantStatus(value.statement().clone()),
    };
    PyUnsignedObject { inner }
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyPrincipal>()?;
    module.add_class::<PyUnsignedObject>()?;
    module.add_class::<PySignedObject>()?;
    module.add_class::<PyGrantRequest>()?;
    module.add_class::<PyAuthorityDiff>()?;
    module.add_class::<PyGrantPlan>()?;
    module.add_class::<PySigningRequest>()?;
    module.add_class::<PyAuthorizationPlan>()?;
    module.add_class::<PyAuthorizationPlanBuilder>()?;
    module.add_class::<PyMcpAction>()?;
    module.add_class::<PyAssurancePolicy>()?;
    module.add_class::<PyTrustAnchor>()?;
    module.add_class::<PyStatusSnapshot>()?;
    module.add_class::<PyTrustedContext>()?;
    module.add_function(wrap_pyfunction!(root_grant, module)?)?;
    module.add_function(wrap_pyfunction!(plan_child, module)?)?;
    module.add_function(wrap_pyfunction!(plan_child_statement, module)?)?;
    module.add_function(wrap_pyfunction!(grant_request_from_statement, module)?)?;
    module.add_function(wrap_pyfunction!(principal_status_statement, module)?)?;
    module.add_function(wrap_pyfunction!(grant_status_statement, module)?)?;
    module.add_function(wrap_pyfunction!(prepare_signing, module)?)?;
    module.add_function(wrap_pyfunction!(prepare_mcp_action, module)?)?;
    module.add_function(wrap_pyfunction!(status_snapshot, module)?)?;
    module.add_function(wrap_pyfunction!(compile_trusted_context, module)?)?;
    module.add_function(wrap_pyfunction!(self_contained_configuration, module)?)?;
    module.add_function(wrap_pyfunction!(inspect_unsigned, module)?)?;
    module.add_function(wrap_pyfunction!(inspect_signed, module)?)?;
    module.add_function(wrap_pyfunction!(inspect_plan, module)?)?;
    module.add_function(wrap_pyfunction!(inspect_mcp_action, module)?)?;
    module.add_function(wrap_pyfunction!(inspect_trusted_context, module)?)?;
    module.add_function(wrap_pyfunction!(parse_signed, module)?)?;
    module.add_function(wrap_pyfunction!(parse_unsigned, module)?)?;
    module.add_function(wrap_pyfunction!(unsigned_from_signed, module)?)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn scope_parts(
    subject: PrincipalId,
    profile_id: &str,
    profile_version: u16,
    permissions: Vec<(String, String)>,
    not_before: u64,
    expires_at: u64,
    audiences: Vec<String>,
    body_digests: Option<Vec<Vec<u8>>>,
    budget: Option<(String, u64)>,
    remaining_depth: u16,
    status: Option<(String, u64)>,
    assurance_floor: &str,
    extensions: Vec<(String, Vec<u8>)>,
) -> PyResult<ScopeParts> {
    Ok(ScopeParts {
        subject,
        profile: ProfileRef::new(
            ProfileId::parse(profile_id).map_err(value_error)?,
            profile_version,
        )
        .map_err(value_error)?,
        permissions: permission_set(permissions)?,
        validity: ValidityWindow::new(Timestamp::new(not_before), Timestamp::new(expires_at))
            .map_err(value_error)?,
        audiences: audience_set(audiences)?,
        action_constraint: action_constraint(body_digests)?,
        budget_ceiling: budget_ceiling(budget)?,
        remaining_depth,
        status_policy: status_policy(status)?,
        assurance_floor: AssurancePolicyId::parse(assurance_floor).map_err(value_error)?,
        extensions: critical_extensions(extensions)?,
    })
}

fn scope_from_statement(statement: &auths_model::GrantStatement) -> ScopeParts {
    ScopeParts {
        subject: statement.subject().clone(),
        profile: statement.profile().clone(),
        permissions: statement.permissions().clone(),
        validity: statement.validity(),
        audiences: statement.audiences().clone(),
        action_constraint: statement.action_constraint().clone(),
        budget_ceiling: statement.budget_ceiling().cloned(),
        remaining_depth: statement.remaining_depth(),
        status_policy: statement.status_policy().clone(),
        assurance_floor: statement.assurance_floor().clone(),
        extensions: statement.extensions().clone(),
    }
}

fn permission_set(values: Vec<(String, String)>) -> PyResult<PermissionSet> {
    PermissionSet::new(
        values
            .into_iter()
            .map(|(capability, resource)| {
                Ok(Permission::new(
                    auths_model::CapabilityId::parse(&capability).map_err(value_error)?,
                    ResourceId::parse(&resource).map_err(value_error)?,
                ))
            })
            .collect::<PyResult<Vec<_>>>()?,
    )
    .map_err(value_error)
}

fn audience_set(values: Vec<String>) -> PyResult<AudienceSet> {
    AudienceSet::new(
        values
            .into_iter()
            .map(|value| Audience::parse(&value).map_err(value_error))
            .collect::<PyResult<Vec<_>>>()?,
    )
    .map_err(value_error)
}

fn action_constraint(values: Option<Vec<Vec<u8>>>) -> PyResult<ActionConstraint> {
    let Some(values) = values else {
        return Ok(ActionConstraint::AnyBody);
    };
    let digests = values
        .into_iter()
        .map(|value| array32(&value, "body digest").map(Digest::new))
        .collect::<PyResult<Vec<_>>>()?;
    match digests.as_slice() {
        [digest] => Ok(ActionConstraint::ExactBodyDigest(*digest)),
        _ => ActionConstraint::allowed_body_digests(digests).map_err(value_error),
    }
}

fn budget_ceiling(value: Option<(String, u64)>) -> PyResult<Option<BudgetCeiling>> {
    value
        .map(|(algebra, value)| {
            Ok(BudgetCeiling::new(
                BudgetAlgebraId::parse(&algebra).map_err(value_error)?,
                value,
            ))
        })
        .transpose()
}

fn status_policy(value: Option<(String, u64)>) -> PyResult<StatusPolicy> {
    match value {
        Some((method, maximum_age)) => Ok(StatusPolicy::SnapshotRequired {
            method: StatusMethodId::parse(&method).map_err(value_error)?,
            max_age: FreshnessLimit::new(maximum_age).map_err(value_error)?,
        }),
        None => Ok(StatusPolicy::ExpiryOnly),
    }
}

fn critical_extensions(values: Vec<(String, Vec<u8>)>) -> PyResult<CriticalExtensions> {
    CriticalExtensions::new(
        values
            .into_iter()
            .map(|(identifier, bytes)| {
                CriticalExtension::new(
                    auths_model::ExtensionId::parse(&identifier).map_err(value_error)?,
                    bytes,
                )
                .map_err(value_error)
            })
            .collect::<PyResult<Vec<_>>>()?,
    )
    .map_err(value_error)
}

fn principal_state(value: &str) -> PyResult<PrincipalState> {
    match value {
        "active" => Ok(PrincipalState::Active),
        "revoked" => Ok(PrincipalState::Revoked),
        "superseded" => Ok(PrincipalState::Superseded),
        _ => Err(PyValueError::new_err("invalid principal status state")),
    }
}

fn grant_state(value: &str) -> PyResult<GrantState> {
    match value {
        "active" => Ok(GrantState::Active),
        "revoked" => Ok(GrantState::Revoked),
        "superseded" => Ok(GrantState::Superseded),
        _ => Err(PyValueError::new_err("invalid grant status state")),
    }
}

pub(crate) fn signing_descriptor(
    principal_method: &str,
    verification_method: &str,
    suite: &str,
) -> PyResult<SignatureDescriptor> {
    Ok(SignatureDescriptor::new(
        PrincipalMethodId::parse(principal_method).map_err(value_error)?,
        VerificationMethod::parse(verification_method).map_err(value_error)?,
        SignatureSuiteId::parse(suite).map_err(value_error)?,
    ))
}

fn authority_diff(value: &AuthorityDiff) -> PyAuthorityDiff {
    let (parent_depth, child_depth) = value.delegation_depth();
    PyAuthorityDiff {
        removed_permissions: value.removed_permissions(),
        removed_audiences: value.removed_audiences(),
        validity_shortened: value.validity_shortened(),
        action_narrowed: value.action_narrowed(),
        budget_narrowed: value.budget_narrowed(),
        status_narrowed: value.status_narrowed(),
        parent_depth,
        child_depth,
    }
}

const fn warning_label(value: OverGrantingWarning) -> &'static str {
    match value {
        OverGrantingWarning::AnyBody => "any-body",
        OverGrantingWarning::MultiplePermissions => "multiple-permissions",
        OverGrantingWarning::MultipleAudiences => "multiple-audiences",
        OverGrantingWarning::DelegationAllowed => "delegation-allowed",
        OverGrantingWarning::NoBudgetCeiling => "no-budget-ceiling",
        OverGrantingWarning::LongValidity => "long-validity",
    }
}

fn build_plan(
    py: Python<'_>,
    members: Vec<Py<PyAuthorizationPlan>>,
    operation: impl FnOnce(
        &PlanBuilder<'_>,
        Vec<AuthorizationPlan>,
    ) -> Result<AuthorizationPlan, auths_author::PlanningError>,
) -> PyResult<PyAuthorizationPlan> {
    let members = members
        .iter()
        .map(|member| member.borrow(py).inner.clone())
        .collect();
    let limits = VerifierLimits::default_deployment();
    Ok(PyAuthorizationPlan {
        inner: operation(&PlanBuilder::new(&limits), members).map_err(value_error)?,
    })
}

fn participant_role(value: &str) -> PyResult<ParticipantRole> {
    match value {
        "root" => Ok(ParticipantRole::Root),
        "intermediate" => Ok(ParticipantRole::Intermediate),
        "actor" => Ok(ParticipantRole::Actor),
        "external-issuer" => Ok(ParticipantRole::ExternalIssuer),
        _ => Err(PyValueError::new_err("invalid assurance participant role")),
    }
}

fn assurance_quantifier(value: &str) -> PyResult<AssuranceQuantifier> {
    match value {
        "any" => Ok(AssuranceQuantifier::Any),
        "every" => Ok(AssuranceQuantifier::Every),
        _ => Err(PyValueError::new_err("invalid assurance quantifier")),
    }
}

pub(crate) fn configuration() -> PyResult<[u8; 32]> {
    let raw_key = auths_raw_key::RawKeyMethod::new().map_err(value_error)?;
    let did_key = auths_did_key::DidKeyMethod::new().map_err(value_error)?;
    let did_keri = auths_did_keri::DidKeriMethod::new().map_err(value_error)?;
    let ed25519 = auths_signature::Ed25519Suite::new().map_err(value_error)?;
    let p256 = auths_signature::P256Sha256Suite::new().map_err(value_error)?;
    let methods: [&dyn PrincipalMethod; 3] = [&raw_key, &did_key, &did_keri];
    let suites: [&dyn SignatureSuite; 2] = [&ed25519, &p256];
    let registries =
        auths_registries::ImmutableRegistries::new(&methods, &suites).map_err(value_error)?;
    Ok(*registries.configuration_id().as_bytes())
}

fn array32(value: &[u8], label: &str) -> PyResult<[u8; 32]> {
    value
        .try_into()
        .map_err(|_| PyValueError::new_err(format!("{label} must contain 32 bytes")))
}

pub(crate) fn value_error(error: impl std::fmt::Display) -> PyErr {
    PyValueError::new_err(error.to_string())
}
