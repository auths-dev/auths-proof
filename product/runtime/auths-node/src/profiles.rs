use auths_production_client::{
    ClientOutcomeKind, ProductVerb, ProductionRequest, ProductionResponse, QualifiedProfile,
    RecoveryReference, RetryClass,
};
use serde::Serialize;
use std::{collections::BTreeSet, sync::Arc};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeFailure {
    Denied,
    Indeterminate,
    Unavailable,
    Malformed,
    ProfileDisabled,
    UnknownWorkflow,
    UnknownReceipt,
    DisclosureDenied,
}

impl RuntimeFailure {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Denied => "authority.denied",
            Self::Indeterminate => "authority.indeterminate",
            Self::Unavailable => "core.runtime-unavailable",
            Self::Malformed => "core.malformed-input",
            Self::ProfileDisabled => "profile.disabled",
            Self::UnknownWorkflow => "workflow.unknown",
            Self::UnknownReceipt => "receipt.unknown",
            Self::DisclosureDenied => "receipt.disclosure-denied",
        }
    }

    #[must_use]
    pub const fn retry(self) -> RetryClass {
        match self {
            Self::Unavailable => RetryClass::Backoff,
            Self::Indeterminate => RetryClass::Reconcile,
            _ => RetryClass::Never,
        }
    }
}

impl std::fmt::Display for RuntimeFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for RuntimeFailure {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowProjection {
    pub reference: String,
    pub profile: String,
    pub state: String,
    pub effect: String,
    pub retry: String,
    pub updated_at: u64,
    pub receipt_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptSummary {
    pub receipt_id: String,
    pub profile: String,
    pub outcome: String,
    pub completed_at: u64,
    pub disclosure: &'static str,
}

pub trait AuthorityPort: Send + Sync {
    fn create(&self, request: &ProductionRequest) -> Result<Vec<u8>, RuntimeFailure>;
    fn delegate(&self, request: &ProductionRequest) -> Result<Vec<u8>, RuntimeFailure>;
    fn verify(&self, request: &ProductionRequest) -> Result<Option<Vec<u8>>, RuntimeFailure>;
}

pub trait ExactProfilePort: Send + Sync {
    fn execute(&self, request: &ProductionRequest) -> Result<ProductionResponse, RuntimeFailure>;
}

pub trait WorkflowPort: Send + Sync {
    fn resume(&self, request: &ProductionRequest) -> Result<ProductionResponse, RuntimeFailure>;
    fn status(&self, reference: &RecoveryReference) -> Result<WorkflowProjection, RuntimeFailure>;
}

pub trait ReceiptPort: Send + Sync {
    fn summary(&self, receipt_id: &str) -> Result<ReceiptSummary, RuntimeFailure>;
    fn disclose(&self, receipt_id: &str, authorization: &[u8]) -> Result<Vec<u8>, RuntimeFailure>;
}

pub trait ReadinessPort: Send + Sync {
    fn ready(&self) -> bool;
}

pub struct ClosedProfileRegistry {
    authority: Arc<dyn AuthorityPort>,
    workflow: Arc<dyn WorkflowPort>,
    receipts: Arc<dyn ReceiptPort>,
    readiness: Arc<dyn ReadinessPort>,
    opentofu: Option<Arc<dyn ExactProfilePort>>,
    postgresql: Option<Arc<dyn ExactProfilePort>>,
    github: Option<Arc<dyn ExactProfilePort>>,
}

impl ClosedProfileRegistry {
    #[must_use]
    pub fn new(
        authority: Arc<dyn AuthorityPort>,
        workflow: Arc<dyn WorkflowPort>,
        receipts: Arc<dyn ReceiptPort>,
        readiness: Arc<dyn ReadinessPort>,
    ) -> Self {
        Self {
            authority,
            workflow,
            receipts,
            readiness,
            opentofu: None,
            postgresql: None,
            github: None,
        }
    }

    #[must_use]
    pub fn with_profile(
        mut self,
        profile: QualifiedProfile,
        port: Arc<dyn ExactProfilePort>,
    ) -> Self {
        match profile {
            QualifiedProfile::OpenTofuSavedPlanApply => self.opentofu = Some(port),
            QualifiedProfile::PostgreSqlBoundedUpdate => self.postgresql = Some(port),
            QualifiedProfile::GitHubIssueAddress => self.github = Some(port),
        }
        self
    }

    #[must_use]
    pub fn enabled_profiles(&self) -> BTreeSet<QualifiedProfile> {
        let mut values = BTreeSet::new();
        if self.opentofu.is_some() {
            values.insert(QualifiedProfile::OpenTofuSavedPlanApply);
        }
        if self.postgresql.is_some() {
            values.insert(QualifiedProfile::PostgreSqlBoundedUpdate);
        }
        if self.github.is_some() {
            values.insert(QualifiedProfile::GitHubIssueAddress);
        }
        values
    }

    fn execute(&self, request: &ProductionRequest) -> Result<ProductionResponse, RuntimeFailure> {
        let port = match request.profile() {
            QualifiedProfile::OpenTofuSavedPlanApply => self.opentofu.as_ref(),
            QualifiedProfile::PostgreSqlBoundedUpdate => self.postgresql.as_ref(),
            QualifiedProfile::GitHubIssueAddress => self.github.as_ref(),
        }
        .ok_or(RuntimeFailure::ProfileDisabled)?;
        port.execute(request)
    }
}

impl crate::api::NodeRuntime for ClosedProfileRegistry {
    fn handle(&self, request: ProductionRequest) -> Result<ProductionResponse, RuntimeFailure> {
        match request.verb() {
            ProductVerb::Create => completed_authority(self.authority.create(&request)?),
            ProductVerb::Delegate => completed_authority(self.authority.delegate(&request)?),
            ProductVerb::Execute => self.execute(&request),
            ProductVerb::Resume => self.workflow.resume(&request),
            ProductVerb::Verify => ProductionResponse::new(
                ClientOutcomeKind::Verified,
                None,
                RetryClass::Never,
                None,
                self.authority.verify(&request)?,
                None,
            )
            .map_err(|_| RuntimeFailure::Malformed),
        }
    }

    fn status(&self, reference: &RecoveryReference) -> Result<WorkflowProjection, RuntimeFailure> {
        self.workflow.status(reference)
    }

    fn receipt_summary(&self, receipt_id: &str) -> Result<ReceiptSummary, RuntimeFailure> {
        self.receipts.summary(receipt_id)
    }

    fn disclose_receipt(
        &self,
        receipt_id: &str,
        authorization: &[u8],
    ) -> Result<Vec<u8>, RuntimeFailure> {
        self.receipts.disclose(receipt_id, authorization)
    }

    fn ready(&self) -> bool {
        self.readiness.ready()
    }
}

fn completed_authority(value: Vec<u8>) -> Result<ProductionResponse, RuntimeFailure> {
    ProductionResponse::new(
        ClientOutcomeKind::Completed,
        None,
        RetryClass::Never,
        None,
        Some(value),
        Some(b"auths-authority-issued-v1".to_vec()),
    )
    .map_err(|_| RuntimeFailure::Malformed)
}

pub fn failure_response(error: RuntimeFailure) -> ProductionResponse {
    let kind = match error {
        RuntimeFailure::Denied
        | RuntimeFailure::Malformed
        | RuntimeFailure::ProfileDisabled
        | RuntimeFailure::UnknownWorkflow
        | RuntimeFailure::UnknownReceipt
        | RuntimeFailure::DisclosureDenied => ClientOutcomeKind::Denied,
        RuntimeFailure::Indeterminate | RuntimeFailure::Unavailable => {
            ClientOutcomeKind::Indeterminate
        }
    };
    ProductionResponse::new(
        kind,
        Some(error.code().to_owned()),
        error.retry(),
        None,
        None,
        None,
    )
    .expect("closed failure projections are valid")
}
