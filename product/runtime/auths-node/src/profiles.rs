use auths_model::{DenialReason, Requirement};
use auths_operations::EffectState;
use auths_production_client::{
    ClientOutcomeKind, NextCall, ProductVerb, ProductionRequest, ProductionResponse,
    QualifiedProfile, RecoveryReference,
};
use serde::Serialize;
use std::{collections::BTreeSet, sync::Arc};

/// Whether a failing provider call had already entered the provider.
///
/// A profile port cannot report an honest effect state without stating this.
/// Before entry the runtime holds proof that nothing was applied; after entry it
/// holds none, and a failed call is indistinguishable from an applied call whose
/// acknowledgement was lost.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderBoundary {
    /// The exact request provably never reached the provider.
    BeforeEntry,
    /// The exact request entered, or may have entered, the provider.
    AfterEntry,
}

/// Every failure this node can put on the wire.
///
/// Each variant projects to one code that exists in
/// `product/errors/v1/registry.json`; `every_wire_code_is_registered` holds
/// that. The two authorization variants carry the kernel's exact reason so the
/// node's decision can be compared to the kernel's without translation, while
/// the wire stays at the coarse registered code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeFailure {
    /// Available facts prove the proof does not authorize the exact action.
    AuthorizationDenied(DenialReason),
    /// A required authorization fact was unavailable, before any effect.
    AuthorizationIndeterminate(Requirement),
    /// The request asserts a principal the node cannot authenticate.
    UnauthenticatedPrincipal,
    /// The exact authorized pair has already produced every effect it may.
    ///
    /// The kernel proves the budget ceiling never widens. Consuming it is
    /// stateful and therefore the node's obligation, not the verifier's, so
    /// this denial is the node's own and never carries a kernel reason.
    ReplayBudgetExhausted,
    /// A concurrent operation changed the exact workflow state.
    StateConflict,
    /// A bounded operation failed **before provider entry**.
    ///
    /// This is the only runtime failure that may claim a safe blind retry. A
    /// failure after provider entry must use [`Self::ProviderOutcomeUnknown`].
    Unavailable,
    /// A provider call failed after entry with no evidence of non-effect.
    ProviderOutcomeUnknown,
    Malformed,
    ProfileDisabled,
    /// A workflow or receipt reference does not name state this caller may read.
    UnknownReference,
    DisclosureDenied,
}

impl RuntimeFailure {
    /// Classifies one failed provider call by the exact boundary it crossed.
    #[must_use]
    pub const fn provider(boundary: ProviderBoundary) -> Self {
        match boundary {
            ProviderBoundary::BeforeEntry => Self::Unavailable,
            ProviderBoundary::AfterEntry => Self::ProviderOutcomeUnknown,
        }
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            // A denied disclosure is a denied authorization: the caller did not
            // present the authorization this receipt requires.
            Self::AuthorizationDenied(_) | Self::DisclosureDenied | Self::ReplayBudgetExhausted => {
                "core.authorization-denied"
            }
            Self::AuthorizationIndeterminate(_) => "core.authorization-indeterminate",
            Self::UnauthenticatedPrincipal => "core.unauthenticated-principal",
            Self::StateConflict => "core.runtime-conflict",
            Self::Unavailable => "core.runtime-unavailable",
            Self::ProviderOutcomeUnknown => "core.outcome-unknown",
            Self::Malformed => "core.malformed-input",
            // A profile this deployment did not enable is a configuration fact.
            Self::ProfileDisabled => "core.invalid-configuration",
            Self::UnknownReference => "core.forged-execution-reference",
        }
    }

    #[must_use]
    pub const fn retry(self) -> NextCall {
        match self {
            // Nothing was applied and the blocking condition may clear.
            Self::AuthorizationIndeterminate(_) | Self::Unavailable | Self::StateConflict => {
                NextCall::Backoff
            }
            Self::ProviderOutcomeUnknown => NextCall::Reconcile,
            _ => NextCall::Never,
        }
    }

    /// Projects the Rust-owned effect state this failure is entitled to claim.
    #[must_use]
    pub const fn effect(self) -> EffectState {
        match self {
            // Provider entry is the only place this node loses the proof of
            // non-effect. Every authorization outcome, including an
            // indeterminate one, is decided strictly before any effect.
            Self::ProviderOutcomeUnknown => EffectState::Possible,
            Self::AuthorizationDenied(_)
            | Self::AuthorizationIndeterminate(_)
            | Self::UnauthenticatedPrincipal
            | Self::ReplayBudgetExhausted
            | Self::StateConflict
            | Self::Unavailable
            | Self::Malformed
            | Self::ProfileDisabled
            | Self::UnknownReference
            | Self::DisclosureDenied => EffectState::NotApplied,
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
    /// Rust-owned effect axis. Never a locally invented word.
    pub effect: EffectState,
    pub retry: NextCall,
    pub updated_at: u64,
    pub receipt_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptSummary {
    pub receipt_id: String,
    pub profile: String,
    /// Rust-owned effect axis. Never a locally invented word: this field
    /// previously carried the free `String` `"succeeded"`.
    pub effect: EffectState,
    pub completed_at: u64,
    pub disclosure: &'static str,
}

pub trait AuthorityPort: Send + Sync {
    /// Creates authority from one exact production request.
    ///
    /// # Errors
    ///
    /// Returns a bounded runtime failure when authority cannot be issued.
    fn create(&self, request: &ProductionRequest) -> Result<Vec<u8>, RuntimeFailure>;

    /// Delegates authority from one exact production request.
    ///
    /// # Errors
    ///
    /// Returns a bounded runtime failure when attenuation or issuance fails.
    fn delegate(&self, request: &ProductionRequest) -> Result<Vec<u8>, RuntimeFailure>;

    /// Verifies authority from one exact production request.
    ///
    /// # Errors
    ///
    /// Returns a bounded runtime failure when verification is denied or
    /// indeterminate.
    fn verify(&self, request: &ProductionRequest) -> Result<Option<Vec<u8>>, RuntimeFailure>;
}

pub trait ExactProfilePort: Send + Sync {
    /// Executes one request through its exact-effect profile.
    ///
    /// # Errors
    ///
    /// Returns a bounded runtime failure when authorization or execution
    /// cannot complete safely.
    fn execute(&self, request: &ProductionRequest) -> Result<ProductionResponse, RuntimeFailure>;
}

pub trait WorkflowPort: Send + Sync {
    /// Resumes one recoverable workflow.
    ///
    /// # Errors
    ///
    /// Returns a bounded runtime failure when recovery cannot advance safely.
    fn resume(&self, request: &ProductionRequest) -> Result<ProductionResponse, RuntimeFailure>;

    /// Reads one workflow's public projection.
    ///
    /// # Errors
    ///
    /// Returns a bounded runtime failure when the workflow is unknown or
    /// unavailable.
    fn status(&self, reference: &RecoveryReference) -> Result<WorkflowProjection, RuntimeFailure>;
}

pub trait ReceiptPort: Send + Sync {
    /// Reads one bounded receipt summary.
    ///
    /// # Errors
    ///
    /// Returns a bounded runtime failure when the receipt is unknown or
    /// unavailable.
    fn summary(&self, receipt_id: &str) -> Result<ReceiptSummary, RuntimeFailure>;

    /// Produces one authorized receipt disclosure.
    ///
    /// # Errors
    ///
    /// Returns a bounded runtime failure when disclosure is denied or the
    /// receipt is unknown or unavailable.
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
                NextCall::Never,
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
        NextCall::Never,
        None,
        Some(value),
        Some(b"auths-authority-issued-v1".to_vec()),
    )
    .map_err(|_| RuntimeFailure::Malformed)
}

/// Projects a bounded runtime failure into the production response contract.
///
/// # Panics
///
/// Panics only if the closed failure projection no longer satisfies the
/// production response invariant.
#[must_use]
pub fn failure_response(error: RuntimeFailure) -> ProductionResponse {
    let kind = match error {
        RuntimeFailure::AuthorizationDenied(_)
        | RuntimeFailure::UnauthenticatedPrincipal
        | RuntimeFailure::ReplayBudgetExhausted
        | RuntimeFailure::Malformed
        | RuntimeFailure::ProfileDisabled
        | RuntimeFailure::UnknownReference
        | RuntimeFailure::DisclosureDenied => ClientOutcomeKind::Denied,
        RuntimeFailure::AuthorizationIndeterminate(_)
        | RuntimeFailure::StateConflict
        | RuntimeFailure::Unavailable
        | RuntimeFailure::ProviderOutcomeUnknown => ClientOutcomeKind::Indeterminate,
    };
    debug_assert!(
        !(error.effect() == EffectState::Possible && error.retry().asserts_non_effect()),
        "a possible effect may never be projected with a non-effect retry class"
    );
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

#[cfg(test)]
mod tests {
    use super::*;

    const EVERY_FAILURE: &[RuntimeFailure] = &[
        RuntimeFailure::AuthorizationDenied(DenialReason::UntrustedRoot),
        RuntimeFailure::AuthorizationIndeterminate(Requirement::ExternalFactUnavailable),
        RuntimeFailure::UnauthenticatedPrincipal,
        RuntimeFailure::ReplayBudgetExhausted,
        RuntimeFailure::StateConflict,
        RuntimeFailure::Unavailable,
        RuntimeFailure::ProviderOutcomeUnknown,
        RuntimeFailure::Malformed,
        RuntimeFailure::ProfileDisabled,
        RuntimeFailure::UnknownReference,
        RuntimeFailure::DisclosureDenied,
    ];

    #[test]
    fn a_failure_after_provider_entry_never_asserts_non_effect() {
        let failure = RuntimeFailure::provider(ProviderBoundary::AfterEntry);
        assert_eq!(failure.effect(), EffectState::Possible);
        assert_eq!(failure.code(), "core.outcome-unknown");
        assert!(!failure.retry().asserts_non_effect());
        assert_eq!(failure.retry(), NextCall::Reconcile);
        let response = failure_response(failure);
        assert_eq!(response.code(), Some("core.outcome-unknown"));
        assert!(!response.retry().asserts_non_effect());
    }

    #[test]
    fn only_a_failure_before_provider_entry_claims_not_applied() {
        let failure = RuntimeFailure::provider(ProviderBoundary::BeforeEntry);
        assert_eq!(failure.effect(), EffectState::NotApplied);
        assert_eq!(failure.code(), "core.runtime-unavailable");
        assert_eq!(failure.retry(), NextCall::Backoff);
        assert_ne!(
            RuntimeFailure::provider(ProviderBoundary::AfterEntry),
            failure,
            "the two provider boundaries must not collapse onto one failure"
        );
    }

    #[test]
    fn no_possible_effect_is_ever_paired_with_a_non_effect_retry_class() {
        for failure in EVERY_FAILURE.iter().copied() {
            if failure.effect() == EffectState::Possible {
                assert!(
                    !failure.retry().asserts_non_effect(),
                    "{failure:?} told the caller nothing happened"
                );
            }
            let response = failure_response(failure);
            assert_eq!(response.code(), Some(failure.code()));
            assert_eq!(response.retry(), failure.retry());
        }
    }

    /// Every code this node can put on the wire must exist in the product error
    /// registry. Eight of the ten it previously emitted did not:
    /// `authority.denied`, `authority.indeterminate`, `profile.disabled`,
    /// `workflow.unknown`, `receipt.unknown`, `receipt.disclosure-denied`,
    /// `provider.outcome-unknown`, and `verification.rejected`.
    #[test]
    fn every_wire_code_is_registered() {
        for failure in EVERY_FAILURE.iter().copied() {
            let code = failure.code();
            assert!(
                auths_errors::registry().any(|definition| definition.code == code),
                "{failure:?} puts the unregistered code {code:?} on the wire"
            );
        }
    }

    /// A registry definition states which retry and effect pairs the code is
    /// allowed to carry. The node's own projection must be one of them.
    #[test]
    fn every_wire_code_carries_a_registered_effect() {
        for failure in EVERY_FAILURE.iter().copied() {
            let code = failure.code();
            let definition = auths_errors::registry()
                .find(|definition| definition.code == code)
                .unwrap_or_else(|| panic!("{code} is registered"));
            let effect = match failure.effect() {
                EffectState::NotApplied => auths_errors::EffectState::NotApplied,
                EffectState::Possible => auths_errors::EffectState::Possible,
                EffectState::Applied => auths_errors::EffectState::Applied,
            };
            assert!(
                definition
                    .outcomes
                    .iter()
                    .any(|outcome| outcome.effect == effect),
                "{failure:?} claims an effect {code} does not allow"
            );
        }
    }

    /// The receipt summary must speak the same Rust-owned effect vocabulary as
    /// the workflow projection. It previously carried the invented
    /// `outcome: "succeeded"`.
    #[test]
    fn the_receipt_summary_speaks_only_the_rust_owned_effect_vocabulary() {
        let summary = ReceiptSummary {
            receipt_id: "a".repeat(64),
            profile: "auths.github.issue-address/1".into(),
            effect: EffectState::Applied,
            completed_at: 1,
            disclosure: "summary",
        };
        let value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&summary).unwrap()).unwrap();
        assert_eq!(value["effect"].as_str(), Some("applied"));
        assert!(value.get("outcome").is_none());
    }

    /// The public status projection must speak the one Rust-owned effect
    /// vocabulary. It previously carried a free `String` and shipped the locally
    /// invented words `"unknown"` and `"succeeded"`.
    #[test]
    fn the_status_projection_speaks_only_the_rust_owned_effect_vocabulary() {
        let tokens: Vec<String> = [
            EffectState::NotApplied,
            EffectState::Possible,
            EffectState::Applied,
        ]
        .into_iter()
        .map(|effect| {
            let projection = WorkflowProjection {
                reference: "reference".into(),
                profile: "auths.github.issue-address/1".into(),
                state: "outcome-unknown".into(),
                effect,
                retry: NextCall::Resume,
                updated_at: 1,
                receipt_id: None,
            };
            serde_json::from_str::<serde_json::Value>(&serde_json::to_string(&projection).unwrap())
                .unwrap()["effect"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
        assert_eq!(tokens, ["not-applied", "possible", "applied"]);
        assert!(
            !tokens
                .iter()
                .any(|token| token == "unknown" || token == "succeeded")
        );
    }
}
