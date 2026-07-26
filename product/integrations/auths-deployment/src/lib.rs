//! Replay- and budget-safe internal deployment reference integration.

#![forbid(unsafe_code)]

use auths_enforcement::{CommandExecutor, Enforcement, EnforcementDecision, EnforcementError};
use auths_sdk::{
    DomainCommand, DomainProfile, Explanation, RequestContext, Verifier,
    model::{ActionId, ContextDigest, Digest, PlanId},
};
use thiserror::Error;

/// Atomic state-gate outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateClaim {
    /// State was atomically reserved for this execution.
    Claimed,
    /// The challenge or budget was already consumed.
    Rejected,
    /// The state store could not make a trustworthy atomic decision.
    Unavailable,
}

/// Atomic challenge-consumption port.
pub trait ReplayStore: Send + Sync {
    /// Claims an authorized request challenge exactly once.
    fn claim(&self, challenge: [u8; 32], evaluation_time: u64) -> GateClaim;
}

/// Atomic deployment-budget port.
pub trait DeploymentBudgetStore: Send + Sync {
    /// Claims the verified action's blast radius.
    fn claim(&self, action: ActionId, blast_radius: u64) -> GateClaim;
}

/// Privacy-preserving authorized decision inputs for receipt/audit systems.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedDecision {
    /// Digest of the exact proof bundle.
    pub proof_digest: Digest,
    /// Digest of the public verifier context.
    pub context_digest: ContextDigest,
    /// Identifier of the satisfied authorization plan.
    pub plan_id: PlanId,
    /// Identifier of the exact signed action.
    pub action_id: ActionId,
    /// Deterministic kernel work charged.
    pub work_units: u64,
}

/// Audit/receipt port called before application execution.
pub trait DeploymentAuditSink: Send + Sync {
    /// Records authorized decision inputs without proof or action secrets.
    fn authorized(&self, decision: AuthorizedDecision);
}

/// Audit sink for integrations that deliberately disable export.
pub struct NoopDeploymentAuditSink;

impl DeploymentAuditSink for NoopDeploymentAuditSink {
    fn authorized(&self, _decision: AuthorizedDecision) {}
}

/// Complete internal deployment enforcement boundary.
pub struct DeploymentService<E, R, B, A> {
    enforcement: Enforcement<DomainProfile<auths_sdk::DeploymentAction>>,
    executor: E,
    replay: R,
    budgets: B,
    audit: A,
}

impl<E, R, B, A> DeploymentService<E, R, B, A>
where
    E: CommandExecutor<DomainCommand<auths_sdk::DeploymentAction>>,
    R: ReplayStore,
    B: DeploymentBudgetStore,
    A: DeploymentAuditSink,
{
    /// Constructs a deployment boundary from explicit local dependencies.
    #[must_use]
    pub fn new(verifier: Verifier, executor: E, replay: R, budgets: B, audit: A) -> Self {
        Self {
            enforcement: Enforcement::new(verifier, DomainProfile::default()),
            executor,
            replay,
            budgets,
            audit,
        }
    }

    /// Verifies, state-gates, audits, and executes one deployment request.
    ///
    /// `deployment_json` must be the bytes derived from the real request. The
    /// executor receives only the deployment command decoded from sealed
    /// verifier output, never these original untrusted bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed integration/profile failure or application executor
    /// failure. Protocol and state-gate outcomes remain ordinary values.
    pub fn execute(
        &self,
        proof_cbor: &[u8],
        deployment_json: &[u8],
        request: &RequestContext,
    ) -> Result<DeploymentOutcome<E::Output>, DeploymentError<E::Error>> {
        let decision = self
            .enforcement
            .verify(proof_cbor, deployment_json, request)?;
        let authorized = match decision {
            EnforcementDecision::Authorized(authorized) => authorized,
            EnforcementDecision::Denied(explanation) => {
                return Ok(DeploymentOutcome::Denied(explanation));
            }
            EnforcementDecision::Indeterminate(explanation) => {
                return Ok(DeploymentOutcome::Indeterminate(explanation));
            }
        };
        let Some(action_id) = authorized.verified().action_ids().first().copied() else {
            return Ok(DeploymentOutcome::StateUnavailable);
        };
        match self.replay.claim(
            *request.challenge().as_bytes(),
            request.evaluation_time().get(),
        ) {
            GateClaim::Claimed => {}
            GateClaim::Rejected => return Ok(DeploymentOutcome::ReplayRejected),
            GateClaim::Unavailable => return Ok(DeploymentOutcome::StateUnavailable),
        }
        match self
            .budgets
            .claim(action_id, authorized.command().action().blast_radius())
        {
            GateClaim::Claimed => {}
            GateClaim::Rejected => return Ok(DeploymentOutcome::BudgetRejected),
            GateClaim::Unavailable => return Ok(DeploymentOutcome::StateUnavailable),
        }
        self.audit.authorized(AuthorizedDecision {
            proof_digest: authorized.verified().proof_digest(),
            context_digest: authorized.verified().context_digest(),
            plan_id: authorized.verified().plan_id(),
            action_id,
            work_units: authorized.verified().work_units(),
        });
        Ok(DeploymentOutcome::Executed(
            self.executor
                .execute(authorized.command())
                .map_err(DeploymentError::Executor)?,
        ))
    }
}

/// Deployment request outcome.
pub enum DeploymentOutcome<T> {
    /// Verified, state-gated command completed.
    Executed(T),
    /// Available facts denied authority; nothing executed.
    Denied(Explanation),
    /// Required trusted facts were unavailable; nothing executed.
    Indeterminate(Explanation),
    /// Challenge was unknown, expired, or already consumed.
    ReplayRejected,
    /// Stateful blast-radius budget was exhausted.
    BudgetRejected,
    /// Replay or budget state could not make an atomic decision.
    StateUnavailable,
}

/// Deployment integration or executor failure.
#[derive(Debug, Error)]
pub enum DeploymentError<E> {
    /// Auths enforcement/profile integration failed.
    #[error("deployment authorization integration failed: {0}")]
    Enforcement(#[from] EnforcementError),
    /// Application deployment executor failed.
    #[error("authorized deployment execution failed: {0}")]
    Executor(E),
}
