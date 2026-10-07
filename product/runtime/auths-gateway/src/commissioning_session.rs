//! Authenticated operator-only commissioning of the exact shipped driver.
//! Ordinary `GatewayEngine::submit` never constructs or selects this session.

use super::{EngineIo, GatewayEngine, GatewaySubmitResult, VerifiedCommand};
use crate::commissioning_budget::{CommissioningBudget, CommissioningBudgetRefusal};
use crate::commissioning_floor::CommissioningFloor;
use crate::submit::{self, SubmitContext};
use auths_model::PrincipalId;
use auths_recipe_qualification::{
    BoundedText, CommissioningInputs, CommissioningRefusal, CommissioningRequest,
    LifecycleStoreKind, QualificationTuple, Sha256Digest, VerifiedCommissioningPermit,
};
use sha2::{Digest as _, Sha256};
use std::{
    path::Path,
    sync::{Arc, OnceLock},
    time::Instant,
};

/// Independent operator inputs. The installed root, target and clock come
/// from the engine's required qualification gate, never from these inputs.
pub struct CommissioningSessionInputs<'a> {
    /// Closed permit, purpose certificate and authenticated revocation list.
    pub artifacts: CommissioningInputs<'a>,
    /// Signed operator attestation for this exact production installation.
    pub operator_attestation: &'a [u8],
    /// Run/attempt identity established by the protected operator workflow.
    pub protected_run: &'a BoundedText<256>,
    /// Exact reviewed resource file, SHA-256 bound by the permit; at most 64 KiB.
    pub resources: &'a [u8],
    /// Private host directory retained outside database restores.
    pub floor_directory: &'a Path,
}

/// SHA-256 of the normalized principal identifier's UTF-8 bytes.
/// Only actors sealed by native verification are compared at runtime.
#[must_use]
pub fn commissioning_principal_sha256(principal: &PrincipalId) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(principal.as_str().as_bytes()).into())
}

/// A sealed operator capability tied to one engine and reviewed protected run.
/// It grants no qualification verdict, readiness state or ordinary app access.
/// Every submission uses native proof verification and the same ordered driver.
pub struct CommissioningSession<'a> {
    engine: &'a GatewayEngine,
    authority: VerifiedCommissioningPermit,
    tuple: QualificationTuple,
    protected_run: BoundedText<256>,
    resources_sha256: Sha256Digest,
    budget: Arc<CommissioningBudget>,
    floor: CommissioningFloor,
}

/// Obtained only from exact authorized branches and the closed verified request.
pub(super) struct CommissionedAction {
    principal_sha256: Sha256Digest,
    canonical_action_sha256: Sha256Digest,
}

impl GatewayEngine {
    /// Authenticates a private commissioning session against installed trust.
    /// This does not initialize capacity or alter the ordinary application gate.
    /// The caller must be the isolated operator process, not an application.
    ///
    /// # Errors
    /// Refuses missing production identity, invalid operator/permit signatures,
    /// time/revocation faults and every changed installed/run/resource binding.
    pub fn commissioning_session(
        &self,
        inputs: &CommissioningSessionInputs<'_>,
    ) -> Result<CommissioningSession<'_>, &'static str> {
        let (root, tuple) = self
            .qualification
            .commissioning_target()
            .ok_or("gateway.commissioning.unavailable")?;
        if tuple.target.store_kind != LifecycleStoreKind::PostgresqlV1
            || tuple.target.store_schema.as_str() != crate::POSTGRES_STORE_SCHEMA
            || !tuple.target.credential_store_kind.is_production()
            || tuple.compiled_recipe_sha256.as_bytes() != self.recipe.digest()
            || inputs.resources.is_empty()
            || inputs.resources.len() > 64 * 1024
        {
            return Err("gateway.commissioning.binding-mismatch");
        }
        let (now, trusted) = self.qualification.commissioning_time();
        if !trusted {
            return Err("gateway.commissioning.clock-untrusted");
        }
        let expected = crate::OperatorInstallation {
            recipe_digest: self.recipe.digest_hex(),
            profile_lock_sha256: tuple.profile_lock_sha256.to_hex(),
            trusted_context_sha256: self.trusted_context_sha256.to_hex(),
            provider: self.connection.provider().as_str().to_owned(),
            alias: self.connection.alias().as_str().to_owned(),
            deployment: "production".to_owned(),
        };
        let operator =
            crate::verify_operator_attestation(inputs.operator_attestation, &expected, now)
                .map_err(crate::OperatorAttestationError::code)?;
        self.check_principal_separation(Some(&operator))
            .map_err(crate::PrincipalSeparationError::code)?;
        let authority = VerifiedCommissioningPermit::verify(root, &inputs.artifacts)
            .map_err(|_| "gateway.commissioning.unavailable")?;
        self.qualification.remember_commissioning(&authority);
        let binding = &authority.permit().body().statement.binding;
        let resources_sha256 = Sha256Digest::from_bytes(Sha256::digest(inputs.resources).into());
        // The signature binds the candidate source revision to the executable
        // digest independently derived by the installation's tuple. There is no
        // caller-supplied source-commit override or runtime build-mode switch.
        let request = CommissioningRequest {
            source_commit: &binding.source_commit,
            tuple,
            protected_run: inputs.protected_run,
            principal_sha256: binding.principal_sha256,
            trusted_context_sha256: self.trusted_context_sha256,
            resources_sha256,
            canonical_action_sha256: binding.allowed_actions[0],
        };
        authority
            .evaluate(&request, now, trusted, &self.qualification.verifier_state())
            .map_err(permit_code)?;
        let budget = Arc::new(
            CommissioningBudget::new(self.attempts.store(), binding.clone())
                .map_err(CommissioningBudgetRefusal::code)?,
        );
        let floor = CommissioningFloor::new(inputs.floor_directory.to_owned(), binding.clone())
            .map_err(CommissioningBudgetRefusal::code)?;
        Ok(CommissioningSession {
            engine: self,
            tuple: tuple.clone(),
            protected_run: inputs.protected_run.clone(),
            resources_sha256,
            authority,
            budget,
            floor,
        })
    }
}

impl CommissioningSession<'_> {
    /// Fresh authenticated setup registers shared capacity once and retains its
    /// floor before returning. Existing consumption/trust is never reset.
    /// Startup and renewal use `submit`, which never initializes missing state.
    ///
    /// # Errors
    /// Refuses unavailable, changed, rolled-back or unsafe permanent state.
    pub async fn initialize_budget(&self) -> Result<(), &'static str> {
        let budget = self.budget.clone();
        let floor = self.floor.clone();
        let authority = self.authority.clone();
        let state = self.engine.qualification.verifier_state();
        let tuple = self.tuple.clone();
        let protected_run = self.protected_run.clone();
        let resources_sha256 = self.resources_sha256;
        let trusted_context_sha256 = self.engine.trusted_context_sha256;
        let (now, _) = self.engine.qualification.commissioning_time();
        tokio::task::spawn_blocking(move || {
            floor.initialize(&budget.initialize()?)?;
            let binding = &authority.permit().body().statement.binding;
            let request = CommissioningRequest {
                source_commit: &binding.source_commit,
                tuple: &tuple,
                protected_run: &protected_run,
                principal_sha256: binding.principal_sha256,
                trusted_context_sha256,
                resources_sha256,
                canonical_action_sha256: binding.allowed_actions[0],
            };
            // Setup records authenticated trust without permitting a lease.
            // Deliberately withholding clock trust makes this a denied update
            // with zero consumption; the shared record and retained floor
            // nevertheless remember the root-signed list before acknowledgement.
            floor.claim(&budget, &authority, &request, now, false, &state)?;
            Ok(())
        })
        .await
        .map_err(|_| "gateway.commissioning.store-unavailable")?
        .map_err(CommissioningBudgetRefusal::code)
    }

    /// Submits proof and canonical action as the authenticated operator.
    /// No proof/request can select this method through an ordinary app socket.
    /// The exact actor and action must match the finite signed permit; before
    /// every custody acquisition an atomic lifetime unit and host floor commit.
    pub async fn submit(&self, proof: &[u8], action: &[u8]) -> GatewaySubmitResult {
        let io = EngineIo {
            engine: self.engine,
            proof,
            action,
            started: Instant::now(),
            prepared: OnceLock::new(),
            commissioning: Some(self),
            commissioned_action: OnceLock::new(),
            commissioning_refusal: OnceLock::new(),
        };
        submit::run(
            &SubmitContext {
                recipe: &self.engine.recipe,
                attempts: &self.engine.attempts,
                context: &self.engine.trusted_context,
                observer: self.engine.observer.as_ref(),
            },
            &io,
        )
        .await
    }

    pub(super) fn bind_verified(
        &self,
        command: &VerifiedCommand,
    ) -> Result<CommissionedAction, &'static str> {
        let [actor] = command.actors.as_slice() else {
            return Err("gateway.commissioning.binding-mismatch");
        };
        let action = CommissionedAction {
            principal_sha256: commissioning_principal_sha256(actor),
            canonical_action_sha256: Sha256Digest::from_bytes(*command.request.action_commitment()),
        };
        self.check(&action)?;
        Ok(action)
    }

    pub(super) fn check(&self, action: &CommissionedAction) -> Result<(), &'static str> {
        let (now, trusted) = self.engine.qualification.commissioning_time();
        self.authority
            .evaluate(
                &self.request(action),
                now,
                trusted,
                &self.engine.qualification.verifier_state(),
            )
            .map_err(permit_code)
    }

    fn request<'a>(&'a self, action: &CommissionedAction) -> CommissioningRequest<'a> {
        CommissioningRequest {
            source_commit: &self
                .authority
                .permit()
                .body()
                .statement
                .binding
                .source_commit,
            tuple: &self.tuple,
            protected_run: &self.protected_run,
            principal_sha256: action.principal_sha256,
            trusted_context_sha256: self.engine.trusted_context_sha256,
            resources_sha256: self.resources_sha256,
            canonical_action_sha256: action.canonical_action_sha256,
        }
    }

    pub(super) async fn claim(&self, action: &CommissionedAction) -> Result<(), &'static str> {
        let budget = self.budget.clone();
        let floor = self.floor.clone();
        let authority = self.authority.clone();
        let tuple = self.tuple.clone();
        let protected_run = self.protected_run.clone();
        let principal_sha256 = action.principal_sha256;
        let canonical_action_sha256 = action.canonical_action_sha256;
        let trusted_context_sha256 = self.engine.trusted_context_sha256;
        let resources_sha256 = self.resources_sha256;
        let state = self.engine.qualification.verifier_state();
        let (now, trusted) = self.engine.qualification.commissioning_time();
        let update = tokio::task::spawn_blocking(move || {
            let request = CommissioningRequest {
                source_commit: &authority.permit().body().statement.binding.source_commit,
                tuple: &tuple,
                protected_run: &protected_run,
                principal_sha256,
                trusted_context_sha256,
                resources_sha256,
                canonical_action_sha256,
            };
            floor.claim(&budget, &authority, &request, now, trusted, &state)
        })
        .await
        .map_err(|_| "gateway.commissioning.store-unavailable")?
        .map_err(CommissioningBudgetRefusal::code)?;
        match update.refusal() {
            Some(refusal) => Err(refusal.code()),
            // A queued host lock or durable store write can outlast the permit
            // window. Capacity stays spent, but custody requires fresh time.
            None => self.check(action),
        }
    }
}

fn permit_code(refusal: CommissioningRefusal) -> &'static str {
    CommissioningBudgetRefusal::Permit(refusal).code()
}

#[cfg(test)]
#[path = "commissioning_session/tests.rs"]
mod tests;
