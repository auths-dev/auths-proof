//! Native-verified, digest-bound single-host execution coordinator.

// Explicit matches keep each verification and transport failure mapped to its
// distinct public stage; `let...else` would obscure those boundary decisions.
#![allow(clippy::manual_let_else)]

use crate::transport::{GatewayHttpTransport, WriteTransportOutcome};
use crate::{
    ClosedProviderRequest, CompiledRecipe, FileGatewayAttemptStore, GatewayConnectionDescriptor,
};
use auths_connections::{
    ConnectionAlias, ConnectionCredentialStore, ConnectionProfile, ConnectionState,
    PersistentCredentialStore, ProviderKind, SecretBytes,
};
use auths_model::VerificationDecision;
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_profile_api::ActionProfile;
use auths_profile_mcp::McpProfile;
use auths_stores::PersistentConnectionStore;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;

const MAX_PROOF_BYTES: usize = 4 * 1024 * 1024;
const MAX_ACTION_BYTES: usize = 64 * 1024;
const MAX_CONTEXT_BYTES: usize = 4 * 1024 * 1024;

/// Installation failure before an application socket can be served.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum GatewayEngineConfigurationError {
    /// Independently installed trust is missing or unbounded.
    #[error("gateway trusted context is missing or unbounded")]
    InvalidTrust,
    /// The installed recipe differs from the operator-approved digest.
    #[error("gateway recipe approval digest mismatch")]
    UnapprovedRecipe,
}

/// Closed, secret-free application result. A recorded response or matching
/// read-back does not prove provider effect or exclusive causation.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum GatewaySubmitResult {
    /// Native proof verification denied the action.
    Denied { code: String },
    /// Native proof verification could not reach an authorized conclusion.
    Indeterminate { code: String },
    /// Proof was authorized but this operation did not enter write transport.
    NotEntered { code: String },
    /// Write entry/effect is ambiguous; no automatic retry is permitted.
    Unknown,
    /// A complete bounded HTTP response exists, but no read-back was recorded.
    ResponseRecorded { status: u16 },
    /// A separately completed read-back compared exact state; not causation.
    Observed { status: u16, matched: bool },
}

/// One immutable installed operation and independently provisioned trust.
/// Connection state and generation are rechecked on every submission.
pub struct GatewayEngine {
    recipe: CompiledRecipe,
    trusted_context_cbor: Vec<u8>,
    provider: ProviderKind,
    alias: ConnectionAlias,
    workload_id: String,
    profile: ConnectionProfile,
    connections: PersistentConnectionStore,
    credentials: PersistentCredentialStore,
    attempts: FileGatewayAttemptStore,
    administrative_gate: RwLock<()>,
}

impl GatewayEngine {
    /// Constructs an engine only for an exact operator-approved recipe digest.
    /// The caller must be the separately deployed gateway, never the app.
    ///
    /// # Errors
    /// Refuses missing trust or a changed recipe.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        recipe: CompiledRecipe,
        approved_digest: [u8; 32],
        trusted_context_cbor: Vec<u8>,
        provider: ProviderKind,
        alias: ConnectionAlias,
        workload_id: String,
        profile: ConnectionProfile,
        connections: PersistentConnectionStore,
        credentials: PersistentCredentialStore,
        attempts: FileGatewayAttemptStore,
    ) -> Result<Self, GatewayEngineConfigurationError> {
        if trusted_context_cbor.is_empty() || trusted_context_cbor.len() > MAX_CONTEXT_BYTES {
            return Err(GatewayEngineConfigurationError::InvalidTrust);
        }
        if *recipe.digest() != approved_digest {
            return Err(GatewayEngineConfigurationError::UnapprovedRecipe);
        }
        Ok(Self {
            recipe,
            trusted_context_cbor,
            provider,
            alias,
            workload_id,
            profile,
            connections,
            credentials,
            attempts,
            administrative_gate: RwLock::new(()),
        })
    }

    /// Disables new submissions after all already-entered submissions finish.
    /// The operator-only service channel must be the sole caller.
    ///
    /// # Errors
    /// A failed durable transition never reports disabled.
    pub async fn disable_connection(&self) -> Result<(), &'static str> {
        let _guard = self.administrative_gate.write().await;
        let current = self
            .connections
            .load(&self.provider, &self.alias)
            .map_err(|_| "gateway.admin.connection-unavailable")?
            .ok_or("gateway.admin.connection-unavailable")?;
        if current.state() != ConnectionState::Active {
            return Err("gateway.admin.connection-not-active");
        }
        let next = current
            .generation()
            .get()
            .checked_add(1)
            .and_then(std::num::NonZeroU64::new)
            .ok_or("gateway.admin.generation-exhausted")?;
        let commitment = self
            .credentials
            .advance_generation(current.connection_id(), current.generation(), next)
            .map_err(|_| "gateway.admin.credential-unavailable")?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "gateway.admin.clock-unavailable")?
            .as_secs();
        self.connections
            .transition_state(
                &self.provider,
                &self.alias,
                current.generation(),
                ConnectionState::Disabled,
                *commitment.as_bytes(),
                now,
            )
            .map_err(|_| "gateway.admin.transition-unavailable")?;
        Ok(())
    }

    /// Rotates the operator-held secret to a new generation, retaining the
    /// previous generation for unresolved attempts. The admin channel must be
    /// unavailable to the application identity.
    ///
    /// # Errors
    /// A failed durable transition never reports rotation complete.
    pub async fn rotate_connection(&self, secret: SecretBytes) -> Result<(), &'static str> {
        let _guard = self.administrative_gate.write().await;
        let current = self
            .connections
            .load(&self.provider, &self.alias)
            .map_err(|_| "gateway.admin.connection-unavailable")?
            .ok_or("gateway.admin.connection-unavailable")?;
        if current.state() != ConnectionState::Active {
            return Err("gateway.admin.connection-not-active");
        }
        let next = current
            .generation()
            .get()
            .checked_add(1)
            .and_then(std::num::NonZeroU64::new)
            .ok_or("gateway.admin.generation-exhausted")?;
        let commitment = self
            .credentials
            .replace(current.connection_id(), current.generation(), next, secret)
            .await
            .map_err(|_| "gateway.admin.credential-unavailable")?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "gateway.admin.clock-unavailable")?
            .as_secs();
        let replacement = current
            .rotated(
                current.descriptor().to_vec(),
                *current.account_commitment(),
                *commitment.as_bytes(),
                timestamp,
            )
            .map_err(|_| "gateway.admin.transition-unavailable")?;
        self.connections
            .replace(current.generation(), replacement)
            .map_err(|_| "gateway.admin.transition-unavailable")
    }

    /// Revokes new entry after in-flight submissions complete, retaining a
    /// terminal record and withholding every new credential lease.
    ///
    /// # Errors
    /// A failed durable transition never reports revocation complete.
    pub async fn revoke_connection(&self) -> Result<(), &'static str> {
        let _guard = self.administrative_gate.write().await;
        let current = self
            .connections
            .load(&self.provider, &self.alias)
            .map_err(|_| "gateway.admin.connection-unavailable")?
            .ok_or("gateway.admin.connection-unavailable")?;
        if current.state() == ConnectionState::Revoked {
            return Err("gateway.admin.connection-revoked");
        }
        let next = current
            .generation()
            .get()
            .checked_add(1)
            .and_then(std::num::NonZeroU64::new)
            .ok_or("gateway.admin.generation-exhausted")?;
        let commitment = self
            .credentials
            .advance_generation(current.connection_id(), current.generation(), next)
            .map_err(|_| "gateway.admin.credential-unavailable")?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "gateway.admin.clock-unavailable")?
            .as_secs();
        self.connections
            .transition_state(
                &self.provider,
                &self.alias,
                current.generation(),
                ConnectionState::Revoked,
                *commitment.as_bytes(),
                timestamp,
            )
            .map_err(|_| "gateway.admin.transition-unavailable")?;
        let _ = self
            .credentials
            .revoke(current.connection_id(), current.generation())
            .await;
        let _ = self.credentials.revoke(current.connection_id(), next).await;
        Ok(())
    }

    /// Verifies and attempts one exact action. Only proof and action bytes are
    /// accepted from the application; trust, recipe, connection, and credential
    /// come from the operator's installation.
    pub async fn submit(&self, proof_cbor: &[u8], action_cbor: &[u8]) -> GatewaySubmitResult {
        let (request, action_commitment) = match self.verify_and_close(proof_cbor, action_cbor) {
            Ok(value) => value,
            Err(result) => return result,
        };
        let _guard = self.administrative_gate.read().await;
        let binding = match self.connections.resolve(
            &self.provider,
            Some(&self.alias),
            &self.workload_id,
            &self.profile,
        ) {
            Ok(value) => value,
            Err(_) => return not_entered("gateway.connection.unavailable"),
        };
        let descriptor = match GatewayConnectionDescriptor::from_binding(&binding, &self.recipe) {
            Ok(value) => value,
            Err(_) => return not_entered("gateway.connection.recipe-mismatch"),
        };
        if self
            .connections
            .reread_before_lease(&binding, &self.workload_id, &self.profile)
            .is_err()
        {
            return not_entered("gateway.connection.changed");
        }
        let transport = match GatewayHttpTransport::prepare(&self.recipe, descriptor.credential()) {
            Ok(value) => value,
            Err(_) => return not_entered("gateway.transport.preparation"),
        };
        let claim = match self
            .attempts
            .claim(&request, action_commitment, *self.recipe.digest())
        {
            Ok(value) => value,
            Err(crate::GatewayAttemptError::Replay) => {
                return not_entered("gateway.attempt.replay");
            }
            Err(_) => return not_entered("gateway.attempt.unavailable"),
        };
        let lease = match self
            .credentials
            .lease_secret(&binding, Instant::now() + Duration::from_secs(30))
            .await
        {
            Ok(value) => value,
            Err(_) => return checkpoint_not_entered(claim),
        };
        let write = match transport.write(&request, &lease) {
            Ok(value) => value,
            Err(_) => return checkpoint_not_entered(claim),
        };
        match write {
            WriteTransportOutcome::Unknown => {
                let _ = claim.record_unknown();
                GatewaySubmitResult::Unknown
            }
            WriteTransportOutcome::ResponseRecorded { status, digest } => {
                let recorded = match claim.record_response(status, digest) {
                    Ok(value) => value,
                    Err(_) => return GatewaySubmitResult::Unknown,
                };
                let Some(observation) = request.observation() else {
                    return GatewaySubmitResult::ResponseRecorded { status };
                };
                let Some(matched) = transport.observe(observation, &lease) else {
                    return GatewaySubmitResult::ResponseRecorded { status };
                };
                match recorded.record_observation(matched) {
                    Ok(_) => GatewaySubmitResult::Observed { status, matched },
                    Err(_) => GatewaySubmitResult::ResponseRecorded { status },
                }
            }
        }
    }

    fn verify_and_close(
        &self,
        proof_cbor: &[u8],
        action_cbor: &[u8],
    ) -> Result<(ClosedProviderRequest, [u8; 32]), GatewaySubmitResult> {
        if proof_cbor.is_empty()
            || proof_cbor.len() > MAX_PROOF_BYTES
            || action_cbor.is_empty()
            || action_cbor.len() > MAX_ACTION_BYTES
        {
            return Err(GatewaySubmitResult::Indeterminate {
                code: "gateway.submit.invalid-size".to_owned(),
            });
        }
        let raw_key = match auths_raw_key::RawKeyMethod::new() {
            Ok(value) => value,
            Err(_) => return Err(indeterminate_registry()),
        };
        let did_key = match auths_did_key::DidKeyMethod::new() {
            Ok(value) => value,
            Err(_) => return Err(indeterminate_registry()),
        };
        let did_keri = match auths_did_keri::DidKeriMethod::new() {
            Ok(value) => value,
            Err(_) => return Err(indeterminate_registry()),
        };
        let ed25519 = match auths_signature::Ed25519Suite::new() {
            Ok(value) => value,
            Err(_) => return Err(indeterminate_registry()),
        };
        let p256 = match auths_signature::P256Sha256Suite::new() {
            Ok(value) => value,
            Err(_) => return Err(indeterminate_registry()),
        };
        let methods: [&dyn PrincipalMethod; 3] = [&raw_key, &did_key, &did_keri];
        let suites: [&dyn SignatureSuite; 2] = [&ed25519, &p256];
        let registries = match auths_registries::ImmutableRegistries::new(&methods, &suites) {
            Ok(value) => value,
            Err(_) => return Err(indeterminate_registry()),
        };
        let sealed = match auths_verifier::verify_v1_sealed(
            proof_cbor,
            action_cbor,
            &self.trusted_context_cbor,
            &registries,
        ) {
            Ok(value) => value,
            Err(_) => {
                return Err(GatewaySubmitResult::Indeterminate {
                    code: "gateway.verify.invalid-input".to_owned(),
                });
            }
        };
        let Some(action) = sealed.action() else {
            let code = sealed.portable().code().code().to_owned();
            return Err(match sealed.portable().decision() {
                VerificationDecision::Denied => GatewaySubmitResult::Denied { code },
                VerificationDecision::Authorized | VerificationDecision::Indeterminate => {
                    GatewaySubmitResult::Indeterminate { code }
                }
            });
        };
        let command = match McpProfile.decode_verified(action) {
            Ok(value) => value,
            Err(_) => return Err(not_entered("gateway.action.projection")),
        };
        let request = match self.recipe.closed_request(&command) {
            Ok(value) => value,
            Err(error) => return Err(not_entered(error.code())),
        };
        let canonical = match auths_codec::encode_canonical_action(action.canonical_action()) {
            Ok(value) => value,
            Err(_) => return Err(not_entered("gateway.action.commitment")),
        };
        let action_commitment =
            match auths_codec::domain_commitment("auths.canonical-action.v1", &canonical) {
                Ok(value) => *value.as_bytes(),
                Err(_) => return Err(not_entered("gateway.action.commitment")),
            };
        Ok((request, action_commitment))
    }
}

fn indeterminate_registry() -> GatewaySubmitResult {
    GatewaySubmitResult::Indeterminate {
        code: "gateway.verify.registry-unavailable".to_owned(),
    }
}

fn not_entered(code: &'static str) -> GatewaySubmitResult {
    GatewaySubmitResult::NotEntered {
        code: code.to_owned(),
    }
}

fn checkpoint_not_entered(claim: crate::ClaimedGatewayAttempt) -> GatewaySubmitResult {
    match claim.record_not_entered() {
        Ok(_) => not_entered("gateway.credential.unavailable"),
        Err(_) => GatewaySubmitResult::Unknown,
    }
}
