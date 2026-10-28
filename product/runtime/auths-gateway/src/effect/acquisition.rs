//! Independently verified compilation of a bounded recovery acquisition.
//! This constructs the shared bound effect, not an entry permit. The journal
//! must later account and fence the acquisition separately from its source.

use super::*;
use auths_profile_api::ActionProfile as _;
use auths_profile_mcp::{McpProfile, McpToolCall};
#[cfg(unix)]
use serde_json::Map;
use serde_json::{Value, json};

/// Reserved native read-only operation; a mutation tool is never accepted here.
pub const RECOVERY_READ_TOOL: &str = "auths_gateway_recovery_read_v1";
/// Total observation entries permitted for one retained source effect.
pub const MAX_RECOVERY_ATTEMPTS: u64 = 16;
/// The bound evidence freshness contract; signed times are not refreshed.
pub const MAX_RECOVERY_EVIDENCE_AGE_SECONDS: u64 = 30;

/// Protected, closed target loaded from a validated original journal record.
/// There is no public constructor or deserializer. This is provenance data,
/// not the writer's authority and not permission to lease or contact a provider.
#[derive(Clone)]
pub struct RecoveryReadTarget {
    source: EffectBinding,
    request: crate::ClosedObservationRequest,
    echo: Option<String>,
}

impl fmt::Debug for RecoveryReadTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryReadTarget { private: [redacted] }")
    }
}

impl RecoveryReadTarget {
    pub(crate) fn from_journal(
        source: EffectBinding,
        request: crate::ClosedObservationRequest,
        echo: Option<String>,
    ) -> Result<Self, EffectBindingError> {
        if !matches!(source.wire.protocol, Protocol::Mutation { .. })
            || source.wire.scope != Scope::Unscoped
            || !(1..=65_536).contains(&request.maximum_response_bytes())
        {
            return Err(EffectBindingError::Invalid);
        }
        let target = Self {
            source,
            request,
            echo,
        };
        canonical(&target.contract())?;
        Ok(target)
    }

    fn read_wire(&self) -> ReadWire<'_> {
        ReadWire {
            url: self.request.url(),
            headers: self
                .request
                .headers()
                .iter()
                .map(|header| (header.name(), header.value()))
                .collect(),
            maximum_response_bytes: self.request.maximum_response_bytes(),
        }
    }

    fn contract(&self) -> Value {
        json!({
            "schema": "auths.gateway-recovery-read/1",
            "source_effect": hex::encode(self.source.id().as_bytes()),
            "source_operation": self.source.wire.operation,
            "request": self.read_wire(),
            "json_pointer": self.request.json_pointer(),
            "expected": self.request.expected(),
            "echo_pointer": self.request.echo_pointer(),
            "echo": self.echo,
            "maximum_attempts": MAX_RECOVERY_ATTEMPTS,
            "maximum_transport_seconds": 15,
            "maximum_evidence_age_seconds": MAX_RECOVERY_EVIDENCE_AGE_SECONDS,
            "disclosure": "none",
        })
    }

    fn binding(
        &self,
        installed: &EffectInstallation<'_>,
        operation: &LogicalOperationId,
        action_commitment: [u8; 32],
        native_authority: [u8; 32],
    ) -> Result<EffectBinding, GatewaySubmitResult> {
        let invalid = || not_entered("gateway.acquisition.binding");
        let connection = Zeroizing::new(
            installed
                .connection
                .to_canonical_cbor()
                .map_err(|_| invalid())?,
        );
        let connection_commitment =
            commitment("auths.effect-installation/1", &connection).map_err(|_| invalid())?;
        if self.source.wire.connection != connection_commitment
            || self.source.wire.credential_generation
                != installed.connection.credential_generation().get()
        {
            return Err(invalid());
        }
        let maximum =
            u64::try_from(self.request.maximum_response_bytes()).map_err(|_| invalid())?;
        let reservations = [
            (Unit::AcquisitionCount, 1, MAX_RECOVERY_ATTEMPTS),
            (
                Unit::ResponseBytes,
                maximum,
                MAX_RECOVERY_ATTEMPTS * maximum,
            ),
        ]
        .into_iter()
        .map(|(unit, amount, ceiling)| {
            Ok(Reservation {
                key: commitment(
                    "auths.recovery-capacity/1",
                    &canonical(&(self.source.id().as_bytes(), unit))?,
                )?,
                unit,
                amount,
                ceiling,
                window: ReservationWindow::SourceLifetime,
            })
        })
        .collect::<Result<Vec<_>, EffectBindingError>>()
        .map_err(|_| invalid())?;
        let mut reservations = reservations;
        reservations.sort_by_key(|entry| (entry.key, entry.unit));
        let contract = self.contract();
        EffectBinding::new(BindingWire {
            schema: EFFECT_BINDING_SCHEMA.to_owned(),
            namespace: installed.recipe.namespace().as_str().to_owned(),
            partition: installed.partition.to_owned(),
            epoch: installed.epoch,
            operation: operation.as_str().to_owned(),
            action: action_commitment,
            native_authority,
            scope: Scope::Unscoped,
            recipe: *installed.recipe.digest(),
            compiler: COMPILER.to_owned(),
            connection: connection_commitment,
            credential_generation: installed.connection.credential_generation().get(),
            qualification_policy: installed.qualification.as_str().to_owned(),
            configuration: installed.configuration,
            approval_policy: ApprovalPolicy::Exact {
                approver: installed.approver,
            },
            reservations,
            protocol: Protocol::Acquisition {
                request: commitment(
                    "auths.effect-acquisition-request/1",
                    &canonical(&self.read_wire()).map_err(|_| invalid())?,
                )
                .map_err(|_| invalid())?,
                projection: commitment(
                    "auths.gateway-recovery-read/1",
                    &canonical(&contract).map_err(|_| invalid())?,
                )
                .map_err(|_| invalid())?,
                maximum_response_bytes: maximum,
            },
        })
        .map_err(|_| invalid())
    }

    /// Exact private MCP call for separate read authority. It binds the source,
    /// closed request and response limits; callers must authorize it natively.
    /// The output must stay on the private authoring/review channel.
    ///
    /// # Errors
    /// Refuses a different recipe, reused source operation, or invalid encoding.
    pub fn authorization_call(
        &self,
        recipe: &CompiledRecipe,
        operation: &LogicalOperationId,
    ) -> Result<McpToolCall, EffectBindingError> {
        if self.source.wire.recipe != *recipe.digest()
            || self.source.wire.namespace != recipe.namespace().as_str()
            || operation.as_str() == self.source.wire.operation
        {
            return Err(EffectBindingError::Invalid);
        }
        let contract = commitment(
            "auths.gateway-recovery-read/1",
            &canonical(&self.contract())?,
        )?;
        let arguments = json!({
            "operation_id": operation.as_str(),
            "operator_namespace": recipe.namespace().as_str(),
            "recipe_digest": recipe.digest_hex(),
            "source_effect": hex::encode(self.source.id().as_bytes()),
            "source_operation": self.source.wire.operation,
            "read_contract": hex::encode(contract),
            "maximum_response_bytes": self.request.maximum_response_bytes(),
        })
        .as_object()
        .cloned()
        .ok_or(EffectBindingError::Invalid)?;
        McpToolCall::new(recipe.service(), RECOVERY_READ_TOOL, arguments)
            .map_err(|_| EffectBindingError::Invalid)
    }
}

pub(super) struct VerifiedAcquisition {
    pub(super) target: RecoveryReadTarget,
    #[cfg(unix)]
    actors: Vec<auths_model::PrincipalId>,
    #[cfg(unix)]
    action_commitment: [u8; 32],
    #[cfg(unix)]
    arguments: Map<String, Value>,
}

impl VerifiedAcquisition {
    #[cfg(unix)]
    pub(super) fn private_review(&self) -> Value {
        json!({
            "protocol": "acquisition",
            "actors": self.actors.iter().map(auths_model::PrincipalId::as_str).collect::<Vec<_>>(),
            "action_commitment": hex::encode(self.action_commitment),
            "arguments": self.arguments,
            "method": "GET",
            "recovery": self.target.contract(),
        })
    }
}

/// Verifies fresh read-only native authority independently of the source writer
/// and produces the same bound-effect/approval model used for mutations.
/// Performs no custody, admission or provider I/O. Acquisition grant wiring is
/// separate; a mutation claim explicitly refuses this protocol.
///
/// # Errors
/// Refuses invalid native proof, another tool/source/limit, unaccounted managed
/// bounds, observer overlap, unsupported scope, or changed installation.
pub fn compile_recovery_acquisition(
    installed: &EffectInstallation<'_>,
    target: &RecoveryReadTarget,
    now: u64,
    proof: &[u8],
    action: &[u8],
) -> Result<BoundEffect, GatewaySubmitResult> {
    let invalid = || not_entered("gateway.acquisition.binding");
    GatewayConnectionDescriptor::from_record(installed.connection, installed.recipe)
        .map_err(|_| invalid())?;
    if target.source.wire.partition != installed.partition
        || target.source.wire.epoch != installed.epoch
    {
        return Err(invalid());
    }
    let sealed = crate::engine::verify_native(installed.context, now, proof, action)?;
    let verified = sealed.action().ok_or_else(invalid)?;
    let command = McpProfile
        .decode_verified(verified)
        .map_err(|_| invalid())?;
    let operation = command
        .arguments()
        .get("operation_id")
        .and_then(Value::as_str)
        .and_then(|value| LogicalOperationId::parse(value).ok())
        .ok_or_else(invalid)?;
    let expected = target
        .authorization_call(installed.recipe, &operation)
        .map_err(|_| invalid())?;
    // Comparing the canonical call also rejects extra fields and channel-binding
    // representations this unscoped protocol does not yet support.
    if command.call() != &expected {
        return Err(invalid());
    }
    crate::bounds::refuse_unaccounted_acquisition_bounds(proof, verified).map_err(not_entered)?;
    crate::separation::check_proof_observers(proof, verified).map_err(not_entered)?;
    #[cfg(unix)]
    let branches = crate::bounds::authorized_branches(proof, verified).map_err(not_entered)?;
    let canonical_action =
        auths_codec::encode_canonical_action(verified.canonical_action()).map_err(|_| invalid())?;
    let action_commitment =
        commitment("auths.canonical-action.v1", &canonical_action).map_err(|_| invalid())?;
    let binding = target.binding(
        installed,
        &operation,
        action_commitment,
        native_authority_commitment(sealed.portable(), installed.context).map_err(|_| invalid())?,
    )?;
    let contract = target.contract();
    let effect = BoundEffect {
        review: json!({"contract": "auths.gateway-recovery-read/1", "recovery": contract,
            "consequences": "Acquire bounded provider evidence only. This does not repeat the mutation, disclose content, prove exclusive causation, refund capacity or change the original actor."}),
        binding,
        command: CompiledEffect::Acquisition(Box::new(VerifiedAcquisition {
            target: target.clone(),
            #[cfg(unix)]
            actors: branches.actors,
            #[cfg(unix)]
            action_commitment,
            #[cfg(unix)]
            arguments: command.arguments().clone(),
        })),
        connection: installed.connection.clone(),
        proof: Zeroizing::new(proof.to_vec()),
        action: Zeroizing::new(action.to_vec()),
    };
    #[cfg(unix)]
    effect
        .private_review()?
        .to_private_bytes()
        .map_err(|_| invalid())?;
    Ok(effect)
}
