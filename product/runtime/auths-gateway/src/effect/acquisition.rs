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

    pub(crate) fn closed_request(&self) -> &crate::ClosedObservationRequest {
        &self.request
    }

    fn request_bytes(
        &self,
        prerequisites: &Prerequisites,
    ) -> Result<Zeroizing<Vec<u8>>, EffectBindingError> {
        canonical(&json!({"request": self.read_wire(), "prerequisite_acquisitions": prerequisites}))
    }

    fn journal_plan(
        &self,
        prerequisites: &Prerequisites,
    ) -> Result<RecoveryPlan, EffectBindingError> {
        let transport = self.request_bytes(prerequisites)?;
        Ok(RecoveryPlan {
            source_binding: String::from_utf8(self.source.to_private_bytes()?.to_vec())
                .map_err(|_| EffectBindingError::Invalid)?,
            request: commitment("auths.effect-acquisition-request/2", &transport)?,
            contract: commitment(
                "auths.gateway-recovery-read/1",
                &canonical(&self.contract())?,
            )?,
            transport_canonical: String::from_utf8(transport.to_vec())
                .map_err(|_| EffectBindingError::Invalid)?,
            maximum_response_bytes: u64::try_from(self.request.maximum_response_bytes())
                .map_err(|_| EffectBindingError::Invalid)?,
        })
    }

    fn binding(
        &self,
        installed: &EffectInstallation<'_>,
        operation: &LogicalOperationId,
        action_commitment: [u8; 32],
        native_authority: [u8; 32],
        bound: Option<&crate::bounds::BoundAdmission>,
        prerequisites: &Prerequisites,
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
        let plan = self.journal_plan(prerequisites).map_err(|_| invalid())?;
        let capacity = plan.capacity().map_err(|_| invalid())?;
        let mut reservations = capacity.reservations();
        reservations.extend(managed_reservations(
            bound,
            Unit::AcquisitionCount,
            Unit::ResponseBytes,
        ));
        reservations.sort_by_key(|entry| (entry.key, entry.unit));
        build_binding(
            installed,
            operation,
            action_commitment,
            native_authority,
            Protocol::Acquisition {
                request: plan.request,
                projection: plan.contract,
                maximum_response_bytes: plan.maximum_response_bytes,
            },
            reservations,
        )
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

pub(super) fn build_binding(
    installed: &EffectInstallation<'_>,
    operation: &LogicalOperationId,
    action_commitment: [u8; 32],
    native_authority: [u8; 32],
    protocol: Protocol,
    reservations: Vec<Reservation>,
) -> Result<EffectBinding, GatewaySubmitResult> {
    let invalid = || not_entered("gateway.acquisition.binding");
    let connection = Zeroizing::new(
        installed
            .connection
            .to_canonical_cbor()
            .map_err(|_| invalid())?,
    );
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
        connection: commitment("auths.effect-installation/1", &connection)
            .map_err(|_| invalid())?,
        credential_generation: installed.connection.credential_generation().get(),
        qualification_policy: installed.qualification.as_str().to_owned(),
        configuration: installed.configuration,
        approval_policy: ApprovalPolicy::Exact {
            approver: installed.approver,
        },
        reservations,
        protocol,
    })
    .map_err(|_| invalid())
}

/// Private immutable journal projection of the native recovery compiler. It
/// carries no proof or transport capability and is checked against the binding.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryPlan {
    pub(crate) source_binding: String,
    request: [u8; 32],
    contract: [u8; 32],
    transport_canonical: String,
    maximum_response_bytes: u64,
}

/// The same acquisition journal admits independent recovery reads and the
/// enumerated prerequisites of one exact approved mutation. Their source
/// eligibility is distinct; neither variant authorizes disclosure.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "plan",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub(crate) enum AcquisitionPlan {
    Recovery(RecoveryPlan),
    Prerequisite(PrerequisitePlan),
}

impl AcquisitionPlan {
    pub(crate) fn source(&self) -> Result<EffectBinding, EffectBindingError> {
        match self {
            Self::Recovery(plan) => plan.source(),
            Self::Prerequisite(plan) => plan.source(),
        }
    }
    pub(crate) fn capacity(&self) -> Result<AcquisitionCapacity, EffectBindingError> {
        match self {
            Self::Recovery(plan) => plan.capacity(),
            Self::Prerequisite(plan) => plan.capacity(),
        }
    }
    pub(crate) fn validate(
        &self,
        binding: &EffectBinding,
    ) -> Result<AcquisitionCapacity, EffectBindingError> {
        match self {
            Self::Recovery(plan) => plan.validate(binding),
            Self::Prerequisite(plan) => plan.validate(binding),
        }
    }
}

pub(crate) struct AcquisitionCapacity {
    pub(crate) count_key: [u8; 32],
    pub(crate) bytes_key: [u8; 32],
    pub(crate) maximum_bytes: u64,
    pub(crate) attempts: u64,
}

impl RecoveryPlan {
    pub(crate) fn matches_target(
        &self,
        target: &RecoveryReadTarget,
    ) -> Result<bool, EffectBindingError> {
        let witness: Value = serde_json::from_slice(self.transport_canonical.as_bytes())
            .map_err(|_| EffectBindingError::Invalid)?;
        Ok(self.source()? == target.source
            && self.maximum_response_bytes == target.request.maximum_response_bytes() as u64
            && self.contract
                == commitment(
                    "auths.gateway-recovery-read/1",
                    &canonical(&target.contract())?,
                )?
            && canonical(&witness["request"])? == canonical(&target.read_wire())?)
    }

    pub(crate) fn source(&self) -> Result<EffectBinding, EffectBindingError> {
        EffectBinding::from_private_bytes(self.source_binding.as_bytes())
    }

    pub(crate) fn capacity(&self) -> Result<AcquisitionCapacity, EffectBindingError> {
        let source = self.source()?;
        if !(1..=65_536).contains(&self.maximum_response_bytes)
            || !matches!(source.wire.protocol, Protocol::Mutation { .. })
        {
            return Err(EffectBindingError::Invalid);
        }
        let key = |unit| {
            commitment(
                "auths.recovery-capacity/1",
                &canonical(&(source.id().as_bytes(), unit))?,
            )
        };
        Ok(AcquisitionCapacity {
            count_key: key(Unit::AcquisitionCount)?,
            bytes_key: key(Unit::ResponseBytes)?,
            maximum_bytes: self.maximum_response_bytes,
            attempts: MAX_RECOVERY_ATTEMPTS,
        })
    }

    pub(crate) fn validate(
        &self,
        effect: &EffectBinding,
    ) -> Result<AcquisitionCapacity, EffectBindingError> {
        let source = self.source()?;
        let capacity = self.capacity()?;
        let transport = self.transport_canonical.as_bytes();
        if transport.len() > MAX_EFFECT_BYTES
            || self.request != commitment("auths.effect-acquisition-request/2", transport)?
        {
            return Err(EffectBindingError::Invalid);
        }
        let witness: Value =
            serde_json::from_slice(transport).map_err(|_| EffectBindingError::Invalid)?;
        if canonical(&witness)?.as_slice() != transport {
            return Err(EffectBindingError::Invalid);
        }
        if source.wire.namespace != effect.wire.namespace
            || source.wire.partition != effect.wire.partition
            || source.wire.epoch != effect.wire.epoch
            || source.wire.recipe != effect.wire.recipe
            || source.wire.credential_generation != effect.wire.credential_generation
            || source.wire.scope != effect.wire.scope
            || source.wire.connection != effect.wire.connection
            || source.wire.operation == effect.wire.operation
            || effect.wire.protocol
                != (Protocol::Acquisition {
                    request: self.request,
                    projection: self.contract,
                    maximum_response_bytes: self.maximum_response_bytes,
                })
            || effect
                .wire
                .reservations
                .iter()
                .filter(|entry| entry.window == ReservationWindow::SourceLifetime)
                .cloned()
                .collect::<Vec<_>>()
                != capacity.reservations()
            || effect.wire.reservations.iter().any(|entry| {
                matches!(entry.window, ReservationWindow::Fixed { .. })
                    && match entry.unit {
                        Unit::AcquisitionCount => entry.amount != 1,
                        Unit::ResponseBytes => entry.amount != capacity.maximum_bytes,
                        _ => true,
                    }
            })
        {
            return Err(EffectBindingError::Invalid);
        }
        Ok(capacity)
    }
}

impl AcquisitionCapacity {
    pub(super) fn reservations(&self) -> Vec<Reservation> {
        let mut reservations = vec![
            Reservation {
                key: self.count_key,
                unit: Unit::AcquisitionCount,
                amount: 1,
                ceiling: self.attempts,
                window: ReservationWindow::SourceLifetime,
            },
            Reservation {
                key: self.bytes_key,
                unit: Unit::ResponseBytes,
                amount: self.maximum_bytes,
                ceiling: self.attempts * self.maximum_bytes,
                window: ReservationWindow::SourceLifetime,
            },
        ];
        reservations.sort_by_key(|entry| (entry.key, entry.unit));
        reservations
    }
}

#[derive(Clone)]
pub(super) enum AcquisitionTarget {
    Recovery(Box<RecoveryReadTarget>),
    Candidate(Box<super::candidate::CandidateCredentialTarget>),
}

pub(super) struct VerifiedAcquisition {
    pub(super) target: AcquisitionTarget,
    pub(super) bound: Option<crate::bounds::BoundAdmission>,
    pub(super) prerequisites: Prerequisites,
    #[cfg(unix)]
    actors: Vec<auths_model::PrincipalId>,
    #[cfg(unix)]
    action_commitment: [u8; 32],
    #[cfg(unix)]
    arguments: Map<String, Value>,
}

impl VerifiedAcquisition {
    pub(super) fn journal_plan(&self) -> Result<RecoveryPlan, EffectBindingError> {
        match &self.target {
            AcquisitionTarget::Recovery(target) => target.journal_plan(&self.prerequisites),
            AcquisitionTarget::Candidate(_) => Err(EffectBindingError::Invalid),
        }
    }

    pub(super) fn request_bytes(&self) -> Result<Zeroizing<Vec<u8>>, EffectBindingError> {
        match &self.target {
            AcquisitionTarget::Recovery(target) => target.request_bytes(&self.prerequisites),
            AcquisitionTarget::Candidate(target) => target.request_bytes(),
        }
    }

    #[cfg(unix)]
    pub(super) fn private_review(&self) -> Value {
        let mut review = json!({
            "protocol": "acquisition",
            "actors": self.actors.iter().map(auths_model::PrincipalId::as_str).collect::<Vec<_>>(),
            "action_commitment": hex::encode(self.action_commitment),
            "arguments": self.arguments,
            "method": match &self.target {
                AcquisitionTarget::Recovery(_) => "GET",
                AcquisitionTarget::Candidate(target) => target.method(),
            },
            "prerequisite_acquisitions": self.prerequisites,
        });
        match &self.target {
            AcquisitionTarget::Recovery(target) => review["recovery"] = target.contract(),
            AcquisitionTarget::Candidate(target) => review["candidate"] = target.contract(),
        }
        review
    }
}

/// Verifies fresh read-only native authority independently of the source writer
/// and produces the same bound-effect/approval model used for mutations.
/// Performs no custody, admission or provider I/O. Acquisition grant wiring is
/// separate; a mutation claim explicitly refuses this protocol.
///
/// # Errors
/// Refuses invalid native proof, another tool/source/limit, managed bounds on
/// arguments other than the response ceiling, observer overlap, unsupported
/// scope, or changed installation.
pub fn compile_recovery_acquisition(
    installed: &EffectInstallation<'_>,
    target: &RecoveryReadTarget,
    now: u64,
    proof: &[u8],
    action: &[u8],
) -> Result<BoundEffect, GatewaySubmitResult> {
    compile_acquisition(
        installed,
        AcquisitionTarget::Recovery(Box::new(target.clone())),
        now,
        proof,
        action,
    )
}

pub(super) fn compile_acquisition(
    installed: &EffectInstallation<'_>,
    target: AcquisitionTarget,
    now: u64,
    proof: &[u8],
    action: &[u8],
) -> Result<BoundEffect, GatewaySubmitResult> {
    let invalid = || not_entered("gateway.acquisition.binding");
    GatewayConnectionDescriptor::from_record(installed.connection, installed.recipe)
        .map_err(|_| invalid())?;
    match &target {
        AcquisitionTarget::Recovery(target) => {
            if target.source.wire.partition != installed.partition
                || target.source.wire.epoch != installed.epoch
            {
                return Err(invalid());
            }
        }
        AcquisitionTarget::Candidate(target) => target
            .validate_installation(installed)
            .map_err(|_| invalid())?,
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
    let expected = match &target {
        AcquisitionTarget::Recovery(target) => {
            target.authorization_call(installed.recipe, &operation)
        }
        AcquisitionTarget::Candidate(target) => {
            target.authorization_call(installed.recipe, &operation)
        }
    }
    .map_err(|_| invalid())?;
    // Comparing the canonical call also rejects extra fields and channel-binding
    // representations this unscoped protocol does not yet support.
    if command.call() != &expected {
        return Err(invalid());
    }
    let bound = crate::bounds::admit_acquisition_bounds(
        proof,
        verified,
        installed.recipe.namespace(),
        now,
    )?;
    crate::separation::check_proof_observers(proof, verified).map_err(not_entered)?;
    #[cfg(unix)]
    let branches = crate::bounds::authorized_branches(proof, verified).map_err(not_entered)?;
    let canonical_action =
        auths_codec::encode_canonical_action(verified.canonical_action()).map_err(|_| invalid())?;
    let action_commitment =
        commitment("auths.canonical-action.v1", &canonical_action).map_err(|_| invalid())?;
    let prerequisites = match &target {
        AcquisitionTarget::Recovery(_) => {
            Prerequisites::credentials(installed.recipe, *installed.connection.account_commitment())
                .map_err(|_| invalid())?
        }
        AcquisitionTarget::Candidate(target) => target.prerequisites().clone(),
    };
    let authority =
        native_authority_commitment(sealed.portable(), installed.context).map_err(|_| invalid())?;
    let (binding, review) = match &target {
        AcquisitionTarget::Recovery(target) => (
            target.binding(
                installed,
                &operation,
                action_commitment,
                authority,
                bound.as_ref(),
                &prerequisites,
            )?,
            json!({"contract": "auths.gateway-recovery-read/1", "recovery": target.contract(),
                "consequences": "Acquire bounded provider evidence only. This does not repeat the mutation, disclose content, prove exclusive causation, refund capacity or change the original actor."}),
        ),
        AcquisitionTarget::Candidate(target) => (
            target.binding(
                installed,
                &operation,
                action_commitment,
                authority,
                bound.as_ref(),
            )?,
            json!({"contract": "auths.gateway-candidate-check/1", "candidate": target.contract(),
                "consequences": "Check this exact candidate credential with the declared bounded reads. These reads do not authorize publication, mutation or disclosure."}),
        ),
    };
    let effect = BoundEffect {
        review,
        binding,
        command: CompiledEffect::Acquisition(Box::new(VerifiedAcquisition {
            target,
            bound,
            prerequisites,
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
