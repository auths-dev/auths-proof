//! Separately verified disclosure compilation over sealed retained provenance.
//! No constructor in this module releases bytes or authenticates a live channel.
use super::*;
use auths_profile_api::ActionProfile as _;
use auths_profile_mcp::{McpProfile, McpToolCall};
use auths_raw_key::{RawKeyDescriptor, RawKeyType};
use serde_json::{Value, json};

/// Reserved release action; it cannot name a recipe's provider mutation.
pub const DISCLOSURE_TOOL: &str = "auths_gateway_disclosure_v1";
const CONTRACT: &str = "auths.gateway-disclosure/1";
const MAX_DELIVERIES: u64 = 16;

/// Exact private delivery description derived from validated journal content.
/// A recipient key and channel commitment are proposed data, not proof that a
/// peer is authenticated. Live authentication belongs at the entry boundary.
#[derive(Clone)]
pub struct DisclosureTarget {
    content: crate::RetainedContent,
    recipient: String,
    recipient_key: [u8; 32],
    channel: [u8; 32],
    instance: [u8; 32],
}

impl fmt::Debug for DisclosureTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DisclosureTarget { private: [redacted] }")
    }
}

impl DisclosureTarget {
    /// Proposes delivery of the exact retained projection, with no truncation or
    /// caller-supplied bytes. The byte ceiling is its actual retained length.
    /// This neither authenticates a recipient nor reuses source read authority.
    ///
    /// # Errors
    /// Refuses a weak/invalid recipient key or unsupported source scope.
    pub fn new(
        content: crate::RetainedContent,
        recipient_key: [u8; 32],
        channel: [u8; 32],
        delivery_instance: [u8; 32],
    ) -> Result<Self, EffectBindingError> {
        let key =
            VerifyingKey::from_bytes(&recipient_key).map_err(|_| EffectBindingError::Invalid)?;
        if key.is_weak() || content.bytes > 65_536 || content.source.wire.scope != Scope::Unscoped {
            return Err(EffectBindingError::Invalid);
        }
        let recipient = RawKeyDescriptor::new(RawKeyType::Ed25519, recipient_key.to_vec())
            .map_err(|_| EffectBindingError::Invalid)?
            .principal()
            .map_err(|_| EffectBindingError::Invalid)?
            .as_str()
            .to_owned();
        Ok(Self {
            content,
            recipient,
            recipient_key,
            channel,
            instance: delivery_instance,
        })
    }

    fn contract(&self) -> Value {
        json!({"schema": CONTRACT,
            "source_effect": hex::encode(self.content.source.id().as_bytes()),
            "source_operation": self.content.source.wire.operation,
            "source_contract": self.content.review,
            "protected_content": hex::encode(self.content.commitment),
            "projection": hex::encode(self.content.projection),
            "recipient": self.recipient, "recipient_key": hex::encode(self.recipient_key),
            "channel": hex::encode(self.channel), "delivery_instance": hex::encode(self.instance),
            "maximum_disclosure_bytes": self.content.bytes,
            "maximum_source_deliveries": MAX_DELIVERIES,
            "acknowledgement": DISCLOSURE_ACK_SCHEMA})
    }

    /// Authors the exact native release call on a private authoring channel.
    /// A fresh proof and exact approval must authorize this entire description.
    ///
    /// # Errors
    /// Refuses another recipe/namespace, the source operation ID or encoding.
    pub fn authorization_call(
        &self,
        recipe: &CompiledRecipe,
        operation: &LogicalOperationId,
    ) -> Result<McpToolCall, EffectBindingError> {
        let source = &self.content.source.wire;
        if source.recipe != *recipe.digest()
            || source.namespace != recipe.namespace().as_str()
            || source.operation == operation.as_str()
        {
            return Err(EffectBindingError::Invalid);
        }
        let arguments = json!({"operation_id": operation.as_str(),
            "operator_namespace": recipe.namespace().as_str(), "recipe_digest": recipe.digest_hex(),
            "disclosure_contract": hex::encode(commitment(CONTRACT, &canonical(&self.contract())?)?),
            "source_effect": hex::encode(self.content.source.id().as_bytes()),
            "source_operation": source.operation, "recipient": self.recipient,
            "channel": hex::encode(self.channel), "delivery_instance": hex::encode(self.instance),
            "maximum_disclosure_bytes": self.content.bytes})
            .as_object().cloned().ok_or(EffectBindingError::Invalid)?;
        McpToolCall::new(recipe.service(), DISCLOSURE_TOOL, arguments)
            .map_err(|_| EffectBindingError::Invalid)
    }

    fn validate_installation(
        &self,
        installed: &EffectInstallation<'_>,
    ) -> Result<(), EffectBindingError> {
        GatewayConnectionDescriptor::from_record(installed.connection, installed.recipe)
            .map_err(|_| EffectBindingError::Invalid)?;
        let source = &self.content.source.wire;
        let connection = Zeroizing::new(
            installed
                .connection
                .to_canonical_cbor()
                .map_err(|_| EffectBindingError::Invalid)?,
        );
        if source.partition != installed.partition
            || source.epoch != installed.epoch
            || source.recipe != *installed.recipe.digest()
            || source.namespace != installed.recipe.namespace().as_str()
            || source.connection != commitment("auths.effect-installation/1", &connection)?
            || source.credential_generation != installed.connection.credential_generation().get()
        {
            return Err(EffectBindingError::Invalid);
        }
        Ok(())
    }

    fn protocol(&self) -> Protocol {
        Protocol::Disclosure {
            source_effect: *self.content.source.id().as_bytes(),
            protected_content: self.content.commitment,
            recipient: self.recipient.clone(),
            channel: self.channel,
            delivery_instance: self.instance,
            projection: self.content.projection,
            maximum_bytes: self.content.bytes,
        }
    }

    fn capacity(&self) -> Result<SourceCapacity, EffectBindingError> {
        let source = self.content.source.id();
        Ok(SourceCapacity {
            count_key: commitment("auths.disclosure-source-count/1", source.as_bytes())?,
            bytes_key: commitment("auths.disclosure-source-bytes/1", source.as_bytes())?,
            maximum_bytes: self.content.bytes,
            attempts: MAX_DELIVERIES,
        })
    }

    fn reservations(&self) -> Result<Vec<Reservation>, EffectBindingError> {
        Ok(self
            .capacity()?
            .reservations(Unit::DisclosureCount, Unit::DisclosureBytes))
    }
}

pub(super) struct VerifiedDisclosure {
    pub(super) target: DisclosureTarget,
    pub(super) prerequisites: Prerequisites,
    #[cfg(unix)]
    actors: Vec<auths_model::PrincipalId>,
    #[cfg(unix)]
    action_commitment: [u8; 32],
    #[cfg(unix)]
    arguments: serde_json::Map<String, Value>,
}

impl VerifiedDisclosure {
    #[cfg(unix)]
    pub(super) fn private_review(&self) -> Value {
        json!({"actors": self.actors.iter().map(auths_model::PrincipalId::as_str).collect::<Vec<_>>(), "action_commitment": hex::encode(self.action_commitment),
            "arguments": self.arguments, "disclosure": self.target.contract()})
    }
}

/// Compiles separately verified release authority over retained content using
/// the common binding, native review and exact approval model. Performs no
/// credential access, provider read, byte release or live peer authentication.
///
/// # Errors
/// Refuses invalid native authority, a changed source/installation, unsupported
/// policy arguments, observer overlap or any substituted delivery dimension.
pub fn compile_disclosure(
    installed: &EffectInstallation<'_>,
    target: &DisclosureTarget,
    now: u64,
    proof: &[u8],
    action: &[u8],
) -> Result<BoundEffect, GatewaySubmitResult> {
    let invalid = || not_entered("gateway.disclosure.binding");
    target
        .validate_installation(installed)
        .map_err(|_| invalid())?;
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
    if command.call()
        != &target
            .authorization_call(installed.recipe, &operation)
            .map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    let bound =
        crate::bounds::admit_disclosure_bounds(proof, verified, installed.recipe.namespace(), now)?;
    crate::separation::check_proof_observers(proof, verified).map_err(not_entered)?;
    #[cfg(unix)]
    let branches = crate::bounds::authorized_branches(proof, verified).map_err(not_entered)?;
    let canonical_action =
        auths_codec::encode_canonical_action(verified.canonical_action()).map_err(|_| invalid())?;
    let action_commitment =
        commitment("auths.canonical-action.v1", &canonical_action).map_err(|_| invalid())?;
    let authority =
        native_authority_commitment(sealed.portable(), installed.context).map_err(|_| invalid())?;
    let mut reservations = target.reservations().map_err(|_| invalid())?;
    reservations.extend(managed_reservations(
        bound.as_ref(),
        Unit::DisclosureCount,
        Unit::DisclosureBytes,
    ));
    reservations.sort_by_key(|entry| (entry.key, entry.unit));
    let binding = acquisition::build_binding(
        installed,
        &operation,
        action_commitment,
        authority,
        target.protocol(),
        reservations,
    )?;
    let effect = BoundEffect {
        review: json!({"contract": CONTRACT, "disclosure": target.contract(),
            "consequences": "Release the exact retained projection to this recipient and channel once. A grant makes delivery possible; only an exact authenticated ACK records the recipient assertion. Lost delivery or ACK never authorizes redelivery or refund."}),
        binding,
        command: CompiledEffect::Disclosure(Box::new(VerifiedDisclosure {
            target: target.clone(),
            prerequisites: Prerequisites::disclosure(),
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
