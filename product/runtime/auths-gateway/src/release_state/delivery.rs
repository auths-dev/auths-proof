//! One enrolled delivery binding shared by authentication, durable entry and ACK.
//! Only the protected journal constructs bindings and entered-release permits.

use super::{FileReleaseTaskLedger, ReleaseStage, ReleaseStateError, ReleaseTaskState};
use crate::release_commitment::{ReleaseCommitmentContext, ReleaseCommitmentKey};
use crate::release_verify::VerifiedReleaseRequest;
use serde::Serialize;

/// Immutable recipient/operation projection. This is not an entry permit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ReleaseDeliveryBinding {
    task_id: String,
    task_commitment: String,
    operation_id: String,
    recipient: String,
    delivery_channel: String,
    enrollment_commitment: String,
    partition_generation: u64,
    instance_generation: u64,
    #[serde(skip)]
    identity_fingerprint: Option<String>,
}

impl ReleaseDeliveryBinding {
    pub(crate) fn task_id(&self) -> &str {
        &self.task_id
    }
    pub(crate) fn task_commitment(&self) -> &str {
        &self.task_commitment
    }
    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }
    pub(crate) fn recipient(&self) -> &str {
        &self.recipient
    }
    pub(crate) fn channel(&self) -> &str {
        &self.delivery_channel
    }
    pub(crate) fn identity_fingerprint(&self) -> Option<&str> {
        self.identity_fingerprint.as_deref()
    }

    pub(crate) fn message_fields(
        &self,
    ) -> Result<serde_json::Map<String, serde_json::Value>, ReleaseStateError> {
        let serde_json::Value::Object(value) =
            serde_json::to_value(self).map_err(|_| ReleaseStateError::Binding)?
        else {
            return Err(ReleaseStateError::Binding);
        };
        Ok(value)
    }
}

/// Minted only after durable disclosure entry. Not cloneable or serializable;
/// consuming it is the only production path into a channel's content write.
pub(crate) struct EnteredRelease {
    binding: ReleaseDeliveryBinding,
    resource_handle: String,
    released_bytes: u64,
    commitment_key_version: u32,
    content_commitment: String,
}

impl EnteredRelease {
    pub(crate) fn validate_content<'a>(
        &'a self,
        binding: &ReleaseDeliveryBinding,
        content: &[u8],
        key: &ReleaseCommitmentKey,
    ) -> Result<&'a str, ReleaseStateError> {
        let receipt_scope = ReleaseCommitmentContext::new(
            binding.task_id(),
            &self.resource_handle,
            binding.operation_id(),
            "released",
        )
        .map_err(|_| ReleaseStateError::Binding)?;
        let commitment = key.commit(&receipt_scope, content);
        if &self.binding != binding
            || u64::try_from(content.len()).ok() != Some(self.released_bytes)
            || commitment.key_version() != self.commitment_key_version
            || !super::same_commitment(&commitment.hex(), &self.content_commitment)
        {
            return Err(ReleaseStateError::Binding);
        }
        Ok(&self.resource_handle)
    }
}

impl ReleaseTaskState {
    /// Early channel preparation repeats native scope admission, but reserves
    /// nothing. The locked reservation and disclosure transition remain mandatory.
    pub(crate) fn read_delivery_binding(
        &self,
        verified: &VerifiedReleaseRequest,
        now: u64,
    ) -> Result<ReleaseDeliveryBinding, ReleaseStateError> {
        self.active(now)?;
        let request = verified.request();
        if request.task_id() != self.task_id
            || !super::same_commitment(
                &hex::encode(request.task_commitment()),
                &self.task_commitment,
            )
        {
            return Err(ReleaseStateError::Binding);
        }
        let scope = self
            .resources
            .iter()
            .find(|scope| {
                scope.handle == request.resource_handle()
                    && scope.recipe_digest == hex::encode(request.recipe_digest())
            })
            .ok_or(ReleaseStateError::Binding)?;
        self.admit_read_participant(
            verified.authority(),
            scope,
            request.operation_id().as_str(),
            now,
        )?;
        self.delivery_binding(verified.actor().as_str(), request.operation_id().as_str())
    }

    fn delivery_binding(
        &self,
        principal: &str,
        operation_id: &str,
    ) -> Result<ReleaseDeliveryBinding, ReleaseStateError> {
        let card = self
            .activated_card
            .as_ref()
            .ok_or(ReleaseStateError::Binding)?;
        let pins = self
            .participants
            .tree()?
            .retained_principal_pins(principal)?;
        let (channel, _) = card
            .delegation
            .permitted_channels
            .iter()
            .find(|(_, channel)| {
                channel.principal == pins.principal
                    && channel.instance_generation == pins.instance_generation
            })
            .ok_or(ReleaseStateError::Binding)?;
        Ok(ReleaseDeliveryBinding {
            task_id: self.task_id.clone(),
            task_commitment: self.task_commitment.clone(),
            operation_id: operation_id.to_owned(),
            recipient: principal.to_owned(),
            delivery_channel: channel.clone(),
            enrollment_commitment: hex::encode(pins.enrollment_commitment),
            partition_generation: pins.partition_generation,
            instance_generation: pins.instance_generation,
            identity_fingerprint: (principal == card.agent_principal)
                .then(|| card.agent_key_fingerprint.clone()),
        })
    }

    fn entered_release(&self, operation_id: &str) -> Result<EnteredRelease, ReleaseStateError> {
        let operation = self
            .operations
            .get(operation_id)
            .ok_or(ReleaseStateError::Binding)?;
        if operation.stage != ReleaseStage::ReleaseEntered {
            return Err(ReleaseStateError::Stage);
        }
        Ok(EnteredRelease {
            binding: self.delivery_binding(&operation.recipient, operation_id)?,
            resource_handle: operation.resource_handle.clone(),
            released_bytes: operation.released_bytes.ok_or(ReleaseStateError::Binding)?,
            commitment_key_version: operation
                .commitment_key_version
                .ok_or(ReleaseStateError::Binding)?,
            content_commitment: operation
                .content_commitment
                .clone()
                .ok_or(ReleaseStateError::Binding)?,
        })
    }
}

impl FileReleaseTaskLedger {
    pub(crate) fn enter_release(
        &self,
        task_id: &str,
        operation_id: &str,
        content: &[u8],
        key: &ReleaseCommitmentKey,
        time: &crate::QualificationGate,
    ) -> Result<(ReleaseTaskState, EnteredRelease), ReleaseStateError> {
        let state = self.update_timed(task_id, time, |state, now| {
            state.admit_disclosure_participant(operation_id, content.len(), now)?;
            state.enter_release(operation_id, content, key, now)
        })?;
        // update_timed returns only after file and directory fsync succeed.
        // A later revocation does not retract this already charged entry.
        let permit = state.entered_release(operation_id)?;
        Ok((state, permit))
    }
}

#[cfg(test)]
impl ReleaseDeliveryBinding {
    /// Synthetic channel/crypto oracle only; native tree tests use journal projection.
    pub(crate) fn initial_for_test(
        task: &crate::task_activation::ApprovedAgentTask,
        operation_id: &str,
    ) -> Self {
        let card = task.descriptor();
        Self {
            task_id: card.task_id.clone(),
            task_commitment: hex::encode(task.commitment()),
            operation_id: operation_id.to_owned(),
            recipient: card.agent_principal.clone(),
            delivery_channel: card.delivery_channel.clone(),
            enrollment_commitment: "11".repeat(32),
            partition_generation: card.delegation.partition_generation,
            instance_generation: card.delegation.root_instance_generation,
            identity_fingerprint: Some(card.agent_key_fingerprint.clone()),
        }
    }
}

#[cfg(test)]
impl EnteredRelease {
    /// Pure channel transport fixture; this never supplies native journal evidence.
    pub(crate) fn for_test(
        binding: ReleaseDeliveryBinding,
        resource: &str,
        content: &[u8],
        key: &ReleaseCommitmentKey,
    ) -> Self {
        let receipt_scope = ReleaseCommitmentContext::new(
            binding.task_id(),
            resource,
            binding.operation_id(),
            "released",
        )
        .unwrap();
        let commitment = key.commit(&receipt_scope, content);
        Self {
            binding,
            resource_handle: resource.to_owned(),
            released_bytes: content.len() as u64,
            commitment_key_version: commitment.key_version(),
            content_commitment: commitment.hex(),
        }
    }
}
