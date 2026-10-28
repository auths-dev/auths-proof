//! Durable task write entry. The task lock orders entry grants against
//! revocation; the separate attempt journal retains the transport outcome.

use super::{FileReleaseTaskLedger, ReleaseStateError, ReleaseTaskState, WriteOperation};
use crate::engine::VerifiedCommand;
use crate::task_activation::TaskActivationPins;
use crate::task_write::{ApprovedTaskWrite, ExactWriteIntent};
use crate::{ClosedProviderRequest, QualificationGate};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "stage", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum WriteEntry {
    Reserved,
    Granted { at: u64 },
}

impl WriteEntry {
    pub(super) fn valid_for(&self, not_before: u64, expires_at: u64) -> bool {
        match self {
            Self::Reserved => true,
            Self::Granted { at } => (not_before..expires_at).contains(at),
        }
    }
}

/// Minted only after a durable entry grant. Neither cloneable nor serializable:
/// reopening the journal cannot reconstruct permission to send again.
pub(crate) struct EnteredTaskWrite {
    request: ClosedProviderRequest,
}

impl EnteredTaskWrite {
    /// Consume the grant for the exact closed request verified at entry.
    pub(crate) fn into_request(self) -> ClosedProviderRequest {
        self.request
    }
}

impl WriteOperation {
    fn matches_entry(&self, intent: &ExactWriteIntent, command: &VerifiedCommand) -> bool {
        self.writer == intent.writer
            && self.operator_namespace == command.request.namespace().as_str()
            && self.resource_handle == intent.resource_handle
            && self.recipe_digest == intent.recipe_digest
            && self.verb == intent.verb
            && self.connection_id == intent.connection_id
            && self.connection_generation == intent.connection_generation
            && self.connection_subject == intent.connection_subject
            && self.action_commitment == intent.action_commitment
            && self.request_commitment == intent.request_commitment
            && crate::task_write::request_commitment(command)
                .is_ok_and(|commitment| commitment == intent.request_commitment)
    }
}

impl ReleaseTaskState {
    fn grant_write_entry(
        &mut self,
        approved: &ApprovedTaskWrite,
        command: &VerifiedCommand,
        pins: &TaskActivationPins,
        valid_until: Option<u64>,
        now: u64,
    ) -> Result<(), ReleaseStateError> {
        let current = self.activated_task(pins, now)?;
        let intent = approved.intent();
        if hex::encode(current.commitment()) != intent.task_commitment
            || self.task_id != intent.task_id
            || valid_until.is_some_and(|deadline| now >= deadline)
        {
            return Err(ReleaseStateError::Binding);
        }
        self.authorize_write_participant(command, intent, now)?;
        let operation = self
            .writes
            .get_mut(&intent.operation_id)
            .ok_or(ReleaseStateError::Binding)?;
        if !operation.matches_entry(intent, command) {
            return Err(ReleaseStateError::Binding);
        }
        if operation.entry != WriteEntry::Reserved {
            return Err(ReleaseStateError::Replay);
        }
        operation.entry = WriteEntry::Granted { at: now };
        Ok(())
    }
}

impl FileReleaseTaskLedger {
    /// Order one exact task write entry against task/participant revocation.
    /// Time is sampled under the journal lock. A failed persist returns no
    /// permit, even if the resulting file already conservatively records entry.
    pub(crate) fn enter_write(
        &self,
        approved: &ApprovedTaskWrite,
        command: VerifiedCommand,
        pins: &TaskActivationPins,
        time: &QualificationGate,
        valid_until: Option<u64>,
    ) -> Result<EnteredTaskWrite, ReleaseStateError> {
        self.update_timed(&approved.intent().task_id, time, |state, now| {
            state.grant_write_entry(approved, &command, pins, valid_until, now)
        })?;
        Ok(EnteredTaskWrite {
            request: command.request,
        })
    }
}
