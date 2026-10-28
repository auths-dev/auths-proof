//! Participant eligibility and ancestor accounting owned by the task journal.
//! Native grant paths establish authority; immutable tree ancestry attributes
//! all retained charges, including those belonging to revoked participants.

use super::{ReleaseStateError, ReleaseTaskState};
use crate::bounds::NativeAuthority;
use crate::participant_enrollment::{ParentEnrollmentPins, ParticipantCeilings};
use crate::task_write::ExactWriteIntent;

impl ReleaseTaskState {
    fn require_new_operation(&self, operation_id: &str) -> Result<(), ReleaseStateError> {
        if self.operations.contains_key(operation_id) || self.writes.contains_key(operation_id) {
            Err(ReleaseStateError::Replay)
        } else {
            Ok(())
        }
    }

    fn ancestor_usage(
        &self,
        ancestor: &[u8; 32],
    ) -> Result<ParticipantCeilings, ReleaseStateError> {
        let tree = self.participants.tree()?;
        let mut total = ParticipantCeilings::default();
        for operation in self.operations.values() {
            if tree.retained_path(&operation.recipient)?.contains(ancestor) {
                total = total
                    .checked_add(ParticipantCeilings {
                        provider_reads: 1,
                        disclosures: u32::from(operation.released_bytes.is_some()),
                        disclosure_bytes: operation.released_bytes.unwrap_or(0),
                        writes: 0,
                    })
                    .ok_or(ReleaseStateError::Exhausted)?;
            }
        }
        for write in self.writes.values() {
            if tree.retained_identity(write.writer.principal())? != write.writer {
                return Err(ReleaseStateError::Corrupt);
            }
            if tree
                .retained_path(write.writer.principal())?
                .contains(ancestor)
            {
                total.writes = total
                    .writes
                    .checked_add(1)
                    .ok_or(ReleaseStateError::Exhausted)?;
            }
        }
        Ok(total)
    }

    fn require_capacity(
        &self,
        path: &[ParentEnrollmentPins],
        debit: ParticipantCeilings,
    ) -> Result<(), ReleaseStateError> {
        for ancestor in path {
            let used = self.ancestor_usage(&ancestor.enrollment_commitment)?;
            if !used
                .checked_add(debit)
                .is_some_and(|total| total.within(ancestor.ceilings))
            {
                return Err(ReleaseStateError::Exhausted);
            }
        }
        Ok(())
    }

    pub(super) fn admit_read_participant(
        &self,
        authority: &NativeAuthority,
        scope: &super::ReleaseResourceScope,
        operation_id: &str,
        now: u64,
    ) -> Result<(), ReleaseStateError> {
        let scope_id = crate::task_enrollment::scope_id("read", scope)?;
        let path = self
            .participants
            .tree()?
            .authorize_scope(authority, &scope_id, now)?;
        self.require_new_operation(operation_id)?;
        self.require_capacity(
            &path,
            ParticipantCeilings {
                provider_reads: 1,
                ..ParticipantCeilings::default()
            },
        )
    }

    /// Metadata for review and reconstruction; never an admission decision.
    pub(crate) fn write_participant(
        &self,
        verified: &crate::engine::VerifiedCommand,
    ) -> Result<crate::participant_enrollment::EnrolledParticipant, ReleaseStateError> {
        let [authority] = verified.authorities.as_slice() else {
            return Err(ReleaseStateError::Binding);
        };
        Ok(self
            .participants
            .tree()?
            .retained_identity(authority.actor().as_str())?)
    }

    /// Fresh eligibility check used by the existing pre-entry guard. This is
    /// not an entry permit: `enter_write` separately orders the durable grant.
    pub(crate) fn write_participant_active(
        &self,
        writer: &crate::participant_enrollment::EnrolledParticipant,
        now: u64,
    ) -> bool {
        self.participants.tree().is_ok_and(|tree| {
            tree.retained_identity(writer.principal())
                .is_ok_and(|current| current == *writer)
                && tree.active_principal_path(writer.principal(), now).is_ok()
        })
    }

    pub(super) fn matches_child_writer(
        &self,
        handle: &str,
        recipe: &str,
        writer: &crate::participant_enrollment::EnrolledParticipant,
    ) -> bool {
        self.child_binding.as_ref().is_none_or(|child| {
            child.id != handle
                || child.populate_recipe_digest != recipe
                || self
                    .writes
                    .get(&child.create_operation_id)
                    .is_some_and(|create| create.writer == *writer)
        })
    }

    pub(crate) fn admit_write_participant(
        &self,
        verified: &crate::engine::VerifiedCommand,
        intent: &ExactWriteIntent,
        now: u64,
    ) -> Result<(), ReleaseStateError> {
        let path = self.authorize_write_participant(verified, intent, now)?;
        self.require_new_operation(&intent.operation_id)?;
        self.require_capacity(
            &path,
            ParticipantCeilings {
                writes: 1,
                ..ParticipantCeilings::default()
            },
        )
    }

    /// Shared eligibility predicate for reservation and durable entry. Entry
    /// checks an existing reservation and must not debit capacity a second time.
    pub(super) fn authorize_write_participant(
        &self,
        verified: &crate::engine::VerifiedCommand,
        intent: &ExactWriteIntent,
        now: u64,
    ) -> Result<Vec<ParentEnrollmentPins>, ReleaseStateError> {
        let [authority] = verified.authorities.as_slice() else {
            return Err(ReleaseStateError::Binding);
        };
        if self.write_participant(verified)? != intent.writer
            || hex::encode(verified.request.action_commitment()) != intent.action_commitment
            || verified.request.operation_id().as_str() != intent.operation_id
        {
            return Err(ReleaseStateError::Binding);
        }
        let matches = |scope: &&crate::task_activation::TaskWriteScope| {
            scope.handle == intent.resource_handle
                && scope.recipe_digest == intent.recipe_digest
                && scope.verb == intent.verb
                && scope.connection_id == intent.connection_id
                && scope.connection_generation == intent.connection_generation
                && scope.connection_subject == intent.connection_subject
        };
        let scope_id = if let Some(scope) = self.write_scopes.iter().find(matches) {
            crate::task_enrollment::scope_id("write", scope)?
        } else if self
            .bound_child_scope()
            .as_ref()
            .is_some_and(|scope| matches(&scope))
        {
            crate::task_enrollment::pending_scope_id(
                self.activated_card
                    .as_ref()
                    .ok_or(ReleaseStateError::Binding)?,
            )?
        } else {
            return Err(ReleaseStateError::Binding);
        };
        let path = self
            .participants
            .tree()?
            .authorize_scope(authority, &scope_id, now)?;
        if !self.matches_child_writer(
            &intent.resource_handle,
            &intent.recipe_digest,
            &intent.writer,
        ) {
            return Err(ReleaseStateError::Binding);
        }
        Ok(path)
    }

    pub(super) fn admit_disclosure_participant(
        &self,
        operation_id: &str,
        content_bytes: usize,
        now: u64,
    ) -> Result<(), ReleaseStateError> {
        let operation = self
            .operations
            .get(operation_id)
            .ok_or(ReleaseStateError::Binding)?;
        let path = self
            .participants
            .tree()?
            .active_principal_path(&operation.recipient, now)?;
        if operation.stage != super::ReleaseStage::ProviderCallReserved {
            return Err(ReleaseStateError::Stage);
        }
        self.require_capacity(
            &path,
            ParticipantCeilings {
                disclosures: 1,
                disclosure_bytes: u64::try_from(content_bytes)
                    .map_err(|_| ReleaseStateError::Exhausted)?,
                ..ParticipantCeilings::default()
            },
        )
    }

    pub(super) fn validate_participant_accounting(&self) -> Result<(), ReleaseStateError> {
        // Empty pending activation is valid, but no operation may predate root
        // publication. Synthetic pure-state test fixtures have no signed card.
        if self.operations.is_empty() && self.writes.is_empty() {
            return Ok(());
        }
        let tree = self.participants.tree()?;
        for participant in tree.retained_ceilings()? {
            if !self
                .ancestor_usage(&participant.enrollment_commitment)?
                .within(participant.ceilings)
            {
                return Err(ReleaseStateError::Corrupt);
            }
        }
        Ok(())
    }
}
