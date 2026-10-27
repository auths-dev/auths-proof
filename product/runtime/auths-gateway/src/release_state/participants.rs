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
        // The current exact-write projection still only admits the initial
        // participant. Its writes belong to that immutable root, never a child.
        // Child write admission must add exact actor/instance binding to approval.
        if tree
            .retained_path(&self.agent_principal)?
            .contains(ancestor)
        {
            total.writes =
                u32::try_from(self.writes.len()).map_err(|_| ReleaseStateError::Exhausted)?;
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

    pub(super) fn admit_write_participant(
        &self,
        verified: &crate::engine::VerifiedCommand,
        intent: &ExactWriteIntent,
        now: u64,
    ) -> Result<(), ReleaseStateError> {
        let [authority] = verified.authorities.as_slice() else {
            return Err(ReleaseStateError::Binding);
        };
        if authority.actor().as_str() != self.agent_principal
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
        self.require_new_operation(&intent.operation_id)?;
        self.require_capacity(
            &path,
            ParticipantCeilings {
                writes: 1,
                ..ParticipantCeilings::default()
            },
        )
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
