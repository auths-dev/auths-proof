//! Immutable identity attribution, not authority or an execution permit.

use super::{EnrollmentTree, EnrollmentTreeError, ParentEnrollmentPins};
use serde::{Deserialize, Serialize};

/// Exact participant snapshot bound into approval and durable effect attribution.
/// Deserialization does not authorize anything: the journal compares all fields
/// to its retained enrollment and separately verifies current native scope authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolledParticipant {
    engagement_commitment: String,
    partition_generation: u64,
    enrollment_commitment: String,
    principal: String,
    instance_generation: u64,
}

impl EnrolledParticipant {
    pub(crate) fn from_pins(pins: &ParentEnrollmentPins) -> Self {
        Self {
            engagement_commitment: hex::encode(pins.engagement_commitment),
            partition_generation: pins.partition_generation,
            enrollment_commitment: hex::encode(pins.enrollment_commitment),
            principal: pins.principal.as_str().to_owned(),
            instance_generation: pins.instance_generation,
        }
    }

    /// Canonical native principal of this exact enrolled instance.
    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
    }

    pub(crate) fn matches_task(&self, task: &crate::task_activation::ApprovedAgentTask) -> bool {
        self.engagement_commitment == hex::encode(task.commitment())
            && self.partition_generation == task.descriptor().delegation.partition_generation
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        principal: &str,
        commitment: &[u8; 32],
        partition: u64,
        instance: u64,
    ) -> Self {
        Self {
            engagement_commitment: hex::encode(commitment),
            partition_generation: partition,
            enrollment_commitment: "ab".repeat(32),
            principal: principal.to_owned(),
            instance_generation: instance,
        }
    }
}

impl EnrollmentTree {
    /// Retained metadata is deliberately available after revocation. New entry
    /// must also pass `authorize_scope` under the owning journal transaction.
    pub(crate) fn retained_identity(
        &self,
        principal: &str,
    ) -> Result<EnrolledParticipant, EnrollmentTreeError> {
        self.retained_principal_pins(principal)
            .map(|pins| EnrolledParticipant::from_pins(&pins))
    }
}
