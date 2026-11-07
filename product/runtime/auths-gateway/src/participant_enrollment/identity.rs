//! Immutable identity attribution, not authority or an execution permit.

use super::{EnrollmentTree, EnrollmentTreeError, ParentEnrollmentPins};
use serde::{Deserialize, Serialize};

/// Exact participant snapshot bound into approval and durable effect attribution.
/// Deserialization does not authorize anything: the journal compares all fields
/// to its retained enrollment and separately verifies current native scope authority.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
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
}

impl EnrollmentTree {
    /// Retained metadata is deliberately available after revocation.
    ///
    /// # Errors
    /// Refuses a principal not retained by this engagement. This is attribution,
    /// not current native authority, admission or entry permission. New entry
    /// must also pass `verify_operation_scope` under the owning journal transaction.
    pub fn retained_identity(
        &self,
        principal: &str,
    ) -> Result<EnrolledParticipant, EnrollmentTreeError> {
        self.retained_principal_pins(principal)
            .map(|pins| EnrolledParticipant::from_pins(&pins))
    }
}

impl std::fmt::Debug for EnrolledParticipant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EnrolledParticipant { private: [redacted] }")
    }
}
