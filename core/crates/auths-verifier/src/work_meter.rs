//! Checked accounting for the verifier's declared primitive/adapter units.
//! Failed reservations preserve both fields. This counter is distinct from
//! the structural traversal bounds of the surrounding verifier algorithms.

use crate::{DenialReason, VerificationFailure};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WorkMeter {
    pub(super) used: u64,
    pub(super) limit: u64,
}

pub(super) const fn new(limit: u64) -> WorkMeter { WorkMeter { used: 0, limit } }
pub(super) const fn from_used(limit: u64, used: u64) -> WorkMeter { WorkMeter { used, limit } }

pub(super) fn reserve(meter: &mut WorkMeter, maximum: u64) -> Result<(), VerificationFailure> {
    let next = meter.used.checked_add(maximum).ok_or(VerificationFailure::Denied(
        DenialReason::ResourceLimitExceeded,
    ))?;
    if next > meter.limit {
        return Err(VerificationFailure::Denied(DenialReason::ResourceLimitExceeded));
    }
    meter.used = next;
    Ok(())
}

impl WorkMeter {
    pub(super) const fn new(limit: u64) -> Self { new(limit) }
    pub(super) const fn from_used(limit: u64, used: u64) -> Self { from_used(limit, used) }
    pub(super) fn reserve(&mut self, maximum: u64) -> Result<(), VerificationFailure> { reserve(self, maximum) }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The complete original body, independent of the new extracted free leaf.
    fn reference(meter: &mut WorkMeter, maximum: u64) -> Result<(), VerificationFailure> {
        let next = meter.used.checked_add(maximum).ok_or(VerificationFailure::Denied(
            DenialReason::ResourceLimitExceeded,
        ))?;
        if next > meter.limit {
            return Err(VerificationFailure::Denied(DenialReason::ResourceLimitExceeded));
        }
        meter.used = next;
        Ok(())
    }

    #[test]
    fn complete_boundary_matrix_preserves_result_and_both_fields() {
        let words = [0, 1, 2, 99, 100, 101, u64::MAX / 2, u64::MAX - 1, u64::MAX];
        for limit in words {
            for used in words {
                for maximum in words {
                    let mut actual = WorkMeter::from_used(limit, used);
                    let mut expected = actual;
                    assert_eq!(actual.reserve(maximum), reference(&mut expected, maximum));
                    assert_eq!(actual, expected);
                }
            }
        }
    }

    #[test]
    fn refusal_does_not_spend_and_later_smaller_reservation_can_fit() {
        let mut meter = WorkMeter::new(5);
        assert_eq!(meter.reserve(3), Ok(()));
        assert_eq!(meter.reserve(3), Err(VerificationFailure::Denied(DenialReason::ResourceLimitExceeded)));
        assert_eq!(meter.used, 3);
        assert_eq!(meter.reserve(2), Ok(()));
        assert_eq!(meter.used, 5);
        assert_eq!(meter.reserve(0), Ok(()));
        assert_eq!(meter.limit, 5);
    }
}
