//! Post-apply result validation.

use crate::{action::OpenTofuSavedPlanApplyV1, errors::PortError, types::OpenTofuApplyResult};

/// Checks that authenticated observations describe the authorized lineage.
pub fn validate_apply_result(
    action: &OpenTofuSavedPlanApplyV1,
    result: &OpenTofuApplyResult,
) -> Result<(), PortError> {
    if result.state_lineage != action.state_lineage()
        || result.prior_state_serial != action.state_serial()
        || result.resulting_state_serial <= result.prior_state_serial
        || result.finished_at < result.started_at
        || !result.state_committed
        || !result.postconditions_observed
        || !result.converged
    {
        return Err(PortError::PostconditionFailed);
    }
    Ok(())
}
