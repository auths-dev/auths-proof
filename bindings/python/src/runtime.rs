use auths_lifecycle::{
    LifecycleState,
    kernel::{
        KernelCode, OperationCode, ReplayCode, TransitionGates, additive_capacity_available,
        exclusive_capacity_available, replay_code, transition_code,
    },
};
use pyo3::{exceptions::PyValueError, prelude::*};

#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn runtime_transition_v1(
    current: Option<&str>,
    operation: &str,
    core_authorized: bool,
    policy_eligible: bool,
    configuration_matches: bool,
    not_revoked: bool,
    not_expired: bool,
    capacity_available: bool,
    execution_intent_present: bool,
    credential_authorized: bool,
    attempt_present: bool,
    provider_call_entered: bool,
    cancellation_allowed: bool,
    definite_effect: bool,
    definite_non_effect: bool,
    reconciliation_fresh: bool,
    reconciliation_matches: bool,
) -> PyResult<(String, Option<String>)> {
    let code = transition_code(
        current.map(parse_state).transpose()?,
        parse_operation(operation)?,
        TransitionGates {
            core_authorized,
            policy_eligible,
            configuration_matches,
            not_revoked,
            not_expired,
            capacity_available,
            execution_intent_present,
            credential_authorized,
            attempt_present,
            provider_call_entered,
            cancellation_allowed,
            definite_effect,
            definite_non_effect,
            reconciliation_fresh,
            reconciliation_matches,
        },
    );
    Ok(match code {
        KernelCode::Applied(state) => ("applied".into(), Some(state_label(state).into())),
        KernelCode::ObservationOnly => ("observation-only".into(), current.map(str::to_owned)),
        other => ("rejected".into(), Some(kernel_code(other).into())),
    })
}

#[pyfunction]
fn runtime_replay_v1(record_exists: bool, commitments_equal: bool) -> &'static str {
    match replay_code(record_exists, commitments_equal) {
        ReplayCode::Absent => "absent",
        ReplayCode::ExactReplay => "exact-replay",
        ReplayCode::Conflict => "conflict",
    }
}

#[pyfunction]
fn runtime_additive_capacity_v1(ceiling: u64, committed: u64, active: u64, requested: u64) -> bool {
    additive_capacity_available(ceiling, committed, active, requested)
}

#[pyfunction]
fn runtime_exclusive_capacity_v1(has_live_owner: bool, owner_is_exact_replay: bool) -> bool {
    exclusive_capacity_available(has_live_owner, owner_is_exact_replay)
}

#[pyfunction]
fn runtime_execution_state_v1(outcome: &str) -> PyResult<&'static str> {
    match outcome {
        "succeeded" => Ok("committed"),
        "cancelled" | "outcome-unknown" => Ok("outcome-unknown"),
        _ => Err(PyValueError::new_err(
            "unsupported observed execution outcome",
        )),
    }
}

fn parse_state(value: &str) -> PyResult<LifecycleState> {
    match value {
        "decision-recorded" => Ok(LifecycleState::DecisionRecorded),
        "reserved" => Ok(LifecycleState::Reserved),
        "execution-intent-recorded" => Ok(LifecycleState::ExecutionIntentRecorded),
        "executing" => Ok(LifecycleState::Executing),
        "committed" => Ok(LifecycleState::Committed),
        "released" => Ok(LifecycleState::Released),
        "outcome-unknown" => Ok(LifecycleState::OutcomeUnknown),
        "reconciled-committed" => Ok(LifecycleState::ReconciledCommitted),
        "reconciled-released" => Ok(LifecycleState::ReconciledReleased),
        _ => Err(PyValueError::new_err("unsupported runtime state")),
    }
}

fn state_label(value: LifecycleState) -> &'static str {
    match value {
        LifecycleState::DecisionRecorded => "decision-recorded",
        LifecycleState::Reserved => "reserved",
        LifecycleState::ExecutionIntentRecorded => "execution-intent-recorded",
        LifecycleState::Executing => "executing",
        LifecycleState::Committed => "committed",
        LifecycleState::Released => "released",
        LifecycleState::OutcomeUnknown => "outcome-unknown",
        LifecycleState::ReconciledCommitted => "reconciled-committed",
        LifecycleState::ReconciledReleased => "reconciled-released",
    }
}

fn parse_operation(value: &str) -> PyResult<OperationCode> {
    match value {
        "record-decision" => Ok(OperationCode::RecordDecision),
        "reserve" => Ok(OperationCode::Reserve),
        "record-execution-intent" => Ok(OperationCode::RecordExecutionIntent),
        "authorize-credential" => Ok(OperationCode::AuthorizeCredential),
        "start-attempt" => Ok(OperationCode::StartAttempt),
        "mark-provider-call-entered" => Ok(OperationCode::MarkProviderCallEntered),
        "commit" => Ok(OperationCode::Commit),
        "release" => Ok(OperationCode::Release),
        "mark-outcome-unknown" => Ok(OperationCode::MarkOutcomeUnknown),
        "reconcile-effect" => Ok(OperationCode::ReconcileEffect),
        "reconcile-non-effect" => Ok(OperationCode::ReconcileNonEffect),
        "reconcile-inconclusive" => Ok(OperationCode::ReconcileInconclusive),
        _ => Err(PyValueError::new_err("unsupported runtime operation")),
    }
}

fn kernel_code(value: KernelCode) -> &'static str {
    match value {
        KernelCode::Applied(_) => "applied",
        KernelCode::ObservationOnly => "observation-only",
        KernelCode::Terminal => "terminal",
        KernelCode::IllegalTransition => "illegal-transition",
        KernelCode::NotAuthorized => "not-authorized",
        KernelCode::NotEligible => "not-eligible",
        KernelCode::ConfigurationMismatch => "configuration-mismatch",
        KernelCode::Revoked => "revoked",
        KernelCode::Expired => "expired",
        KernelCode::CapacityExceeded => "capacity-exceeded",
        KernelCode::ExecutionIntentMissing => "execution-intent-missing",
        KernelCode::CredentialNotAuthorized => "credential-not-authorized",
        KernelCode::AttemptMissing => "attempt-missing",
        KernelCode::ProviderCallNotEntered => "provider-call-not-entered",
        KernelCode::EffectNotProved => "effect-not-proved",
        KernelCode::NonEffectNotProved => "non-effect-not-proved",
        KernelCode::ReconciliationStale => "reconciliation-stale",
        KernelCode::ReconciliationMismatch => "reconciliation-mismatch",
    }
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(runtime_transition_v1, module)?)?;
    module.add_function(wrap_pyfunction!(runtime_replay_v1, module)?)?;
    module.add_function(wrap_pyfunction!(runtime_additive_capacity_v1, module)?)?;
    module.add_function(wrap_pyfunction!(runtime_exclusive_capacity_v1, module)?)?;
    module.add_function(wrap_pyfunction!(runtime_execution_state_v1, module)?)?;
    Ok(())
}
