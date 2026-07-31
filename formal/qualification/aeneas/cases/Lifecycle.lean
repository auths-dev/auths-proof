import qualification.aeneas.generated.lifecycle.Funs

open Aeneas Aeneas.Std Result
open auths_lifecycle

namespace qualification.aeneas.cases

private def decisionGates : kernel.TransitionGates where
  core_authorized := true
  policy_eligible := true
  configuration_matches := true
  not_revoked := true
  not_expired := true
  capacity_available := true
  execution_intent_present := true
  credential_authorized := false
  attempt_present := false
  provider_call_entered := false
  cancellation_allowed := true
  definite_effect := false
  definite_non_effect := true
  reconciliation_fresh := true
  reconciliation_matches := true

example :
    kernel.transition_code none kernel.OperationCode.RecordDecision
      decisionGates =
        ok (kernel.KernelCode.Applied
          model.LifecycleState.DecisionRecorded) := by
  rfl

example :
    kernel.replay_code true true =
      ok kernel.ReplayCode.ExactReplay := by
  rfl

example :
    kernel.exclusive_capacity_available true false = ok false := by
  rfl

end qualification.aeneas.cases
