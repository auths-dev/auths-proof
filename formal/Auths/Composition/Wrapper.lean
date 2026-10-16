import Auths.Composition.Traversal
open Aeneas Aeneas.Std Result
open auths_composition
namespace Auths.Composition.Wrapper

section
variable {B O : Type}
variable (nativeBranch : core.ops.function.FnMut B auths_model.ProofRef BranchOutcome)
variable (nativeObserver : core.ops.function.FnMut O EvaluationEvent Unit)

theorem validation_refusal (plan : auths_model.AuthorizationPlan) (limits : auths_model.VerifierLimits)
    (branch : B) (observer : O) (reason : auths_model.ModelError)
    (refused : auths_model.AuthorizationPlan.validate plan limits = ok (.Err reason)) :
    evaluate_observed nativeBranch nativeObserver plan limits branch observer =
      ok (.Err .AuthorizationPlanInvalid, branch, observer) := by
  simp [evaluate_observed, refused]


theorem evaluated_has_validated_plan
    (plan : auths_model.AuthorizationPlan) (limits : auths_model.VerifierLimits)
    (branch finalBranch : B) (observer finalObserver : O) (outcome : BranchOutcome)
    (evaluated : evaluate_observed nativeBranch nativeObserver plan limits branch observer =
      ok (.Ok outcome, finalBranch, finalObserver)) :
    ∃ shape, auths_model.AuthorizationPlan.validate plan limits = ok (.Ok shape) := by
  cases validation : auths_model.AuthorizationPlan.validate plan limits with
  | fail error => simp [evaluate_observed, validation] at evaluated
  | div => simp [evaluate_observed, validation] at evaluated
  | ok result =>
    cases result with
    | Ok shape => exact ⟨shape, rfl⟩
    | Err reason =>
      rw [validation_refusal nativeBranch nativeObserver plan limits branch observer reason validation] at evaluated
      simp at evaluated

variable (modelBranch : B → auths_model.ProofRef → BranchOutcome × B)
variable (modelObserver : O → Auths.Composition.PlanModel.Event auths_model.ProofRef → O)
variable (branchContract : ∀ state reference,
    nativeBranch.call_mut state reference = ok (modelBranch state reference))
variable (observerContract : ∀ state event,
    nativeObserver.call_mut state event = ok ((), modelObserver state (Auths.Composition.PlanModel.eventView event)))
include branchContract observerContract

theorem validated_refines (plan : auths_model.AuthorizationPlan) (limits : auths_model.VerifierLimits)
    (branch : B) (observer : O) (shape : auths_model.PlanShape)
    (validated : auths_model.AuthorizationPlan.validate plan limits = ok (.Ok shape)) :
    evaluate_observed nativeBranch nativeObserver plan limits branch observer =
      let expected := Auths.Composition.PlanModel.evaluate modelBranch modelObserver
        (Auths.Composition.PlanModel.viewPlan plan) branch observer
      ok (.Ok expected.1, expected.2.1, expected.2.2) := by
  simp only [evaluate_observed, validated, bind_tc_ok]
  rw [Auths.Composition.Traversal.evaluator_refines nativeBranch nativeObserver modelBranch modelObserver
    branchContract observerContract plan branch observer]
  simp only [bind_tc_ok]
  cases result : Auths.Composition.PlanModel.evaluate modelBranch modelObserver
      (Auths.Composition.PlanModel.viewPlan plan) branch observer with
  | mk outcome states => cases states; rfl

end
end Auths.Composition.Wrapper
