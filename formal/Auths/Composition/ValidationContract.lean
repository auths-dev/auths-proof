import Auths.Composition.ValidationPublic
import Auths.Composition.ValidationSoundness
open Aeneas Aeneas.Std Result Aeneas.Std.WP
open auths_composition Auths.Composition.PlanModel Auths.Composition.ValidationModel
open Auths.Composition.ValidationRefinement Auths.Composition.ValidationPublic
namespace Auths.Composition.ValidationContract

theorem source_accepts_iff_valid (plan : auths_model.AuthorizationPlan)
    (limits : auths_model.VerifierLimits) (bounded : LimitsBounded limits) :
    (∃ shape, auths_model.AuthorizationPlan.validate plan limits = ok (.Ok shape)) ↔
      Valid (sourceLimits limits) (viewPlan plan) := by
  obtain ⟨native, nativeEq, meaning⟩ := spec_imp_exists (validator_refines plan limits bounded)
  cases checked : checkPlan (sourceLimits limits) 1 (viewPlan plan) rootState with
  | error reason =>
    have invalid : ¬ Valid (sourceLimits limits) (viewPlan plan) := by
      intro valid
      obtain ⟨next, accepted⟩ := Auths.Composition.ValidationComplete.valid_is_accepted _ _ valid
      simp [checked] at accepted
    cases reason <;> simp only [checked, ShapeCorresponds] at meaning
    · subst native
      simp [nativeEq, invalid]
    · subst native
      simp [nativeEq, invalid]
  | ok next =>
    have valid := Auths.Composition.ValidationSoundness.accepted_is_valid _ _ next checked
    simp only [checked, ShapeCorresponds] at meaning
    obtain ⟨shape, same, _⟩ := meaning
    subst native
    exact ⟨fun _ => valid, fun _ => ⟨shape, nativeEq⟩⟩

section
variable {B O : Type}
variable (nativeBranch : core.ops.function.FnMut B auths_model.ProofRef BranchOutcome)
variable (nativeObserver : core.ops.function.FnMut O EvaluationEvent Unit)
variable (modelBranch : B → auths_model.ProofRef → BranchOutcome × B)
variable (modelObserver : O → Event auths_model.ProofRef → O)
variable (branchContract : ∀ state reference,
    nativeBranch.call_mut state reference = ok (modelBranch state reference))
variable (observerContract : ∀ state event,
    nativeObserver.call_mut state event = ok ((), modelObserver state (eventView event)))

include branchContract observerContract in
/-- Every independently valid bounded plan reaches the public three-valued
    evaluator and preserves its exact result, callback state, and event state. -/
theorem valid_public_evaluator_refines (plan : auths_model.AuthorizationPlan)
    (limits : auths_model.VerifierLimits) (bounded : LimitsBounded limits)
    (valid : Valid (sourceLimits limits) (viewPlan plan)) (state : B) (observer : O) :
    evaluate_observed nativeBranch nativeObserver plan limits state observer =
      let expected := evaluate modelBranch modelObserver (viewPlan plan) state observer
      ok (.Ok expected.1, expected.2.1, expected.2.2) := by
  obtain ⟨shape, nativeEq⟩ := (source_accepts_iff_valid plan limits bounded).mpr valid
  exact Auths.Composition.Wrapper.validated_refines nativeBranch nativeObserver modelBranch modelObserver
    branchContract observerContract plan limits state observer shape nativeEq

/-- Invalid structure is refused before either callback, regardless of their
    implementations; there is no callback-totality premise for this result. -/
theorem invalid_plan_preserves_callbacks (plan : auths_model.AuthorizationPlan)
    (limits : auths_model.VerifierLimits) (bounded : LimitsBounded limits)
    (invalid : ¬ Valid (sourceLimits limits) (viewPlan plan)) (state : B) (observer : O) :
    evaluate_observed nativeBranch nativeObserver plan limits state observer =
      ok (.Err .AuthorizationPlanInvalid, state, observer) := by
  cases checked : checkPlan (sourceLimits limits) 1 (viewPlan plan) rootState with
  | ok next => exact False.elim (invalid (Auths.Composition.ValidationSoundness.accepted_is_valid _ _ next checked))
  | error reason =>
    exact rejected_plan_preserves_callbacks nativeBranch nativeObserver plan limits bounded
      state observer reason checked
end


theorem public_event_bound {B : Type}
    (nativeBranch : core.ops.function.FnMut B auths_model.ProofRef BranchOutcome)
    (nativeObserver : core.ops.function.FnMut Nat EvaluationEvent Unit)
    (modelBranch : B → auths_model.ProofRef → BranchOutcome × B)
    (branchContract : ∀ state reference,
      nativeBranch.call_mut state reference = ok (modelBranch state reference))
    (observerContract : ∀ count event,
      nativeObserver.call_mut count event = ok ((), count + 1))
    (plan : auths_model.AuthorizationPlan) (limits : auths_model.VerifierLimits)
    (bounded : LimitsBounded limits) (valid : Valid (sourceLimits limits) (viewPlan plan))
    (state : B) (count : Nat) :
    ∃ outcome next finalCount,
      evaluate_observed nativeBranch nativeObserver plan limits state count =
        ok (.Ok outcome, next, finalCount) ∧ finalCount ≤ count + 2048 := by
  obtain ⟨shape, validated⟩ := (source_accepts_iff_valid plan limits bounded).mpr valid
  obtain ⟨outcome, next, exactCount⟩ := Auths.Composition.Work.source_event_count
    nativeBranch modelBranch branchContract nativeObserver observerContract plan state count
  refine ⟨outcome, next, count + Auths.Composition.Work.nodes (viewPlan plan), ?_, ?_⟩
  · simp only [evaluate_observed, validated, bind_tc_ok, exactCount]
    rfl
  · have bound := Auths.Composition.ValidationSoundness.valid_has_bounded_events
      (sourceLimits limits) (viewPlan plan) valid bounded.2.1 bounded.1
    omega

end Auths.Composition.ValidationContract
