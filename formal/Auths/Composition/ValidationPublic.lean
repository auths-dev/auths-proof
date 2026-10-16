import Auths.Composition.ValidationRefinement
import Auths.Composition.Wrapper
open Aeneas Aeneas.Std Result Aeneas.Std.WP
open auths_composition Auths.Composition.PlanModel Auths.Composition.ValidationModel
open Auths.Composition.ValidationLeaves Auths.Composition.SetModel Auths.Composition.ValidationRefinement
namespace Auths.Composition.ValidationPublic
set_option maxHeartbeats 2000000

/-- The returned carrier preserves the independently computed set and depth.
    Pairwise ordering makes the returned sequence canonical as well. -/
def ShapeCorresponds (expected : Except ShapeError (State auths_model.ProofRef))
    (actual : core.result.Result auths_model.PlanShape auths_model.ModelError) : Prop :=
  match expected with
  | .error .tooLarge => actual = .Err .PlanLimitExceeded
  | .error .invalidOperator => actual = .Err .InvalidPlan
  | .ok next => ∃ shape, actual = .Ok shape ∧
      shape.leaves.elements.toList.Pairwise Before ∧
      shape.leaves.elements.toList.toFinset = next.seen ∧
      shape.maximum_depth.val = next.maximumDepth

theorem validator_refines (plan : auths_model.AuthorizationPlan)
    (limits : auths_model.VerifierLimits) (bounded : LimitsBounded limits) :
    auths_model.AuthorizationPlan.validate plan limits ⦃ result => ShapeCorresponds
      (checkPlan (sourceLimits limits) 1 (viewPlan plan) rootState) result ⦄ := by
  rw [auths_model.AuthorizationPlan.validate.eq_def]
  simp only [alloc.collections.btree.set.BTreeSetTGlobal.new, bind_tc_ok]
  let initial : NativeSet := ⟨[], by simp⟩
  have initialGood : GoodSet limits initial := by simp [GoodSet, initial]
  have run := walk_refines plan limits bounded 1#usize 0#usize initial (by decide) initialGood
  apply spec_bind run
  intro actual meaning
  rcases actual with ⟨outcome, refs, maximum⟩
  change Corresponds (checkPlan (sourceLimits limits) 1 (viewPlan plan) rootState)
    (outcome, refs, maximum) at meaning
  cases expected : checkPlan (sourceLimits limits) 1 (viewPlan plan) rootState with
  | error reason =>
    cases reason with
    | tooLarge =>
      simp only [expected, Corresponds] at meaning
      rw [meaning]
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame.from, ShapeCorresponds]
    | invalidOperator =>
      simp only [expected, Corresponds] at meaning
      rw [meaning]
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame.from, ShapeCorresponds]
  | ok next =>
    simp only [expected, Corresponds] at meaning
    obtain ⟨nativeOk, sorted, stateEq⟩ := meaning
    rw [nativeOk]
    simp only [core.result.Result.Insts.CoreOpsTry.branch,
      alloc.collections.btree.set.BTreeSet.len, bind_tc_ok,
      alloc.collections.btree.set.BTreeSet.Insts.CoreIterTraitsCollectIntoIteratorTIntoIter.into_iter]
    let initialLeaves := auths_composition.alloc.vec.Vec.with_capacity auths_model.ProofRef
      (Usize.ofNatCore refs.values.length (by have bound := refs.bound; scalar_tac))
    have capacity : initialLeaves.size + refs.values.length ≤ Usize.max := by
      change 0 + refs.values.length ≤ Usize.max
      simpa only [Nat.zero_add] using refs.bound
    have collect := Auths.Composition.Collect.collect_exact refs.values
      ⟨refs.values, refs.bound⟩ initialLeaves rfl capacity
    apply spec_bind collect
    intro leaves exactValues
    have sequence : leaves.elements.toList = refs.values := by
      simpa only [initialLeaves, auths_composition.alloc.vec.Vec.with_capacity,
        auths_composition.alloc.vec.Vec.ofBase, Aeneas.Std.alloc.vec.Vec.with_capacity,
        auths_composition.alloc.vec.SizedList.toList_ofList, List.nil_append] using exactValues
    simp only [spec_ok, ShapeCorresponds]
    refine ⟨⟨leaves, maximum⟩, rfl, ?_, ?_, ?_⟩
    · simpa only [sequence] using sorted
    · exact sequence ▸ congrArg State.seen stateEq
    · exact congrArg State.maximumDepth stateEq


def evaluateChecked {B O : Type}
    (branch : B → auths_model.ProofRef → BranchOutcome × B)
    (observe : O → Event auths_model.ProofRef → O)
    (limits : Limits) (plan : Plan auths_model.ProofRef) (state : B) (observer : O) :
    core.result.Result BranchOutcome auths_model.DenialReason × B × O :=
  match checkPlan limits 1 plan rootState with
  | .error _ => (.Err .AuthorizationPlanInvalid, state, observer)
  | .ok _ =>
    let next := evaluate branch observe plan state observer
    (.Ok next.1, next.2.1, next.2.2)

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
/-- The complete public composition wrapper, including its actual validator,
    agrees with the independent checker and three-valued evaluator. -/
theorem public_evaluator_refines (plan : auths_model.AuthorizationPlan)
    (limits : auths_model.VerifierLimits) (bounded : LimitsBounded limits)
    (state : B) (observer : O) :
    evaluate_observed nativeBranch nativeObserver plan limits state observer =
      ok (evaluateChecked modelBranch modelObserver (sourceLimits limits) (viewPlan plan) state observer) := by
  obtain ⟨validated, nativeEq, meaning⟩ := spec_imp_exists (validator_refines plan limits bounded)
  cases checked : checkPlan (sourceLimits limits) 1 (viewPlan plan) rootState with
  | error reason =>
    cases reason with
    | tooLarge =>
      simp only [checked, ShapeCorresponds] at meaning
      subst validated
      rw [Auths.Composition.Wrapper.validation_refusal nativeBranch nativeObserver plan limits state observer
        .PlanLimitExceeded nativeEq]
      simp only [evaluateChecked, checked]
    | invalidOperator =>
      simp only [checked, ShapeCorresponds] at meaning
      subst validated
      rw [Auths.Composition.Wrapper.validation_refusal nativeBranch nativeObserver plan limits state observer
        .InvalidPlan nativeEq]
      simp only [evaluateChecked, checked]
  | ok next =>
    simp only [checked, ShapeCorresponds] at meaning
    obtain ⟨shape, same, sorted, refs, maximum⟩ := meaning
    subst validated
    rw [Auths.Composition.Wrapper.validated_refines nativeBranch nativeObserver modelBranch modelObserver
      branchContract observerContract plan limits state observer shape nativeEq]
    simp only [evaluateChecked, checked]

/-- A rejected structural plan cannot mutate either callback state. -/
theorem rejected_plan_preserves_callbacks (plan : auths_model.AuthorizationPlan)
    (limits : auths_model.VerifierLimits) (bounded : LimitsBounded limits)
    (state : B) (observer : O) (reason : ShapeError)
    (rejected : checkPlan (sourceLimits limits) 1 (viewPlan plan) rootState = .error reason) :
    evaluate_observed nativeBranch nativeObserver plan limits state observer =
      ok (.Err .AuthorizationPlanInvalid, state, observer) := by
  obtain ⟨validated, nativeEq, meaning⟩ := spec_imp_exists (validator_refines plan limits bounded)
  cases reason <;> simp only [rejected, ShapeCorresponds] at meaning
  · subst validated
    exact Auths.Composition.Wrapper.validation_refusal nativeBranch nativeObserver plan limits state observer
      .InvalidPlan nativeEq
  · subst validated
    exact Auths.Composition.Wrapper.validation_refusal nativeBranch nativeObserver plan limits state observer
      .PlanLimitExceeded nativeEq
end

end Auths.Composition.ValidationPublic
