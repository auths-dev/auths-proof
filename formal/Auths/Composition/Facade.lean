import Auths.Composition.ValidationContract
open Aeneas Aeneas.Std Result
open auths_composition Auths.Composition.PlanModel Auths.Composition.ValidationModel Auths.Composition.ValidationRefinement
namespace Auths.Composition.Facade

def eventOutcome {R : Type} : Event R → BranchOutcome
  | .proof _ outcome => outcome
  | .aggregate _ _ _ _ outcome => outcome

theorem event_outcome_exact :
    EvaluationEvent.outcome = (fun event => ok (eventOutcome (eventView event))) := by
  funext event
  cases event <;> rfl

theorem observer_mut_exact {B : Type}
    (branch : core.ops.function.FnMut B auths_model.ProofRef BranchOutcome)
    (state : auths_composition.evaluate.closure B) (event : EvaluationEvent) :
    auths_composition.evaluate.closure.Insts.CoreOpsFunctionFnMutTupleEvaluationEventTuple.call_mut
      branch state event = ok state := rfl

theorem observer_once_exact {B : Type}
    (branch : core.ops.function.FnMut B auths_model.ProofRef BranchOutcome)
    (state : auths_composition.evaluate.closure B) (event : EvaluationEvent) :
    auths_composition.evaluate.closure.Insts.CoreOpsFunctionFnOnceTupleEvaluationEventTuple.call_once
      branch state event = ok () := rfl

theorem evaluate_refines {B : Type}
    (nativeBranch : core.ops.function.FnMut B auths_model.ProofRef BranchOutcome)
    (modelBranch : B → auths_model.ProofRef → BranchOutcome × B)
    (branchContract : ∀ state reference, nativeBranch.call_mut state reference = ok (modelBranch state reference))
    (plan : auths_model.AuthorizationPlan) (limits : auths_model.VerifierLimits)
    (bounded : LimitsBounded limits) (state : B) :
    auths_composition.evaluate nativeBranch plan limits state =
      let expected := Auths.Composition.ValidationPublic.evaluateChecked modelBranch
        (fun (observer : Unit) _ => observer) (sourceLimits limits) (viewPlan plan) state ()
      ok (expected.1, expected.2.1) := by
  unfold auths_composition.evaluate
  have observerContract : ∀ observer event,
      (auths_composition.evaluate.closure.Insts.CoreOpsFunctionFnMutTupleEvaluationEventTuple nativeBranch).call_mut observer event =
        ok ((), observer) := by intro observer event; rfl
  rw [Auths.Composition.ValidationPublic.public_evaluator_refines nativeBranch
    (auths_composition.evaluate.closure.Insts.CoreOpsFunctionFnMutTupleEvaluationEventTuple nativeBranch)
    modelBranch (fun (observer : Unit) _ => observer) branchContract observerContract plan limits bounded state ()]
  simp only [bind_tc_ok]
  cases expected : Auths.Composition.ValidationPublic.evaluateChecked modelBranch
      (fun (observer : Unit) _ => observer) (sourceLimits limits) (viewPlan plan) state () with
  | mk result states => cases states; rfl

/-- Structural refusal needs no premise about branch correctness or termination. -/
theorem invalid_plan_preserves_callback {B : Type}
    (nativeBranch : core.ops.function.FnMut B auths_model.ProofRef BranchOutcome)
    (plan : auths_model.AuthorizationPlan) (limits : auths_model.VerifierLimits)
    (bounded : LimitsBounded limits)
    (invalid : ¬ Valid (sourceLimits limits) (viewPlan plan)) (state : B) :
    auths_composition.evaluate nativeBranch plan limits state =
      ok (.Err .AuthorizationPlanInvalid, state) := by
  unfold auths_composition.evaluate
  rw [Auths.Composition.ValidationContract.invalid_plan_preserves_callbacks nativeBranch
    (auths_composition.evaluate.closure.Insts.CoreOpsFunctionFnMutTupleEvaluationEventTuple nativeBranch)
    plan limits bounded invalid state ()]
  rfl

end Auths.Composition.Facade
