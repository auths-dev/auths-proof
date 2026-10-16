import Auths.Composition.Traversal
open Aeneas Aeneas.Std
open auths_composition
open Auths.Composition.PlanModel
namespace Auths.Composition.Work

mutual
  def nodes {R : Type} : Plan R → Nat
    | .proof _ => 1
    | .allOf members | .anyOf members | .kOfN _ members => 1 + memberNodes members
  termination_by plan => sizeOf plan
  def memberNodes {R : Type} : List (Plan R) → Nat
    | [] => 0
    | head :: tail => nodes head + memberNodes tail
  termination_by members => sizeOf members
end

def countEvent {R : Type} (count : Nat) (_ : Event R) : Nat := count + 1

section
variable {R B : Type} (branch : B → R → BranchOutcome × B)

def NodeCountCorrect (plan : Plan R) : Prop :=
  ∀ state count, (evaluate branch countEvent plan state count).2.2 = count + nodes plan

def MemberCountCorrect (members : List (Plan R)) : Prop :=
  ∀ state count, (evaluateChildren branch countEvent members state count).2.2 = count + memberNodes members

theorem event_count (plan : Plan R) : NodeCountCorrect branch plan := by
  refine Plan.rec
    (motive_1 := fun plan => NodeCountCorrect branch plan)
    (motive_2 := fun members => MemberCountCorrect branch members)
    ?_ ?_ ?_ ?_ ?_ ?_ plan
  · intro reference state count
    simp [evaluate, countEvent, nodes]
  · intro members correct state count
    simp only [evaluate, countEvent, nodes]
    have counted := correct state count
    rw [counted]
    omega
  · intro members correct state count
    simp only [evaluate, countEvent, nodes]
    have counted := correct state count
    rw [counted]
    omega
  · intro required members correct state count
    simp only [evaluate, countEvent, nodes]
    have counted := correct state count
    rw [counted]
    omega
  · intro state count
    simp [evaluateChildren, memberNodes]
  · intro head tail headCorrect tailCorrect state count
    generalize childEq : evaluate branch countEvent head state count = child
    rcases child with ⟨outcome, next, counted⟩
    have headCount := headCorrect state count
    rw [childEq] at headCount
    have tailCount := tailCorrect next counted
    simp only [evaluateChildren, childEq, memberNodes]
    rw [tailCount]
    dsimp only at headCount
    rw [headCount]
    omega

end

mutual
  def leaves {R : Type} : Plan R → List R
    | .proof reference => [reference]
    | .allOf members | .anyOf members | .kOfN _ members => memberLeaves members
  termination_by plan => sizeOf plan
  def memberLeaves {R : Type} : List (Plan R) → List R
    | [] => []
    | head :: tail => leaves head ++ memberLeaves tail
  termination_by members => sizeOf members
end

def recordLeaf {R : Type} (trace : List R) : Event R → List R
  | .proof reference _ => trace ++ [reference]
  | .aggregate _ _ _ _ _ => trace

section
variable {R B : Type} (branch : B → R → BranchOutcome × B)

def NodeOrderCorrect (plan : Plan R) : Prop :=
  ∀ state trace, (evaluate branch recordLeaf plan state trace).2.2 = trace ++ leaves plan

def MemberOrderCorrect (members : List (Plan R)) : Prop :=
  ∀ state trace, (evaluateChildren branch recordLeaf members state trace).2.2 = trace ++ memberLeaves members

theorem leaf_order (plan : Plan R) : NodeOrderCorrect branch plan := by
  refine Plan.rec
    (motive_1 := fun plan => NodeOrderCorrect branch plan)
    (motive_2 := fun members => MemberOrderCorrect branch members)
    ?_ ?_ ?_ ?_ ?_ ?_ plan
  · intro reference state trace
    simp [evaluate, recordLeaf, leaves]
  · intro members correct state trace
    simp only [evaluate, recordLeaf, leaves]
    exact correct state trace
  · intro members correct state trace
    simp only [evaluate, recordLeaf, leaves]
    exact correct state trace
  · intro required members correct state trace
    simp only [evaluate, recordLeaf, leaves]
    exact correct state trace
  · intro state trace
    simp [evaluateChildren, memberLeaves]
  · intro head tail headCorrect tailCorrect state trace
    generalize childEq : evaluate branch recordLeaf head state trace = child
    rcases child with ⟨outcome, next, observed⟩
    have headOrder := headCorrect state trace
    rw [childEq] at headOrder
    have tailOrder := tailCorrect next observed
    simp only [evaluateChildren, childEq, memberLeaves]
    rw [tailOrder]
    dsimp only at headOrder
    rw [headOrder, List.append_assoc]

end
section
variable {B : Type}
variable (nativeBranch : core.ops.function.FnMut B auths_model.ProofRef BranchOutcome)
variable (modelBranch : B → auths_model.ProofRef → BranchOutcome × B)
variable (branchContract : ∀ state reference,
  nativeBranch.call_mut state reference = Aeneas.Std.Result.ok (modelBranch state reference))

include branchContract

theorem source_event_count
    (nativeObserver : core.ops.function.FnMut Nat EvaluationEvent Unit)
    (observerContract : ∀ count event,
      nativeObserver.call_mut count event = Aeneas.Std.Result.ok ((), count + 1))
    (plan : auths_model.AuthorizationPlan) (state : B) (count : Nat) :
    ∃ outcome next, evaluate_node nativeBranch nativeObserver plan state count =
      Aeneas.Std.Result.ok (outcome, next, count + nodes (viewPlan plan)) := by
  let expected := evaluate modelBranch countEvent (viewPlan plan) state count
  refine ⟨expected.1, expected.2.1, ?_⟩
  have counted := event_count modelBranch (viewPlan plan) state count
  rw [← counted]
  exact Auths.Composition.Traversal.evaluator_refines nativeBranch nativeObserver modelBranch countEvent
    branchContract observerContract plan state count

theorem source_leaf_order
    (nativeObserver : core.ops.function.FnMut (List auths_model.ProofRef) EvaluationEvent Unit)
    (observerContract : ∀ trace event,
      nativeObserver.call_mut trace event = Aeneas.Std.Result.ok ((), recordLeaf trace (eventView event)))
    (plan : auths_model.AuthorizationPlan) (state : B) (trace : List auths_model.ProofRef) :
    ∃ outcome next, evaluate_node nativeBranch nativeObserver plan state trace =
      Aeneas.Std.Result.ok (outcome, next, trace ++ leaves (viewPlan plan)) := by
  let expected := evaluate modelBranch recordLeaf (viewPlan plan) state trace
  refine ⟨expected.1, expected.2.1, ?_⟩
  have ordered := leaf_order modelBranch (viewPlan plan) state trace
  rw [← ordered]
  exact Auths.Composition.Traversal.evaluator_refines nativeBranch nativeObserver modelBranch recordLeaf
    branchContract observerContract plan state trace

end

end Auths.Composition.Work
