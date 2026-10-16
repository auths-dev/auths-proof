import Auths.Composition.Bounds
import Auths.Composition.SetModel
import Auths.Composition.Collect
open Auths.Composition.PlanModel
namespace Auths.Composition.ValidationModel

structure Limits where
  leaves : Nat
  depth : Nat
  children : Nat

structure State (R : Type) where
  seen : Finset R
  maximumDepth : Nat

inductive ShapeError where
  | invalidOperator
  | tooLarge
  deriving DecidableEq

def enter {R : Type} (limits : Limits) (depth : Nat) (state : State R) :
    Except ShapeError (State R) :=
  if depth > limits.depth then .error .tooLarge
  else .ok { state with maximumDepth := max state.maximumDepth depth }

mutual
  def checkPlan {R : Type} [DecidableEq R] (limits : Limits) (depth : Nat)
      (plan : Plan R) (state : State R) : Except ShapeError (State R) := do
    let state ← enter limits depth state
    match plan with
    | .proof reference =>
      if reference ∈ state.seen then .error .tooLarge
      else
        let next := { state with seen := insert reference state.seen }
        if next.seen.card > limits.leaves then .error .tooLarge else .ok next
    | .allOf members | .anyOf members =>
      if members.isEmpty then .error .invalidOperator
      else if members.length > limits.children then .error .tooLarge
      else checkChildren limits (depth + 1) members state
    | .kOfN required members =>
      if required = 0 ∨ required > members.length ∨ members.isEmpty then .error .invalidOperator
      else if members.length > limits.children then .error .tooLarge
      else checkChildren limits (depth + 1) members state
  termination_by sizeOf plan

  def checkChildren {R : Type} [DecidableEq R] (limits : Limits) (depth : Nat)
      (members : List (Plan R)) (state : State R) : Except ShapeError (State R) := do
    match members with
    | [] => .ok state
    | head :: tail =>
      let next ← checkPlan limits depth head state
      checkChildren limits depth tail next
  termination_by sizeOf members
end

mutual
  def operatorsValid {R : Type} (limits : Limits) : Plan R → Prop
    | .proof _ => True
    | .allOf members | .anyOf members =>
        members ≠ [] ∧ members.length ≤ limits.children ∧ childrenValid limits members
    | .kOfN required members =>
        0 < required ∧ required ≤ members.length ∧
        members.length ≤ limits.children ∧ childrenValid limits members
  termination_by plan => sizeOf plan

  def childrenValid {R : Type} (limits : Limits) : List (Plan R) → Prop
    | [] => True
    | head :: tail => operatorsValid limits head ∧ childrenValid limits tail
  termination_by members => sizeOf members
end

/-- Independent structural contract, expressed without a verifier result. -/
def Valid {R : Type} (limits : Limits) (plan : Plan R) : Prop :=
  operatorsValid limits plan ∧
  Auths.Composition.Bounds.depth plan ≤ limits.depth ∧
  (Auths.Composition.Work.leaves plan).Nodup ∧
  (Auths.Composition.Work.leaves plan).length ≤ limits.leaves

def rootState {R : Type} : State R := ⟨∅, 0⟩

def sourceLimits (limits : auths_composition.auths_model.VerifierLimits) : Limits :=
  ⟨limits.plan_leaves.val, limits.plan_depth.val, limits.plan_branching.val⟩

end Auths.Composition.ValidationModel
