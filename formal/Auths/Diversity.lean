import Lean.Elab.Tactic.Omega

namespace Auths

structure CompositionFloor where
  branches : Nat
  actors : Nat
  roots : Nat
  deriving DecidableEq, Repr

def floorSatisfied (required actual : CompositionFloor) : Prop :=
  required.branches ≤ actual.branches ∧
  required.actors ≤ actual.actors ∧
  required.roots ≤ actual.roots

theorem tighter_floor_cannot_create_authorization
    {loose tight actual : CompositionFloor}
    (ordering : loose.branches ≤ tight.branches ∧ loose.actors ≤ tight.actors ∧
      loose.roots ≤ tight.roots)
    (accepted : floorSatisfied tight actual) :
    floorSatisfied loose actual := by
  simp only [floorSatisfied] at accepted ⊢
  omega

end Auths
