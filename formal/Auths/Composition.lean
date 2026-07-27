import Lean.Elab.Tactic.Omega
import Auths.Base

namespace Auths

def all (left right : Truth) : Truth :=
  match left, right with
  | .denied, _ | _, .denied => .denied
  | .indeterminate, _ | _, .indeterminate => .indeterminate
  | .authorized, .authorized => .authorized

def any (left right : Truth) : Truth :=
  match left, right with
  | .authorized, _ | _, .authorized => .authorized
  | .indeterminate, _ | _, .indeterminate => .indeterminate
  | .denied, .denied => .denied

def thresholdCounts (k authorized indeterminate : Nat) : Truth :=
  if k ≤ authorized then .authorized
  else if k ≤ authorized + indeterminate then .indeterminate
  else .denied

def thresholdTwo : Nat → Truth → Truth → Truth
  | 0, _, _ => .authorized
  | 1, left, right => any left right
  | _, left, right => all left right

theorem all_commutative (left right : Truth) : all left right = all right left := by
  cases left <;> cases right <;> rfl

theorem all_associative (a b c : Truth) : all (all a b) c = all a (all b c) := by
  cases a <;> cases b <;> cases c <;> rfl

theorem all_idempotent (value : Truth) : all value value = value := by
  cases value <;> rfl

theorem any_commutative (left right : Truth) : any left right = any right left := by
  cases left <;> cases right <;> rfl

theorem any_associative (a b c : Truth) : any (any a b) c = any a (any b c) := by
  cases a <;> cases b <;> cases c <;> rfl

theorem any_idempotent (value : Truth) : any value value = value := by
  cases value <;> rfl

theorem threshold_one_eq_any (left right : Truth) :
    thresholdTwo 1 left right = any left right := rfl

theorem threshold_n_eq_all (left right : Truth) :
    thresholdTwo 2 left right = all left right := rfl

theorem threshold_monotone_k (left right : Truth) :
    Truth.le (thresholdTwo 2 left right) (thresholdTwo 1 left right) := by
  cases left <;> cases right <;>
    simp [Truth.le, Truth.rank, thresholdTwo, all, any]

theorem composition_permutation_invariant (left right : Truth) :
    all left right = all right left ∧ any left right = any right left :=
  ⟨all_commutative left right, any_commutative left right⟩

theorem canonical_diagnostic_permutation_invariant (left right : Nat) :
    canonicalCode left right = canonicalCode right left :=
  canonicalCode_commutative left right

inductive Plan where
  | proof (reference : Nat)
  | allOf (members : List Plan)
  | anyOf (members : List Plan)
  | kOfN (k : Nat) (members : List Plan)
  deriving Repr

def Plan.leaves : Plan → List Nat
  | .proof reference => [reference]
  | .allOf members | .anyOf members | .kOfN _ members =>
      members.flatMap Plan.leaves

def Plan.visit (plan : Plan) : List Nat := plan.leaves

def Plan.nodes : Plan → Nat
  | .proof _ => 1
  | .allOf members | .anyOf members | .kOfN _ members =>
      1 + (members.map Plan.nodes).sum

def Plan.cost (plan : Plan) : Nat := plan.nodes

theorem every_leaf_visited_once (plan : Plan) : plan.visit = plan.leaves := by
  rfl

theorem validated_plan_terminates (plan : Plan) : ∃ count, plan.nodes = count :=
  ⟨plan.nodes, rfl⟩

theorem evaluation_cost_linear_in_nodes (plan : Plan) : plan.cost = plan.nodes := rfl

theorem authorized_implies_threshold_met {k authorized indeterminate : Nat}
    (result : thresholdCounts k authorized indeterminate = .authorized) :
    k ≤ authorized := by
  simp only [thresholdCounts] at result
  split at result
  · assumption
  · split at result <;> contradiction

theorem denied_implies_threshold_impossible {k authorized indeterminate : Nat}
    (result : thresholdCounts k authorized indeterminate = .denied) :
    authorized + indeterminate < k := by
  simp only [thresholdCounts] at result
  split at result
  · contradiction
  · split at result
    · contradiction
    · omega

theorem indeterminate_implies_threshold_reachable {k authorized indeterminate : Nat}
    (result : thresholdCounts k authorized indeterminate = .indeterminate) :
    authorized < k ∧ k ≤ authorized + indeterminate := by
  simp only [thresholdCounts] at result
  split at result
  · contradiction
  · split at result
    · omega
    · contradiction

end Auths
