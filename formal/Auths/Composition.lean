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

def thresholdCounts := Generated.thresholdCounts

def thresholdTwo : Nat → Truth → Truth → Truth
  | 0, _, _ => .authorized
  | 1, left, right => any left right
  | 2, left, right => all left right
  | _, _, _ => .denied

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

/-- K = 0 and K ≥ 3 lie outside the product's domain, since the wire format
and plan validation reject them; over two inputs they take the threshold
formula's values. -/
theorem threshold_zero_authorized (left right : Truth) :
    thresholdTwo 0 left right = .authorized := rfl

theorem threshold_above_inputs_denied {k : Nat} (above : 3 ≤ k) (left right : Truth) :
    thresholdTwo k left right = .denied := by
  match k, above with
  | k + 3, _ => rfl

/-- Increasing k cannot improve a result, for every k. -/
theorem threshold_antitone_k {k₁ k₂ : Nat} (raise : k₁ ≤ k₂) (left right : Truth) :
    Truth.le (thresholdTwo k₂ left right) (thresholdTwo k₁ left right) := by
  match k₁, k₂, raise with
  | 0, 0, _ | 1, 1, _ | 2, 2, _ =>
      simp [Truth.le]
  | 0, 1, _ | 0, 2, _ | 1, 2, _ =>
      cases left <;> cases right <;>
        simp [Truth.le, Truth.rank, thresholdTwo, all, any]
  | k₁, k₂ + 3, _ =>
      simp [Truth.le, Truth.rank, thresholdTwo]
  | k₁ + 3, 0, raise | k₁ + 3, 1, raise | k₁ + 3, 2, raise => omega

/-- The same law for the generated count function that the verifier runs. -/
theorem thresholdCounts_antitone_required {k₁ k₂ a i : Nat} (raise : k₁ ≤ k₂) :
    Truth.le (thresholdCounts k₂ a i) (thresholdCounts k₁ a i) := by
  simp only [Truth.le, thresholdCounts, Generated.thresholdCounts]
  split <;> split <;> (try split) <;> (try split) <;> simp [Truth.rank] <;> omega

/-- The two-input helper is the generated count function over its two inputs,
for every k. -/
theorem thresholdTwo_eq_thresholdCounts (k : Nat) (left right : Truth) :
    thresholdTwo k left right =
      thresholdCounts k
        ([left, right].countP (· == .authorized))
        ([left, right].countP (· == .indeterminate)) := by
  match k with
  | 0 => simp [thresholdTwo, thresholdCounts, Generated.thresholdCounts]
  | 1 | 2 =>
      cases left <;> cases right <;> decide
  | k + 3 =>
      have total : [left, right].countP (· == .authorized) +
          [left, right].countP (· == .indeterminate) ≤ 2 := by
        cases left <;> cases right <;> decide
      simp only [thresholdTwo, thresholdCounts, Generated.thresholdCounts]
      rw [if_neg (by omega), if_neg (by omega)]

theorem binary_composition_swap_invariant (left right : Truth) :
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

theorem plan_visit_is_leaf_enumeration (plan : Plan) : plan.visit = plan.leaves := by
  rfl

theorem plan_cost_is_node_count (plan : Plan) : plan.cost = plan.nodes := rfl

theorem authorized_implies_threshold_met {k authorized indeterminate : Nat}
    (result : thresholdCounts k authorized indeterminate = .authorized) :
    k ≤ authorized := by
  simp only [thresholdCounts, Generated.thresholdCounts] at result
  split at result
  · assumption
  · split at result <;> contradiction

theorem denied_implies_threshold_impossible {k authorized indeterminate : Nat}
    (result : thresholdCounts k authorized indeterminate = .denied) :
    authorized + indeterminate < k := by
  simp only [thresholdCounts, Generated.thresholdCounts] at result
  split at result
  · contradiction
  · split at result
    · contradiction
    · omega

theorem indeterminate_implies_threshold_reachable {k authorized indeterminate : Nat}
    (result : thresholdCounts k authorized indeterminate = .indeterminate) :
    authorized < k ∧ k ≤ authorized + indeterminate := by
  simp only [thresholdCounts, Generated.thresholdCounts] at result
  split at result
  · contradiction
  · split at result
    · omega
    · contradiction

end Auths
