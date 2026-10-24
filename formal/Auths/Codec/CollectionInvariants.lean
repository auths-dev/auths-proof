import Auths.Codec.SnapshotUniqueness
import Mathlib.Data.List.Chain
import Mathlib.Data.List.Sort
import Mathlib.Tactic

namespace Auths.Codec.CollectionInvariants

def adjacent {T : Type} [DecidableEq T] : List T → Bool
  | [] => false
  | [_] => false
  | first :: second :: rest => decide (first = second) || adjacent (second :: rest)

theorem adjacent_false_chain {T : Type} [DecidableEq T] (values : List T) :
    adjacent values = false ↔ values.IsChain (fun left right => left ≠ right) := by
  induction values with
  | nil => simp [adjacent]
  | cons first rest ih =>
    cases rest with
    | nil => simp [adjacent]
    | cons second rest => simp [adjacent, List.isChain_cons_cons, ← ih]

/-- Sorting is not itself uniqueness. Antisymmetry of the actual key order
and absence of equal adjacent elements together establish global uniqueness. -/
theorem adjacent_false_nodup {T : Type} [DecidableEq T] (relation : T → T → Prop)
    (antisymmetric : ∀ left right, relation left right → relation right left → left = right)
    (values : List T) (ordered : values.Pairwise relation) :
    adjacent values = false ↔ values.Nodup := by
  revert ordered
  induction values with
  | nil => intro _; simp [adjacent]
  | cons first rest ih =>
    intro ordered
    cases rest with
    | nil => simp [adjacent]
    | cons second tail =>
      obtain ⟨fromFirst, restOrdered⟩ := List.pairwise_cons.mp ordered
      have restMeaning := ih restOrdered
      have pieces : adjacent (first :: second :: tail) = false ↔
          first ≠ second ∧ adjacent (second :: tail) = false := by
        change ((decide (first = second)) || adjacent (second :: tail)) = false ↔ _
        simp
      rw [pieces, restMeaning]
      constructor
      · rintro ⟨different, unique⟩
        refine List.nodup_cons.mpr ⟨?_, unique⟩
        intro member
        rcases List.mem_cons.mp member with same | later
        · exact different same
        · have forward := fromFirst second (by simp)
          have backward := (List.pairwise_cons.mp restOrdered).1 first later
          exact different (antisymmetric first second forward backward)
      · intro unique
        obtain ⟨absent, unique⟩ := List.nodup_cons.mp unique
        exact ⟨fun same => absent (by simp [same]), unique⟩

def adjacentProbes {T : Type} [DecidableEq T] : List T → Nat
  | [] => 0
  | [_] => 0
  | first :: second :: rest =>
      if first = second then 1 else 1 + adjacentProbes (second :: rest)

theorem adjacent_probes_bound {T : Type} [DecidableEq T] (values : List T) :
    adjacentProbes values ≤ values.length - 1 := by
  induction values with
  | nil => simp [adjacentProbes]
  | cons first rest ih =>
    cases rest with
    | nil => simp [adjacentProbes]
    | cons second tail =>
      change (if first = second then 1 else 1 + adjacentProbes (second :: tail)) ≤
        (tail.length + 2) - 1
      have remaining : adjacentProbes (second :: tail) ≤ tail.length := by simpa using ih
      split <;> omega

/-- An order-preserving list must use global identity, not the adjacent
criterion: its nonadjacent repeated values remain invalid. -/
theorem global_refusal_iff {T : Type} [DecidableEq T] (values : List T) :
    SnapshotUniqueness.hasDuplicate values = true ↔ ¬ values.Nodup :=
  SnapshotUniqueness.duplicate_iff values

def CollectionValid {T : Type} (element : T → Prop) (minimum maximum : Nat)
    (values : List T) : Prop :=
  minimum ≤ values.length ∧ values.length ≤ maximum ∧ values.Nodup ∧
    ∀ value ∈ values, element value

theorem permutation_preserves_valid {T : Type} (element : T → Prop)
    (minimum maximum : Nat) {left right : List T} (same : left.Perm right) :
    CollectionValid element minimum maximum left ↔ CollectionValid element minimum maximum right := by
  simp only [CollectionValid, same.length_eq, same.nodup_iff]
  constructor <;> rintro ⟨lower, upper, unique, valid⟩
  · exact ⟨lower, upper, unique, fun value member => valid value (same.mem_iff.mpr member)⟩
  · exact ⟨lower, upper, unique, fun value member => valid value (same.mem_iff.mp member)⟩

inductive BoundFailure where
  | empty
  | aboveMaximum
  | duplicate
  deriving DecidableEq

def normalized {T : Type} [LinearOrder T] (values : List T) : List T :=
  values.insertionSort (· ≤ ·)

/-- Independent constructor semantics keeps the pre-sort length refusal ahead
of duplicate refusal. The positive result is a canonical permutation. -/
def construct {T : Type} [LinearOrder T] (maximum : Nat) (values : List T) :
    Except BoundFailure (List T) :=
  if values = [] then .error .empty
  else if maximum < values.length then .error .aboveMaximum
  else if values.Nodup then .ok (normalized values) else .error .duplicate

theorem normalized_permutation {T : Type} [LinearOrder T] (values : List T) :
    (normalized values).Perm values := List.perm_insertionSort (· ≤ ·) values

theorem normalized_ordered {T : Type} [LinearOrder T] (values : List T) :
    (normalized values).Pairwise (· ≤ ·) := List.pairwise_insertionSort (· ≤ ·) values

theorem construct_accepts_iff {T : Type} [LinearOrder T] (maximum : Nat)
    (values output : List T) :
    construct maximum values = .ok output ↔
      values ≠ [] ∧ values.length ≤ maximum ∧ values.Nodup ∧ output = normalized values := by
  unfold construct
  split <;> split_ifs <;> simp_all [eq_comm]

theorem construct_earns_valid {T : Type} [LinearOrder T] (maximum : Nat)
    (values output : List T) (accepted : construct maximum values = .ok output) :
    output ≠ [] ∧ output.length ≤ maximum ∧ output.Nodup ∧ output.Pairwise (· ≤ ·) := by
  obtain ⟨nonempty, bounded, unique, rfl⟩ := (construct_accepts_iff maximum values output).mp accepted
  have same := normalized_permutation values
  exact ⟨by intro empty; exact nonempty (List.length_eq_zero_iff.mp (by simpa [empty] using same.length_eq.symm)),
    by simpa [same.length_eq] using bounded, same.nodup_iff.mpr unique, normalized_ordered values⟩

theorem oversize_precedes_duplicate {T : Type} [LinearOrder T] (maximum : Nat)
    (values : List T) (tooMany : maximum < values.length) :
    construct maximum values = .error .aboveMaximum := by
  have nonempty : values ≠ [] := by intro empty; simp [empty] at tooMany
  simp [construct, nonempty, tooMany]

example : adjacent ([1, 2, 1] : List Nat) = false := rfl
example : SnapshotUniqueness.hasDuplicate ([1, 2, 1] : List Nat) = true := by decide
example : construct 2 ([1, 1, 1] : List Nat) = .error .aboveMaximum := by decide
example : construct 4 ([3, 1, 2] : List Nat) = .ok [1, 2, 3] := by decide

end Auths.Codec.CollectionInvariants
