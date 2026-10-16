import Mathlib.Tactic
namespace Auths.Product.SlotBatch
abbrev Key := List Nat
inductive Entry where
  | claim (key : Key)
  | count (counter : Key) (slot : Nat)
  | sum (counter : Key) (slot amount cumulative : Nat)
  deriving DecidableEq

def wordMax : Nat := 2 ^ 64 - 1

def countEntries (counters : List Key) (slots : List Nat) : List Entry :=
  List.zipWith Entry.count counters slots

def sumEntries : List Key → List Nat → List Nat → Nat → Option (List Entry)
  | [], [], [], _ => some []
  | counter :: counters, slot :: slots, total :: totals, amount =>
    if total + amount ≤ wordMax then
      (sumEntries counters slots totals amount).map (Entry.sum counter slot amount (total + amount) :: ·)
    else none
  | _, _, _, _ => none

def shape (counts : List Key) (countSlots : List Nat) (sums : List Key) (sumSlots totals : List Nat) : Prop :=
  counts.length ≤ 16 ∧ sums.length ≤ 16 ∧ counts.length = countSlots.length ∧
    sums.length = sumSlots.length ∧ sums.length = totals.length

instance (counts : List Key) (countSlots : List Nat) (sums : List Key) (sumSlots totals : List Nat) :
    Decidable (shape counts countSlots sums sumSlots totals) := inferInstanceAs (Decidable (_ ∧ _ ∧ _ ∧ _ ∧ _))

def build (claim : Key) (counts : List Key) (countSlots : List Nat) (sums : List Key)
    (sumSlots totals : List Nat) (amount : Nat) : Option (List Entry) :=
  if shape counts countSlots sums sumSlots totals then
    (sumEntries sums sumSlots totals amount).map (fun entries => .claim claim :: (countEntries counts countSlots ++ entries))
  else none

theorem sum_entries_length (counters : List Key) (slots totals : List Nat) (amount : Nat) (entries : List Entry)
    (produced : sumEntries counters slots totals amount = some entries) :
    entries.length = counters.length ∧ counters.length = slots.length ∧ counters.length = totals.length := by
  induction counters generalizing slots totals entries with
  | nil => cases slots <;> cases totals <;> simp_all [sumEntries]
  | cons counter rest ih =>
    cases slots with
    | nil => simp [sumEntries] at produced
    | cons slot slots =>
      cases totals with
      | nil => simp [sumEntries] at produced
      | cons total totals =>
        simp only [sumEntries] at produced
        split at produced <;> rename_i fits
        · cases tail : sumEntries rest slots totals amount with
          | none => simp [tail] at produced
          | some next =>
            simp only [tail, Option.map_some, Option.some.injEq] at produced
            subst entries
            obtain ⟨length, slotsLength, totalsLength⟩ := ih slots totals next tail
            simp_all
        · simp at produced

theorem first_is_claim (claim : Key) (counts : List Key) (countSlots : List Nat) (sums : List Key)
    (sumSlots totals : List Nat) (amount : Nat) (entries : List Entry)
    (produced : build claim counts countSlots sums sumSlots totals amount = some entries) :
    entries.head? = some (.claim claim) := by
  unfold build at produced
  split at produced
  · cases result : sumEntries sums sumSlots totals amount with
    | none => simp [result] at produced
    | some suffix =>
      simp only [result, Option.map_some, Option.some.injEq] at produced
      subst entries
      rfl
  · simp at produced

theorem exact_entry_count (claim : Key) (counts : List Key) (countSlots : List Nat) (sums : List Key)
    (sumSlots totals : List Nat) (amount : Nat) (entries : List Entry)
    (produced : build claim counts countSlots sums sumSlots totals amount = some entries) :
    entries.length = 1 + counts.length + sums.length ∧ entries.length ≤ 33 := by
  unfold build at produced
  split at produced <;> rename_i valid
  · cases result : sumEntries sums sumSlots totals amount with
    | none => simp [result] at produced
    | some suffix =>
      simp only [result, Option.map_some, Option.some.injEq] at produced
      subst entries
      have sumLength := sum_entries_length sums sumSlots totals amount suffix result
      obtain ⟨countBound, sumBound, countsLength, sumsLength, totalsLength⟩ := valid
      simp only [List.length_cons, List.length_append, countEntries, List.length_zipWith, countsLength, Nat.min_self]
      omega
  · simp at produced

theorem invalid_shape_refused (claim : Key) (counts : List Key) (countSlots : List Nat) (sums : List Key)
    (sumSlots totals : List Nat) (amount : Nat) (invalid : ¬shape counts countSlots sums sumSlots totals) :
    build claim counts countSlots sums sumSlots totals amount = none := by simp [build, invalid]
end Auths.Product.SlotBatch
