import Auths.Codec.ProtocolSort
import Auths.Codec.CollectionInvariants

open Aeneas Aeneas.Std
open AuthsProtocolCodec

namespace Auths.Codec.KeyOrder

variable {Key : Type} [Ord Key] [Std.TransOrd Key] [Std.LawfulEqOrd Key]

def LE (left right : Key) : Prop := (compare left right).isLE = true
def LT (left right : Key) : Prop := compare left right = .lt

instance decidableLE : DecidableRel (LE (Key := Key)) := fun _ _ => inferInstanceAs (Decidable (_ = _))

theorem total (left right : Key) : LE left right ∨ LE right left := by
  cases comparison : compare left right with
  | lt => exact Or.inl (by simp [LE, comparison])
  | eq => exact Or.inl (by simp [LE, comparison])
  | gt => exact Or.inr (by simp [LE, Std.OrientedCmp.lt_of_gt comparison])

theorem trans {first middle last : Key} (left : LE first middle) (right : LE middle last) :
    LE first last := Std.TransOrd.isLE_trans left right

theorem antisymmetric (left right : Key) (forward : LE left right) (backward : LE right left) :
    left = right := by
  cases comparison : compare left right with
  | lt => simp [LE, Std.OrientedCmp.gt_of_lt comparison] at backward
  | eq => exact Std.compare_eq_iff_eq.mp comparison
  | gt => simp [LE, comparison] at forward

theorem weak_distinct_strict (left right : Key) (weak : LE left right) (different : left ≠ right) :
    LT left right := by
  cases comparison : compare left right with
  | lt => exact comparison
  | eq => exact False.elim (different (Std.compare_eq_iff_eq.mp comparison))
  | gt => simp [LE, comparison] at weak

theorem ordered_unique_strict (values : List Key) (ordered : values.Pairwise LE)
    (unique : values.Nodup) : values.Pairwise LT := by
  revert ordered unique
  induction values with
  | nil => simp
  | cons first rest ih =>
    intro ordered unique
    obtain ⟨fromFirst, restOrdered⟩ := List.pairwise_cons.mp ordered
    obtain ⟨absent, restUnique⟩ := List.nodup_cons.mp unique
    apply List.pairwise_cons.mpr
    refine ⟨?_, ih restOrdered restUnique⟩
    intro value member
    apply weak_distinct_strict first value (fromFirst value member)
    intro same
    exact absent (same.symm ▸ member)

theorem sorted_keys {T : Type} (view : T → Key) (values : alloc.vec.Vec T) :
    ((ProtocolSort.sortedVector (fun left right => compare (view left) (view right)) values).val.map view).Pairwise LE := by
  let relation : T → T → Prop := fun left right => LE (view left) (view right)
  letI : Std.Total relation := ⟨fun left right => total (view left) (view right)⟩
  letI : IsTrans T relation := ⟨fun _ _ _ left right => trans left right⟩
  rw [ProtocolSort.sorted_vector_contents]
  have ordered := List.pairwise_insertionSort relation values.val
  simpa [List.pairwise_map, relation, ProtocolSort.relation, LE] using ordered

theorem sorted_clean_unique {T : Type} [DecidableEq Key] (view : T → Key)
    (values : alloc.vec.Vec T)
    (clean : CollectionInvariants.adjacent
      ((ProtocolSort.sortedVector (fun left right => compare (view left) (view right)) values).val.map view) = false) :
    ((ProtocolSort.sortedVector (fun left right => compare (view left) (view right)) values).val.map view).Nodup :=
  (CollectionInvariants.adjacent_false_nodup LE antisymmetric _ (sorted_keys view values)).mp clean

theorem sorted_clean_strict {T : Type} [DecidableEq Key] (view : T → Key)
    (values : alloc.vec.Vec T)
    (clean : CollectionInvariants.adjacent
      ((ProtocolSort.sortedVector (fun left right => compare (view left) (view right)) values).val.map view) = false) :
    ((ProtocolSort.sortedVector (fun left right => compare (view left) (view right)) values).val.map view).Pairwise LT :=
  ordered_unique_strict _ (sorted_keys view values) (sorted_clean_unique view values clean)

end Auths.Codec.KeyOrder
