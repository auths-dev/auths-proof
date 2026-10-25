import qualification.aeneas.generated.composition.Funs
import Mathlib.Data.List.Lex
open Aeneas Aeneas.Std Result
namespace Auths.Composition.Order

abbrev listComparison {T : Type} := @Array.Insts.CoreCmpOrd.compareValues T

theorem array_comparison {T : Type} {N : Std.Usize} (order : core.cmp.Ord T)
    (left right : Array T N) :
    Array.Insts.CoreCmpOrd.cmp order left right = listComparison order left.val right.val := by
  rfl

theorem byte_comparison (left right : Std.U8) :
    core.cmp.OrdU8.cmp left right = ok (compare left.val right.val) := rfl

theorem bytes_comparison (left right : List Std.U8) :
    listComparison core.cmp.OrdU8 left right =
      ok (List.compareLex compare (left.map UScalar.val) (right.map UScalar.val)) := by
  unfold listComparison
  induction left generalizing right with
  | nil => cases right <;> rfl
  | cons head tail ih =>
    cases right with
    | nil => rfl
    | cons other rest =>
      rw [Array.Insts.CoreCmpOrd.compareValues_cons_cons, byte_comparison]
      simp only [bind_tc_ok, List.map_cons]
      cases comparison : compare head.val other.val <;>
        simp [comparison, ih, List.compareLex]

def referenceKey (reference : auths_composition.auths_model.ProofRef) : List Nat :=
  reference.val.map UScalar.val

theorem reference_key_injective : Function.Injective referenceKey := by
  intro left right same
  apply Subtype.ext
  apply (List.map_injective_iff.mpr (show Function.Injective (fun byte : Std.U8 => byte.val) from by
    intro first second equal
    scalar_tac))
  exact same

instance referenceDecidableEq : DecidableEq auths_composition.auths_model.ProofRef :=
  fun left right => decidable_of_iff (referenceKey left = referenceKey right)
    reference_key_injective.eq_iff

theorem reference_comparison (left right : auths_composition.auths_model.ProofRef) :
    auths_composition.auths_model.ProofRef.Insts.CoreCmpOrd.cmp left right =
      ok (List.compareLex compare (referenceKey left) (referenceKey right)) := by
  unfold auths_composition.auths_model.ProofRef.Insts.CoreCmpOrd.cmp
    auths_composition.auths_model.Digest.Insts.CoreCmpOrd.cmp
  rw [array_comparison]
  exact bytes_comparison left.val right.val

theorem nat_lists_lt (left right : List Nat) :
    List.compareLex compare left right = .lt ↔ left < right := by
  induction left generalizing right with
  | nil => cases right <;> simp [List.compareLex]
  | cons head tail ih =>
    cases right with
    | nil => simp [List.compareLex]
    | cons other rest =>
      rw [List.compareLex_cons_cons, List.cons_lt_cons_iff]
      cases comparison : compare head other with
      | lt =>
        have less := compare_lt_iff_lt.mp comparison
        simp [less]
      | eq =>
        have same := compare_eq_iff_eq.mp comparison
        subst other
        simpa using ih rest
      | gt =>
        have more := compare_gt_iff_gt.mp comparison
        have notLess := not_lt_of_gt more
        have different := ne_of_gt more
        simp [notLess, different]

theorem nat_lists_eq (left right : List Nat) :
    List.compareLex compare left right = .eq ↔ left = right := by
  induction left generalizing right with
  | nil => cases right <;> simp [List.compareLex]
  | cons head tail ih =>
    cases right with
    | nil => simp [List.compareLex]
    | cons other rest =>
      rw [List.compareLex_cons_cons, Ordering.then_eq_eq]
      simp [ih]

theorem nat_lists_gt (left right : List Nat) :
    List.compareLex compare left right = .gt ↔ right < left := by
  induction left generalizing right with
  | nil => cases right <;> simp [List.compareLex]
  | cons head tail ih =>
    cases right with
    | nil => simp [List.compareLex]
    | cons other rest =>
      rw [List.compareLex_cons_cons, List.cons_lt_cons_iff]
      cases comparison : compare head other with
      | lt =>
        have less := compare_lt_iff_lt.mp comparison
        have notMore := not_lt_of_gt less
        have different := ne_of_gt less
        simp [notMore, different]
      | eq =>
        have same := compare_eq_iff_eq.mp comparison
        subst other
        simpa using ih rest
      | gt =>
        have more := compare_gt_iff_gt.mp comparison
        simp [more]

end Auths.Composition.Order
