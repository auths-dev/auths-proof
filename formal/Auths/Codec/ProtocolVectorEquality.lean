import Auths.Support.ProtocolVec
import Mathlib.Tactic

open Aeneas Aeneas.Std Result
open AuthsProtocolCodec

namespace Auths.Codec.ProtocolVectorEquality

private theorem lists_exact {T Key : Type} [DecidableEq Key]
    (comparison : core.cmp.PartialEq T T) (view : T → Key)
    (law : ∀ left right, comparison.eq left right = ok (decide (view left = view right)))
    (left right : List T) :
    (if left.length = right.length then
      List.allM (fun pair => comparison.eq pair.1 pair.2) (left.zip right) else ok false) =
      ok (decide (left.map view = right.map view)) := by
  induction left generalizing right with
  | nil => cases right <;> simp
  | cons first rest ih =>
    cases right with
    | nil => simp
    | cons other tail =>
      by_cases lengths : rest.length = tail.length
      · simp only [List.length_cons, Nat.succ_inj, lengths, ↓reduceIte,
          List.zip_cons_cons, List.allM_cons, law, bind_tc_ok]
        by_cases heads : view first = view other
        · have remaining := ih tail
          simp only [lengths, ↓reduceIte] at remaining
          simpa [heads, List.map_cons] using remaining
        · simp [heads, List.map_cons]
      · have unequal : (first :: rest).map view ≠ (other :: tail).map view := by
          intro same
          have sameLengths := congrArg List.length same
          simp only [List.length_map, List.length_cons, Nat.succ_inj] at sameLengths
          exact lengths sameLengths
        simp [lengths, unequal]

/-- Exact reviewed standard-vector equality transported through the positive
carrier isomorphism. The logical keys preserve signed order and every element;
the source element-comparison law is discharged separately. -/
theorem source_exact {T Key : Type} [DecidableEq Key]
    (comparison : core.cmp.PartialEq T T) (view : T → Key)
    (law : ∀ left right, comparison.eq left right = ok (decide (view left = view right)))
    (left right : alloc.vec.Vec T) :
    alloc.vec.partial_eq.PartialEqVec.eq comparison left right =
      ok (decide (left.val.map view = right.val.map view)) := by
  unfold alloc.vec.partial_eq.PartialEqVec.eq Aeneas.Std.alloc.vec.partial_eq.PartialEqVec.eq
  change (if left.val.length = right.val.length then
    List.allM (fun pair => comparison.eq pair.1 pair.2) (left.val.zip right.val) else ok false) = _
  exact lists_exact comparison view law left.val right.val

theorem byte_law (left right : Std.U8) :
    core.cmp.PartialEqU8.eq left right = ok (decide (left.val = right.val)) := by
  simp [core.cmp.PartialEqU8, UScalar.eq_equiv]

theorem bytes_exact (left right : alloc.vec.Vec Std.U8) :
    alloc.vec.partial_eq.PartialEqVec.eq core.cmp.PartialEqU8 left right =
      ok (decide (left.val.map UScalar.val = right.val.map UScalar.val)) :=
  source_exact core.cmp.PartialEqU8 UScalar.val byte_law left right

end Auths.Codec.ProtocolVectorEquality
