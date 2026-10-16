import Auths.Verifier.StatusGrant
import Auths.Verifier.StatusSearchFound
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsStatusSelection
namespace Auths.StatusSelection.Search

def hit : Aeneas.Std.core.result.Result Nat Nat → Bool
  | .Ok _ => true
  | .Err _ => false

def index : Aeneas.Std.core.result.Result Nat Nat → Nat
  | .Ok value => value
  | .Err value => value

theorem anchor_compare (left right : String) :
    AuthsStatusSelection.auths_model.TrustAnchorId.Insts.CoreCmpOrd.cmp left right =
      ok (compare left right) := rfl

theorem search_loop (values : List String) (target : String) (fuel base size : Nat)
    (ordered : Ordered values) (positive : 0 < size) (enough : size < fuel)
    (bounded : base + size ≤ values.length) :
    ∃ result,
      AuthsStatusSelection.binarySearchLoop AuthsStatusSelection.auths_model.TrustAnchorId.Insts.CoreCmpOrd
        values target fuel base size = ok result ∧
      (hit result = true ↔ Found values target base size) ∧ index result ≤ base + size := by
  induction fuel generalizing base size with
  | zero => omega
  | succ fuel ih =>
    rw [AuthsStatusSelection.binarySearchLoop]
    by_cases large : 1 < size
    · have midBound : base + size / 2 < values.length := by omega
      let value := values[base + size / 2]
      have atMid : values[base + size / 2]? = some value := List.getElem?_eq_getElem midBound
      simp only [large, ↓reduceIte, atMid, bind_tc_ok, anchor_compare]
      let nextBase := if compare value target = .gt then base else base + size / 2
      have nextPositive : 0 < size - size / 2 := by omega
      have nextEnough : size - size / 2 < fuel := by omega
      have nextBound : nextBase + (size - size / 2) ≤ values.length := by
        dsimp only [nextBase]; split_ifs <;> omega
      obtain ⟨result, equation, meaning, resultBound⟩ := ih nextBase (size - size / 2)
        nextPositive nextEnough nextBound
      refine ⟨result, equation, meaning.trans (found_step values target value base size ordered large atMid).symm, ?_⟩
      dsimp only [nextBase] at resultBound
      split_ifs at resultBound <;> omega
    · have one : size = 1 := by omega
      have baseBound : base < values.length := by omega
      let value := values[base]
      have atBase : values[base]? = some value := List.getElem?_eq_getElem baseBound
      simp only [large, ↓reduceIte, atBase, bind_tc_ok, anchor_compare]
      have meaning : (compare value target = .eq) ↔ Found values target base size := by
        rw [one, found_one values target value base atBase, Std.compare_eq_iff_eq]
      cases comparison : compare value target <;>
        simp only [reduceCtorEq, ↓reduceIte]
      · exact ⟨.Err (base + 1), rfl, by simpa [hit, comparison] using meaning, by simp only [index]; omega⟩
      · exact ⟨.Ok base, rfl, by simpa [hit, comparison] using meaning, by simp only [index]; omega⟩
      · exact ⟨.Err base, by simp, by simpa [hit, comparison] using meaning, by simp only [index]; omega⟩

end Auths.StatusSelection.Search
