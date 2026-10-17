import Auths.Codec.ScopeDuplicate
import Auths.Verifier.StatusLeaves
open Aeneas Aeneas.Std Result
open AuthsScopeCodec
namespace Auths.ScopeConstructor
set_option maxHeartbeats 2000000

theorem vector_index (values : alloc.vec.Vec String) (position : Std.Usize) (value : String)
    (atIndex : values.val[position.val]? = some value) :
    alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice String) values position = ok value := by
  change Slice.index_usize values position = ok value
  simp [Slice.index_usize, atIndex]

theorem duplicate_stopped (values : alloc.vec.Vec String) (position : Std.Usize) :
    AuthsScopeCodec.auths_model.StatusScopeAnchors.new_loop values position true = ok true := by
  rw [AuthsScopeCodec.auths_model.StatusScopeAnchors.new_loop.eq_def]
  simp

theorem duplicate_loop (values : alloc.vec.Vec String) (position : Std.Usize)
    (previous : String) (rest : List String)
    (positive : 0 < position.val) (remaining : values.val.drop position.val = rest)
    (atPrevious : values.val[position.val - 1]? = some previous) :
    AuthsScopeCodec.auths_model.StatusScopeAnchors.new_loop values position false = ok (repeated (previous :: rest)) := by
  induction rest generalizing position previous with
  | nil =>
    have finished : ¬ position < alloc.vec.Vec.len values := by
      have size := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at size
      simp only [UScalar.lt_equiv, alloc.vec.Vec.len_val, alloc.vec.Vec.length]
      omega
    rw [AuthsScopeCodec.auths_model.StatusScopeAnchors.new_loop.eq_def]
    simp [finished, repeated]
  | cons head tail ih =>
    obtain ⟨guard, atHead⟩ := Auths.StatusSelection.indexed_head values position head tail remaining
    obtain ⟨next, step, nextValue, nextRemaining⟩ := Auths.StatusSelection.indexed_next values position head tail remaining
    obtain ⟨before, subtract, beforeValue, _⟩ := Aeneas.Std.WP.spec_imp_exists
      (Usize.sub_spec (x := position) (y := 1#usize) (by simpa using Nat.succ_le_of_lt positive))
    have beforeIndex : values.val[before.val]? = some previous := by simpa [beforeValue] using atPrevious
    have within : position.val < values.val.length := by
      simpa only [UScalar.lt_equiv, Slice.len_val] using guard
    have headValue : values.val[position.val] = head := by
      have split := List.drop_eq_getElem_cons within
      rw [remaining] at split
      exact (List.cons.inj split).1.symm
    have headOption : values.val[position.val]? = some head := by
      rw [List.getElem?_eq_getElem within, headValue]
    have nextPrevious : values.val[next.val - 1]? = some head := by simpa [nextValue] using headOption
    rw [AuthsScopeCodec.auths_model.StatusScopeAnchors.new_loop.eq_def]
    simp only [alloc.vec.Vec.len, guard, ↓reduceIte, subtract, bind_tc_ok,
      vector_index values before previous beforeIndex, vector_index values position head headOption,
      AuthsScopeCodec.auths_model.TrustAnchorId.Insts.CoreCmpPartialEqTrustAnchorId.eq,
      AuthsScopeCodec.alloc.string.String.Insts.CoreCmpPartialEqString.eq,
      _root_.alloc.string.String.Insts.CoreCmpPartialEqString.eq, step]
    cases matched : (previous == head) with
    | true => simp [duplicate_stopped, repeated, matched]
    | false =>
      simpa [repeated, matched] using ih next head (by omega) nextRemaining nextPrevious

theorem duplicate_entry (values : alloc.vec.Vec String) (nonempty : values.val ≠ []) :
    AuthsScopeCodec.auths_model.StatusScopeAnchors.new_loop values 1#usize false = ok (repeated values.val) := by
  cases equation : values.val with
  | nil => contradiction
  | cons previous rest =>
    simpa only [equation] using duplicate_loop values 1#usize previous rest (by simp) (by simp [equation]) (by simp [equation])

theorem repeated_sorted (values : List String) : repeated (Model.sorted values) = decide (¬values.Nodup) := by
  have meaning : repeated (Model.sorted values) = false ↔ values.Nodup :=
    (repeated_false_iff_nodup (Model.sorted values) (Model.sorted_pairwise values)).trans
      (Model.sorted_perm values).nodup_iff
  cases result : repeated (Model.sorted values) <;> simp_all

end Auths.ScopeConstructor
