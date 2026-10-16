import Auths.Codec.ScopeLoop
open Aeneas Aeneas.Std Result
open AuthsScopeCodec
namespace Auths.ScopeConstructor
set_option maxHeartbeats 2000000

def sortedVector (values : alloc.vec.Vec String) : alloc.vec.Vec String :=
  ⟨Model.sorted values.val, by rw [Model.sorted_length]; exact values.property⟩

def expectedConstructor (values : alloc.vec.Vec String) :
    Aeneas.Std.core.result.Result (alloc.vec.Vec String) AuthsScopeCodec.auths_model.ModelError :=
  if values.val.isEmpty || Model.maximum < values.val.length || decide (¬values.val.Nodup) then
    .Err .InvalidStatusSnapshot
  else .Ok (sortedVector values)

/-- Exact total source result, with independent list validity; no source
    success, caller ordering or desired-output premise. -/
theorem constructor_refines (values : alloc.vec.Vec String) :
    AuthsScopeCodec.auths_model.StatusScopeAnchors.new values = ok (expectedConstructor values) := by
  unfold AuthsScopeCodec.auths_model.StatusScopeAnchors.new
  simp only [AuthsScopeCodec.alloc.vec.Vec.is_empty, _root_.alloc.vec.Vec.is_empty, bind_tc_ok]
  by_cases empty : values.val.isEmpty = true
  · simp [empty, expectedConstructor]
  · simp only [empty]
    have maximum : AuthsScopeCodec.auths_model.HARD_MAX_TRUST_ANCHORS.val = Model.maximum := by
      simp [AuthsScopeCodec.auths_model.HARD_MAX_TRUST_ANCHORS, Model.maximum]
    simp only [UScalar.lt_equiv, alloc.vec.Vec.len_val, alloc.vec.Vec.length, maximum]
    by_cases oversized : Model.maximum < values.val.length
    · simp [oversized, expectedConstructor, empty]
    · simp only [oversized, Bool.false_eq_true, ↓reduceIte]
      change (do
        let sorted ← AuthsScopeCodec.alloc.slice.Slice.sort
          AuthsScopeCodec.auths_model.TrustAnchorId.Insts.CoreCmpOrd (values : Slice String)
        let duplicate ← AuthsScopeCodec.auths_model.StatusScopeAnchors.new_loop
          (sorted : alloc.vec.Vec String) 1#usize false
        let result ← if duplicate then ok (Aeneas.Std.core.result.Result.Err AuthsScopeCodec.auths_model.ModelError.InvalidStatusSnapshot)
          else ok (Aeneas.Std.core.result.Result.Ok (sorted : alloc.vec.Vec String))
        if duplicate then ok result else ok result) = ok (expectedConstructor values)
      rw [anchor_sort]
      simp only [bind_tc_ok]
      have nonempty : (sortedVector values).val ≠ [] := by
        have length := Model.sorted_length values.val
        simp only [sortedVector]
        intro absent
        have zero := congrArg List.length absent
        simp only [List.length_nil] at zero
        have original : values.val = [] := List.length_eq_zero_iff.mp (length.symm.trans zero)
        simp [original] at empty
      have loop := duplicate_entry (sortedVector values) nonempty
      unfold sortedVector at loop
      rw [loop]
      simp only [repeated_sorted, bind_tc_ok]
      cases valid : decide (¬values.val.Nodup) <;>
        simp [valid, expectedConstructor, empty, oversized, sortedVector] <;> rfl

end Auths.ScopeConstructor
