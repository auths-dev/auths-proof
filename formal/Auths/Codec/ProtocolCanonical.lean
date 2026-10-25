import qualification.aeneas.generated.protocol_codec.Funs

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Codec.ProtocolCanonical

private theorem bytes_ne_exact (left right : Slice Std.U8) :
    core.cmp.impls.PartialEqShared.ne
      (Slice.Insts.CoreCmpPartialEqSlice core.cmp.PartialEqU8) left right
      ⦃ result => result = decide (left ≠ right) ⦄ := by
  have equality := core.slice.cmp.PartialEqSlice.eq_homo_spec
    core.cmp.PartialEqU8 left right (by intro x y; simp [core.cmp.PartialEqU8])
  have comparison := core.cmp.PartialEq.ne.trait_default.spec
    (Slice.Insts.CoreCmpPartialEqSlice core.cmp.PartialEqU8) left right equality
  apply spec_mono comparison
  intro result meaning
  cases result <;> simp_all

/-- Complete source behavior for any carried value and mismatch code. No
expected comparison, encoder or decoder outcome is assumed. Supplying actual
encoder output and earning constructor validity are caller obligations. -/
@[step] theorem with_error_exact {Carrier : Type} (input : Slice Std.U8)
    (encoded : alloc.vec.Vec Std.U8) (value : Carrier) (mismatch : error.CodecError) :
    canonical.accept_with_error input encoded value mismatch ⦃ actual =>
      actual = if encoded.val = input.val then .Ok value else .Err mismatch ⦄ := by
  unfold canonical.accept_with_error
  simp only [alloc.vec.Vec.as_slice, bind_tc_ok]
  step with bytes_ne_exact (alloc.vec.Vec.deref encoded) input as ⟨different, meaning⟩
  by_cases same : encoded.val = input.val
  · have borrowed : alloc.vec.Vec.deref encoded = input := Subtype.ext same
    simp [meaning, borrowed, same]
  · have borrowed : alloc.vec.Vec.deref encoded ≠ input := by
      intro equality
      exact same (congrArg Subtype.val equality)
    simp [meaning, borrowed, same]

@[step] theorem accept_exact {Carrier : Type} (input : Slice Std.U8)
    (encoded : alloc.vec.Vec Std.U8) (value : Carrier) :
    canonical.accept input encoded value ⦃ actual =>
      actual = if encoded.val = input.val then .Ok value else .Err .NonCanonical ⦄ := by
  simpa only [canonical.accept] using with_error_exact input encoded value .NonCanonical

/-- Byte identity and unchanged value follow from actual acceptance. This is
not a substitute for a public decoder's validity, totality or inverse proof. -/
theorem accepted_preserves {Carrier : Type} (input : Slice Std.U8)
    (encoded : alloc.vec.Vec Std.U8) (value output : Carrier)
    (accepted : canonical.accept input encoded value = ok (.Ok output)) :
    encoded.val = input.val ∧ output = value := by
  have behavior := accept_exact input encoded value
  rw [accepted] at behavior
  simp only [spec_ok] at behavior
  by_cases same : encoded.val = input.val
  · exact ⟨same, by simpa [same] using behavior⟩
  · simp [same] at behavior

/-- Result-graph form used to discharge complete public-wrapper guards. -/
theorem with_error_result {Carrier : Type} (input : Slice Std.U8)
    (encoded : alloc.vec.Vec Std.U8) (value : Carrier) (mismatch : error.CodecError) :
    canonical.accept_with_error input encoded value mismatch =
      ok (if encoded.val = input.val then .Ok value else .Err mismatch) := by
  obtain ⟨actual, evaluates, meaning⟩ := spec_imp_exists (with_error_exact input encoded value mismatch)
  simpa only [meaning] using evaluates

theorem accept_result {Carrier : Type} (input : Slice Std.U8)
    (encoded : alloc.vec.Vec Std.U8) (value : Carrier) :
    canonical.accept input encoded value =
      ok (if encoded.val = input.val then .Ok value else .Err .NonCanonical) := by
  simpa only [canonical.accept] using with_error_result input encoded value .NonCanonical

end Auths.Codec.ProtocolCanonical
