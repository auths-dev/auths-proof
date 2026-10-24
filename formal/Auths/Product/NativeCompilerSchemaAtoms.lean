import Auths.Product.NativeCompilerSchemaNames

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

@[step] theorem native_schema_alphanumeric_exact (byte : Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.is_alphanumeric byte ⦃ actual =>
      actual = decide (OperationIdentity.Alphanumeric byte.val) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.construct.is_alphanumeric OperationIdentity.Alphanumeric
  repeat' split
  all_goals simp_all [UScalar.le_equiv]

private theorem native_token_tail (input : Slice Std.U8) (position : Std.Usize) (valid : Bool)
    (positive : 0 < position.val) (positionBound : position.val ≤ input.val.length) :
    AuthsNativeRecipe.auths_gateway_kernel.identity.valid_token_loop input position valid ⦃ actual =>
      actual = (valid && decide (∀ byte ∈ input.val.drop position.val, OperationIdentity.TailByte byte.val)) ⦄ := by
  generalize remaining : input.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position valid with
  | h count ih =>
    unfold AuthsNativeRecipe.auths_gateway_kernel.identity.valid_token_loop
    split <;> rename_i within
    · have inside : position.val < input.val.length := by simpa using within
      cases valid with
      | false => simp
      | true =>
          simp only [Bool.true_eq_true, ↓reduceIte]
          step with Slice.index_usize_spec input position inside as ⟨byte, byteAt⟩
          step with native_schema_alphanumeric_exact byte as ⟨alpha, alphaMeaning⟩
          have nativePositive : position > 0#usize := by scalar_tac
          have originalSuffix : input.val.drop position.val = byte :: input.val.drop (position.val + 1) := by
            simpa only [byteAt] using List.drop_eq_getElem_cons inside
          have recurse (next : Std.Usize) (nextValue : next.val = position.val + 1) (flag : Bool) :
              AuthsNativeRecipe.auths_gateway_kernel.identity.valid_token_loop input next flag ⦃ actual =>
                actual = (flag && decide (∀ byte ∈ input.val.drop next.val, OperationIdentity.TailByte byte.val)) ⦄ := by
            exact ih _ (by omega) next flag (by omega) (by omega) rfl
          repeat' first | step with recurse | step | split
          all_goals simp_all [originalSuffix, OperationIdentity.TailByte, nativePositive,
            UScalar.eq_equiv, Bool.and_assoc, decide_and]
    · have ended : input.val.length ≤ position.val := by simpa using within
      simp [List.drop_eq_nil_of_le ended]

@[step] theorem native_schema_token_exact (input : Slice Std.U8) (maximum : Std.Usize) :
    AuthsNativeRecipe.auths_gateway_kernel.identity.valid_token input maximum ⦃ actual =>
      actual = OperationIdentity.validToken (schemaSliceBytes input) maximum.val ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.identity.valid_token
  cases original : input.val with
  | nil => simp [core.slice.Slice.is_empty, original, schemaSliceBytes, OperationIdentity.validToken]
  | cons first rest =>
      simp only [core.slice.Slice.is_empty, original, List.isEmpty_cons, bind_tc_ok,
        Bool.false_eq_true, ↓reduceIte]
      by_cases large : maximum.val < input.val.length
      · have nativeLarge : input.len > maximum := by scalar_tac
        simp [nativeLarge, schemaSliceBytes, original, OperationIdentity.validToken, Nat.not_le.mpr large]
      · have bound : input.val.length ≤ maximum.val := by omega
        have nativeBound : ¬input.len > maximum := by scalar_tac
        simp only [nativeBound, ↓reduceIte]
        unfold AuthsNativeRecipe.auths_gateway_kernel.identity.valid_token_loop
        have inside : 0 < input.val.length := by simp only [original, List.length_cons]; omega
        have nativeInside : 0#usize < input.len := by scalar_tac
        simp only [nativeInside, Bool.true_eq_true, ↓reduceIte]
        step with Slice.index_usize_spec input 0#usize inside as ⟨byte, byteAt⟩
        have originalByte : byte = first := by simpa only [original] using byteAt
        step with native_schema_alphanumeric_exact byte as ⟨alpha, alphaMeaning⟩
        have recurse (next : Std.Usize) (nextValue : next.val = 1) (flag : Bool) :
            AuthsNativeRecipe.auths_gateway_kernel.identity.valid_token_loop input next flag ⦃ actual =>
              actual = (flag && decide (∀ byte ∈ rest, OperationIdentity.TailByte byte.val)) ⦄ := by
          apply spec_mono (native_token_tail input next flag (by omega) (by simp only [original, List.length_cons]; omega))
          intro actual exact
          simpa only [nextValue, original, List.drop_succ_cons, List.drop_zero] using exact
        repeat' first | step with recurse | step | split
        all_goals simp_all [schemaSliceBytes, original, originalByte, OperationIdentity.validToken,
          List.all_eq_true, Bool.eq_iff_iff, List.forall_mem_map]

@[step] theorem native_schema_enum_byte_exact (byte : Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.scalars.enum_byte_valid byte ⦃ actual =>
      actual = decide (ScalarProjection.EnumByte byte.val) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.scalars.enum_byte_valid
  step with native_schema_alphanumeric_exact byte as ⟨alpha, meaning⟩
  repeat' split
  all_goals simp_all [ScalarProjection.EnumByte, OperationIdentity.Alphanumeric,
    UScalar.eq_equiv]

private theorem native_enum_variant_suffix (input : Slice Std.U8) (position : Std.Usize)
    (positionBound : position.val ≤ input.val.length) :
    AuthsNativeRecipe.auths_gateway_kernel.scalars.enum_variant_valid_loop input position ⦃ actual =>
      actual = decide (∀ byte ∈ input.val.drop position.val, ScalarProjection.EnumByte byte.val) ⦄ := by
  generalize remaining : input.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position with
  | h count ih =>
    unfold AuthsNativeRecipe.auths_gateway_kernel.scalars.enum_variant_valid_loop
    split <;> rename_i within
    · have inside : position.val < input.val.length := by simpa using within
      step with Slice.index_usize_spec input position inside as ⟨byte, byteAt⟩
      step with native_schema_enum_byte_exact byte as ⟨valid, validMeaning⟩
      have originalSuffix : input.val.drop position.val = byte :: input.val.drop (position.val + 1) := by
        simpa only [byteAt] using List.drop_eq_getElem_cons inside
      cases valid with
      | false =>
          have invalid : ¬ScalarProjection.EnumByte byte.val := by simpa using validMeaning.symm
          simp [originalSuffix, invalid]
      | true =>
          have allowed : ScalarProjection.EnumByte byte.val := by simpa using validMeaning.symm
          simp only [Bool.true_eq_true, ↓reduceIte]
          step as ⟨next, nextValue⟩
          apply spec_mono (ih _ (by omega) next (by omega) rfl)
          intro actual exact
          simpa [originalSuffix, allowed, nextValue] using exact
    · have ended : input.val.length ≤ position.val := by simpa using within
      simp [List.drop_eq_nil_of_le ended]

@[step] theorem native_schema_enum_variant_exact (input : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.scalars.enum_variant_valid input ⦃ actual =>
      actual = decide (ScalarProjection.EnumVariant (schemaSliceBytes input)) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.scalars.enum_variant_valid
    AuthsNativeRecipe.auths_gateway_kernel.scalars.MAX_ENUM_BYTES
  by_cases empty : input.val = []
  · simp [empty, core.slice.Slice.is_empty, ScalarProjection.EnumVariant, schemaSliceBytes]
  · have nonempty : 0 < input.val.length := List.length_pos.mpr empty
    simp only [core.slice.Slice.is_empty, List.isEmpty_eq_false.mpr empty, bind_tc_ok,
      Bool.false_eq_true, ↓reduceIte]
    by_cases large : 64 < input.val.length
    · have nativeLarge : input.len > 64#usize := by scalar_tac
      simp [nativeLarge, ScalarProjection.EnumVariant, schemaSliceBytes, Nat.not_le.mpr large]
    · have bound : input.val.length ≤ 64 := by omega
      have nativeBound : ¬input.len > 64#usize := by scalar_tac
      simp only [nativeBound, ↓reduceIte]
      apply spec_mono (native_enum_variant_suffix input 0#usize (by simp))
      intro actual exact
      simpa only [List.drop_zero, ScalarProjection.EnumVariant, schemaSliceBytes,
        List.length_map, nonempty, bound, true_and, List.forall_mem_map] using exact

private theorem native_enum_schema_suffix (variants : Slice (NativeVec Std.U8)) (position : Std.Usize)
    (positionBound : position.val ≤ variants.val.length) :
    AuthsNativeRecipe.auths_gateway_kernel.scalars.enum_schema_valid_loop variants position ⦃ actual =>
      actual = decide (∀ variant ∈ variants.val.drop position.val, ScalarProjection.EnumVariant (bytes variant)) ⦄ := by
  generalize remaining : variants.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position with
  | h count ih =>
    unfold AuthsNativeRecipe.auths_gateway_kernel.scalars.enum_schema_valid_loop
    split <;> rename_i within
    · have inside : position.val < variants.val.length := by simpa using within
      step with Slice.index_usize_spec variants position inside as ⟨variant, variantAt⟩
      step with native_schema_enum_variant_exact (AuthsNativeRecipe.alloc.vec.Vec.deref variant) as ⟨valid, validMeaning⟩
      have originalSuffix : variants.val.drop position.val = variant :: variants.val.drop (position.val + 1) := by
        simpa only [variantAt] using List.drop_eq_getElem_cons inside
      have byteMeaning : valid = decide (ScalarProjection.EnumVariant (bytes variant)) := by
        simpa only [schemaSliceBytes, bytes, native_deref_contents] using validMeaning
      cases valid with
      | false =>
          have invalid : ¬ScalarProjection.EnumVariant (bytes variant) := by simpa using byteMeaning.symm
          simp [originalSuffix, invalid]
      | true =>
          have allowed : ScalarProjection.EnumVariant (bytes variant) := by simpa using byteMeaning.symm
          simp only [Bool.true_eq_true, ↓reduceIte]
          step as ⟨next, nextValue⟩
          apply spec_mono (ih _ (by omega) next (by omega) rfl)
          intro actual exact
          simpa [originalSuffix, allowed, nextValue] using exact
    · have ended : variants.val.length ≤ position.val := by simpa using within
      simp [List.drop_eq_nil_of_le ended]

@[step] theorem native_schema_enum_limits_exact (variants : Slice (NativeVec Std.U8)) :
    AuthsNativeRecipe.auths_gateway_kernel.scalars.enum_schema_valid variants ⦃ actual =>
      actual = decide (ScalarProjection.EnumSchema (nativeNameColumn variants)) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.scalars.enum_schema_valid
    AuthsNativeRecipe.auths_gateway_kernel.scalars.MAX_ENUM_VARIANTS
  by_cases empty : variants.val = []
  · simp [empty, core.slice.Slice.is_empty, ScalarProjection.EnumSchema, nativeNameColumn]
  · have nonempty : 0 < variants.val.length := List.length_pos.mpr empty
    simp only [core.slice.Slice.is_empty, List.isEmpty_eq_false.mpr empty, bind_tc_ok,
      Bool.false_eq_true, ↓reduceIte]
    by_cases large : 32 < variants.val.length
    · have nativeLarge : variants.len > 32#usize := by scalar_tac
      simp [nativeLarge, ScalarProjection.EnumSchema, nativeNameColumn, Nat.not_le.mpr large]
    · have bound : variants.val.length ≤ 32 := by omega
      have nativeBound : ¬variants.len > 32#usize := by scalar_tac
      simp only [nativeBound, ↓reduceIte]
      step with native_schema_unique_names_exact variants as ⟨unique, uniqueMeaning⟩
      cases unique with
      | false =>
          have duplicate : ¬(nativeNameColumn variants).Nodup := by simpa using uniqueMeaning.symm
          simp [ScalarProjection.EnumSchema, duplicate]
      | true =>
          have distinct : (nativeNameColumn variants).Nodup := by simpa using uniqueMeaning.symm
          simp only [Bool.true_eq_true, ↓reduceIte]
          apply spec_mono (native_enum_schema_suffix variants 0#usize (by simp))
          intro actual exact
          simpa only [List.drop_zero, ScalarProjection.EnumSchema, nativeNameColumn,
            List.length_map, nonempty, bound, distinct, true_and, List.forall_mem_map] using exact

end Auths.Product.NativeCompiler.Refinement
