import Auths.Product.NativeCompilerSchemaModel
import Auths.Product.NativeCompilerContainers
import qualification.aeneas.generated.native_recipe.Funs

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

private theorem byte_comparison_suffix (left right : Slice Std.U8)
    (position : Std.Usize) (equal : Bool)
    (sameLength : left.val.length = right.val.length)
    (positionBound : position.val ≤ left.val.length) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.field_name_equal_loop left right position equal ⦃ actual =>
      actual = (equal && decide (left.val.drop position.val = right.val.drop position.val)) ⦄ := by
  generalize remaining : left.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position equal with
  | h count ih =>
    unfold AuthsNativeRecipe.auths_gateway_kernel.construct.field_name_equal_loop
    split <;> rename_i within
    · have inside : position.val < left.val.length := by simpa using within
      cases equal with
      | false => simp
      | true =>
          simp only [Bool.true_eq_true, ↓reduceIte]
          step with Slice.index_usize_spec left position inside as ⟨first, firstAt⟩
          step with Slice.index_usize_spec right position (by omega) as ⟨second, secondAt⟩
          step as ⟨next, nextValue⟩
          have nextBound : next.val ≤ left.val.length := by omega
          have smaller : left.val.length - next.val < count := by omega
          apply spec_mono (ih _ smaller next (decide (first = second)) nextBound rfl)
          intro actual exact
          have leftSuffix : left.val.drop position.val = first :: left.val.drop next.val := by
            simpa only [firstAt, nextValue] using List.drop_eq_getElem_cons inside
          have rightSuffix : right.val.drop position.val = second :: right.val.drop next.val := by
            simpa only [secondAt, nextValue] using List.drop_eq_getElem_cons (show position.val < right.val.length by omega)
          simpa only [leftSuffix, rightSuffix, List.cons.injEq, Bool.true_and, decide_and] using exact
    · have ended : left.val.length ≤ position.val := by simpa using within
      have rightEnded : right.val.length ≤ position.val := by omega
      simp [List.drop_eq_nil_of_le ended, List.drop_eq_nil_of_le rightEnded]

/-- Full original byte equality through the actual native translation. Shared
prefixes, similarly named keys and length differences are all distinguished. -/
@[step] theorem native_schema_byte_equality (left right : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.field_name_equal left right ⦃ actual =>
      actual = decide (schemaSliceBytes left = schemaSliceBytes right) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.construct.field_name_equal
  by_cases sameLength : left.val.length = right.val.length
  · have sameNative : left.len = right.len := by scalar_tac
    simp only [sameNative, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
    apply spec_mono (byte_comparison_suffix left right 0#usize true sameLength (by simp))
    intro actual exact
    simpa only [List.drop_zero, Bool.true_and, native_slice_bytes_equal] using exact
  · have differentNative : left.len ≠ right.len := by
      intro same
      exact sameLength (by simpa using congrArg UScalar.val same)
    have differentBytes : schemaSliceBytes left ≠ schemaSliceBytes right := by
      intro same
      exact sameLength (congrArg List.length ((native_slice_bytes_equal left right).mp same))
    simp [differentNative, differentBytes]

private theorem byte_copy_suffix (input : Slice Std.U8) (output : NativeVec Std.U8)
    (position : Std.Usize) (positionBound : position.val ≤ input.val.length)
    (room : output.val.length + (input.val.length - position.val) ≤ Usize.max) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.append_bytes_loop output input position ⦃ actual =>
      actual.val = output.val ++ input.val.drop position.val ⦄ := by
  generalize remaining : input.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position output with
  | h count ih =>
    unfold AuthsNativeRecipe.auths_gateway_kernel.construct.append_bytes_loop
    split <;> rename_i within
    · have inside : position.val < input.val.length := by simpa using within
      step with Slice.index_usize_spec input position inside as ⟨byte, byteAt⟩
      have capacity : output.val.length < Usize.max := by omega
      step with native_push_exact output byte capacity as ⟨updated, appended⟩
      have updatedLength : updated.val.length = output.val.length + 1 := by
        simp only [appended, List.length_append, List.length_singleton]
      step as ⟨next, nextValue⟩
      have nextBound : next.val ≤ input.val.length := by omega
      have nextRoom : updated.val.length + (input.val.length - next.val) ≤ Usize.max := by omega
      have smaller : input.val.length - next.val < count := by omega
      apply spec_mono (ih _ smaller next updated nextBound nextRoom rfl)
      intro actual exact
      have original : input.val.drop position.val = byte :: input.val.drop next.val := by
        simpa only [byteAt, nextValue] using List.drop_eq_getElem_cons inside
      simpa only [original, appended, List.append_assoc, List.singleton_append] using exact
    · have ended : input.val.length ≤ position.val := by simpa using within
      simp [List.drop_eq_nil_of_le ended]

@[step] theorem native_append_bytes_exact (output : NativeVec Std.U8) (input : Slice Std.U8)
    (room : output.val.length + input.val.length ≤ Usize.max) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.append_bytes output input ⦃ actual =>
      actual.val = output.val ++ input.val ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.construct.append_bytes
  apply spec_mono (byte_copy_suffix input output 0#usize (by simp)
    (by simpa only [Nat.sub_zero] using room))
  intro actual exact
  simpa only [List.drop_zero] using exact

@[step] theorem native_schema_copy_bytes (input : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.copy_bytes input ⦃ actual =>
      actual.val = input.val ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.construct.copy_bytes
    AuthsNativeRecipe.auths_gateway_kernel.construct.append_bytes
  apply spec_mono (byte_copy_suffix input (AuthsNativeRecipe.alloc.vec.Vec.new Std.U8)
    0#usize (by simp) (by simpa only [native_empty_contents, List.length_nil, Nat.zero_add, Nat.sub_zero] using input.property))
  intro actual exact
  simpa only [native_empty_contents, List.drop_zero, List.nil_append] using exact

end Auths.Product.NativeCompiler.Refinement
