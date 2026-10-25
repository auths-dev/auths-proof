import Auths.Product.NativeCompilerEncoding

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open RequestConstruction
set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

private theorem native_json_escape_suffix (output : NativeVec Std.U8) (text : Slice Std.U8)
    (index : Std.Usize) (indexBound : index.val ≤ text.val.length)
    (room : output.val.length + (jsonEscape ((schemaSliceBytes text).drop index.val)).length ≤ Usize.max) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.append_json_escaped_loop output text index ⦃ actual =>
      bytes actual = bytes output ++ jsonEscape ((schemaSliceBytes text).drop index.val) ⦄ := by
  generalize remaining : text.val.length - index.val = count
  induction count using Nat.strong_induction_on generalizing output index with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.construct.append_json_escaped_loop
      by_cases inside : index.val < text.val.length
      · have nativeInside : index < text.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        step with Slice.index_usize_spec text index inside as ⟨byte, byteAt⟩
        have suffix : (schemaSliceBytes text).drop index.val = byte.val ::
            (schemaSliceBytes text).drop (index.val + 1) := by
          simpa [schemaSliceBytes, byteAt, List.drop_map] using
            congrArg (List.map (fun byte : Std.U8 => byte.val)) (List.drop_eq_getElem_cons inside)
        have capacity : output.val.length + (jsonByte byte.val).length ≤ Usize.max := by
          simp only [suffix, jsonEscape, List.flatMap_cons, List.length_append] at room
          omega
        step with native_json_byte_exact output byte capacity as ⟨grown, grownMeaning⟩
        step as ⟨next, nextMeaning⟩
        have grownLength : grown.val.length = output.val.length + (jsonByte byte.val).length := by
          have size := congrArg List.length grownMeaning
          simpa [bytes] using size
        have nextRoom : grown.val.length + (jsonEscape ((schemaSliceBytes text).drop next.val)).length ≤ Usize.max := by
          simp only [suffix, jsonEscape, List.flatMap_cons, List.length_append] at room
          simpa [grownLength, nextMeaning, Nat.add_assoc] using room
        apply spec_mono (ih _ (by omega) grown next (by omega) nextRoom rfl)
        intro actual exact
        simpa [suffix, jsonEscape, List.flatMap_cons, nextMeaning, grownMeaning, List.append_assoc] using exact
      · have ended : index.val = text.val.length := by omega
        have nativeEnded : ¬index < text.len := by scalar_tac
        simp [nativeEnded, schemaSliceBytes, List.drop_map, ended, jsonEscape]

@[step] theorem native_json_escape_exact (output : NativeVec Std.U8) (text : Slice Std.U8)
    (room : output.val.length + (jsonEscape (schemaSliceBytes text)).length ≤ Usize.max) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.append_json_escaped output text ⦃ actual =>
      bytes actual = bytes output ++ jsonEscape (schemaSliceBytes text) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.construct.append_json_escaped
  apply spec_mono (native_json_escape_suffix output text 0#usize (by simp) (by simpa using room))
  intro actual exact
  simpa only [List.drop_zero] using exact

@[step] theorem native_json_string_exact (output : NativeVec Std.U8) (text : Slice Std.U8)
    (room : output.val.length + (jsonString (schemaSliceBytes text)).length ≤ Usize.max) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.append_json_string output text ⦃ actual =>
      bytes actual = bytes output ++ jsonString (schemaSliceBytes text) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.construct.append_json_string
  have capacity : output.val.length < Usize.max := by
    simp only [jsonString, List.length_cons, List.length_append, List.length_singleton] at room
    omega
  step with native_push_exact output 34#u8 capacity as ⟨prefix, prefixMeaning⟩
  have escapeRoom : prefix.val.length + (jsonEscape (schemaSliceBytes text)).length ≤ Usize.max := by
    simp only [prefixMeaning, List.length_append, List.length_singleton]
    simp only [jsonString, List.length_cons, List.length_append, List.length_singleton] at room
    omega
  step with native_json_escape_exact prefix text escapeRoom as ⟨escaped, escapedMeaning⟩
  have finalRoom : escaped.val.length < Usize.max := by
    have size := congrArg List.length escapedMeaning
    simp only [bytes, List.length_map, List.length_append, prefixMeaning,
      List.length_singleton] at size
    simp only [jsonString, List.length_cons, List.length_append, List.length_singleton] at room
    omega
  step with native_push_exact escaped 34#u8 finalRoom as ⟨actual, exact⟩
  simp [bytes, exact, escapedMeaning, prefixMeaning, jsonString, List.map_append, List.append_assoc]

private theorem native_form_encode_suffix (output : NativeVec Std.U8) (text : Slice Std.U8)
    (index : Std.Usize) (indexBound : index.val ≤ text.val.length)
    (room : output.val.length + (formEncode ((schemaSliceBytes text).drop index.val)).length ≤ Usize.max) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.append_form_encoded_loop output text index ⦃ actual =>
      bytes actual = bytes output ++ formEncode ((schemaSliceBytes text).drop index.val) ⦄ := by
  generalize remaining : text.val.length - index.val = count
  induction count using Nat.strong_induction_on generalizing output index with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.construct.append_form_encoded_loop
      by_cases inside : index.val < text.val.length
      · have nativeInside : index < text.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        step with Slice.index_usize_spec text index inside as ⟨byte, byteAt⟩
        have suffix : (schemaSliceBytes text).drop index.val = byte.val ::
            (schemaSliceBytes text).drop (index.val + 1) := by
          simpa [schemaSliceBytes, byteAt, List.drop_map] using
            congrArg (List.map (fun byte : Std.U8 => byte.val)) (List.drop_eq_getElem_cons inside)
        have capacity : output.val.length + (formByte byte.val).length ≤ Usize.max := by
          simp only [suffix, formEncode, List.flatMap_cons, List.length_append] at room
          omega
        step with native_form_byte_exact output byte capacity as ⟨grown, grownMeaning⟩
        step as ⟨next, nextMeaning⟩
        have grownLength : grown.val.length = output.val.length + (formByte byte.val).length := by
          have size := congrArg List.length grownMeaning
          simpa [bytes] using size
        have nextRoom : grown.val.length + (formEncode ((schemaSliceBytes text).drop next.val)).length ≤ Usize.max := by
          simp only [suffix, formEncode, List.flatMap_cons, List.length_append] at room
          simpa [grownLength, nextMeaning, Nat.add_assoc] using room
        apply spec_mono (ih _ (by omega) grown next (by omega) nextRoom rfl)
        intro actual exact
        simpa [suffix, formEncode, List.flatMap_cons, nextMeaning, grownMeaning, List.append_assoc] using exact
      · have ended : index.val = text.val.length := by omega
        have nativeEnded : ¬index < text.len := by scalar_tac
        simp [nativeEnded, schemaSliceBytes, List.drop_map, ended, formEncode]

@[step] theorem native_form_encode_exact (output : NativeVec Std.U8) (text : Slice Std.U8)
    (room : output.val.length + (formEncode (schemaSliceBytes text)).length ≤ Usize.max) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.append_form_encoded output text ⦃ actual =>
      bytes actual = bytes output ++ formEncode (schemaSliceBytes text) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.construct.append_form_encoded
  apply spec_mono (native_form_encode_suffix output text 0#usize (by simp) (by simpa using room))
  intro actual exact
  simpa only [List.drop_zero] using exact

end Auths.Product.NativeCompiler.Refinement
