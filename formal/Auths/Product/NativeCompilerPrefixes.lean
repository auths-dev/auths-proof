import Auths.Product.NativeCompilerEncodingSequences
import Auths.Product.NativeCompilerAstEcho

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open RequestConstruction TemplateAst
set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

private theorem native_optional_separator (present : Bool) (byte : Std.U8) :
    (if present then do
      let source ← lift (Array.to_slice (Array.make 1#usize [byte]))
      AuthsNativeRecipe.auths_gateway_kernel.construct.copy_bytes source
    else ok (AuthsNativeRecipe.alloc.vec.Vec.new Std.U8)) ⦃ actual =>
      bytes actual = (if present then [byte.val] else []) ∧ actual.val.length ≤ 1 ⦄ := by
  cases present with
  | false => simp [bytes, native_empty_contents]
  | true =>
      simp only [Bool.true_eq_true, ↓reduceIte]
      step as ⟨source, sourceMeaning⟩
      step with native_schema_copy_bytes source as ⟨actual, exact⟩
      simp [bytes, exact, sourceMeaning]

@[step] theorem native_json_prefix_exact (name : Slice Std.U8) (comma : Bool)
    (bounded : name.val.length ≤ 130) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_prefix name comma ⦃ actual =>
      bytes actual = jsonPrefix (schemaSliceBytes name) comma ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_prefix
  step with native_optional_separator comma 44#u8 as ⟨initial, initialMeaning, initialLength⟩
  have quotedBound := BodyCompiler.json_string_length (schemaSliceBytes name)
  have quoteRoom : initial.val.length + (jsonString (schemaSliceBytes name)).length ≤ Usize.max := by
    simp only [schemaSliceBytes, List.length_map] at quotedBound
    scalar_tac
  step with native_json_string_exact initial name quoteRoom as ⟨quoted, quotedMeaning⟩
  have finalRoom : quoted.val.length < Usize.max := by
    have size := congrArg List.length quotedMeaning
    simp only [bytes, List.length_map, List.length_append] at size
    simp only [schemaSliceBytes, List.length_map] at quotedBound
    scalar_tac
  step with native_push_exact quoted 58#u8 finalRoom as ⟨actual, exact⟩
  simp [bytes, exact, quotedMeaning, initialMeaning, jsonPrefix, List.map_append, List.append_assoc]

@[step] theorem native_form_prefix_exact (name : Slice Std.U8) (separator : Bool)
    (bounded : name.val.length ≤ 130) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_prefix name separator ⦃ actual =>
      bytes actual = formPrefix (schemaSliceBytes name) separator ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_prefix
  step with native_optional_separator separator 38#u8 as ⟨initial, initialMeaning, initialLength⟩
  have encodedBound := BodyCompiler.form_encode_length (schemaSliceBytes name)
  have encodeRoom : initial.val.length + (formEncode (schemaSliceBytes name)).length ≤ Usize.max := by
    simp only [schemaSliceBytes, List.length_map] at encodedBound
    scalar_tac
  step with native_form_encode_exact initial name encodeRoom as ⟨encoded, encodedMeaning⟩
  have finalRoom : encoded.val.length < Usize.max := by
    have size := congrArg List.length encodedMeaning
    simp only [bytes, List.length_map, List.length_append] at size
    simp only [schemaSliceBytes, List.length_map] at encodedBound
    scalar_tac
  step with native_push_exact encoded 61#u8 finalRoom as ⟨actual, exact⟩
  simp [bytes, exact, encodedMeaning, initialMeaning, formPrefix, List.map_append, List.append_assoc]

end Auths.Product.NativeCompiler.Refinement
