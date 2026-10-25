import Auths.Product.TemplateAstSourceViews
import Auths.Product.BodyCompilerBounds

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.Refinement.Gateway

namespace Auths.Product.TemplateAst.Refinement
set_option maxHeartbeats 4000000

/-- The helper's name envelope covers both ordinary keys and the longest
existing bracketed form echo. The whole compiler earns that envelope from
member/echo validation before calling the helper. -/
@[step] theorem json_prefix_exact (name : Slice U8) (comma : Bool) (bounded : name.val.length ≤ 130) :
    template_ast.json_prefix name comma ⦃ actual => vecBytes actual = jsonPrefix (sliceBytes name) comma ⦄ := by
  cases comma with
  | false =>
    unfold template_ast.json_prefix
    have escapedBound := BodyCompiler.json_string_length (sliceBytes name)
    have fits : (alloc.vec.Vec.new U8).val.length + (jsonString (byteList name.val)).length < 4294967295 := by
      simp only [alloc.vec.Vec.new, List.length_nil, zero_add, sliceBytes, byteList, List.length_map] at *
      omega
    step with append_json_string_spec as ⟨quoted, quotedMeaning⟩
    have room : quoted.length < Usize.max := lt_usize_max (by
      change quoted.val.length < _
      have size := congrArg List.length quotedMeaning
      simp only [List.length_append, byteList, List.length_map, alloc.vec.Vec.new, List.length_nil, zero_add] at size
      simp only [sliceBytes, byteList, List.length_map] at escapedBound
      omega)
    step as ⟨updated, updatedValue⟩
    simp [vecBytes, byteList, updatedValue, quotedMeaning, jsonPrefix, sliceBytes, List.map_append]
  | true =>
    unfold template_ast.json_prefix
    step with copy_bytes_spec as ⟨separator, separatorMeaning⟩
    have escapedBound := BodyCompiler.json_string_length (sliceBytes name)
    have separatorSize : separator.val.length = 1 := by simp [separatorMeaning]
    have fits : separator.val.length + (jsonString (byteList name.val)).length < 4294967295 := by
      simp only [sliceBytes, byteList, List.length_map] at escapedBound
      omega
    step with append_json_string_spec as ⟨quoted, quotedMeaning⟩
    have room : quoted.length < Usize.max := lt_usize_max (by
      change quoted.val.length < _
      have size := congrArg List.length quotedMeaning
      simp only [List.length_append, byteList, List.length_map] at size
      simp only [sliceBytes, byteList, List.length_map] at escapedBound
      omega)
    step as ⟨updated, updatedValue⟩
    simp [vecBytes, byteList, updatedValue, quotedMeaning, separatorMeaning, jsonPrefix,
      sliceBytes, List.map_append, List.append_assoc]

@[step] theorem form_prefix_exact (name : Slice U8) (separator : Bool) (bounded : name.val.length ≤ 130) :
    template_ast.form_prefix name separator ⦃ actual => vecBytes actual = formPrefix (sliceBytes name) separator ⦄ := by
  cases separator with
  | false =>
    unfold template_ast.form_prefix
    have encodedBound := BodyCompiler.form_encode_length (sliceBytes name)
    have fits : (alloc.vec.Vec.new U8).val.length + (formEncode (byteList name.val)).length < 4294967295 := by
      simp only [alloc.vec.Vec.new, List.length_nil, zero_add, sliceBytes, byteList, List.length_map] at *
      omega
    step with append_form_encoded_spec as ⟨encoded, encodedMeaning⟩
    have room : encoded.length < Usize.max := lt_usize_max (by
      change encoded.val.length < _
      have size := congrArg List.length encodedMeaning
      simp only [List.length_append, byteList, List.length_map, alloc.vec.Vec.new, List.length_nil, zero_add] at size
      simp only [sliceBytes, byteList, List.length_map] at encodedBound
      omega)
    step as ⟨updated, updatedValue⟩
    simp [vecBytes, byteList, updatedValue, encodedMeaning, formPrefix, sliceBytes, List.map_append]
  | true =>
    unfold template_ast.form_prefix
    step with copy_bytes_spec as ⟨prefix, prefixMeaning⟩
    have encodedBound := BodyCompiler.form_encode_length (sliceBytes name)
    have prefixSize : prefix.val.length = 1 := by simp [prefixMeaning]
    have fits : prefix.val.length + (formEncode (byteList name.val)).length < 4294967295 := by
      simp only [sliceBytes, byteList, List.length_map] at encodedBound
      omega
    step with append_form_encoded_spec as ⟨encoded, encodedMeaning⟩
    have room : encoded.length < Usize.max := lt_usize_max (by
      change encoded.val.length < _
      have size := congrArg List.length encodedMeaning
      simp only [List.length_append, byteList, List.length_map] at size
      simp only [sliceBytes, byteList, List.length_map] at encodedBound
      omega)
    step as ⟨updated, updatedValue⟩
    simp [vecBytes, byteList, updatedValue, encodedMeaning, prefixMeaning, formPrefix,
      sliceBytes, List.map_append, List.append_assoc]

end Auths.Product.TemplateAst.Refinement
