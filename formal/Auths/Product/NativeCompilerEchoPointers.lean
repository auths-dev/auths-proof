import Auths.Product.NativeCompilerSourceMemberKeys
import Auths.Product.NativeCompilerResponsePointer

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel RecipeAdmissionAtoms
set_option maxHeartbeats 12000000
set_option maxRecDepth 4096

private theorem native_prefix_lists_equal (left right : List Std.U8) :
    AuthsNativeRecipe.NativeModel.equalLists core.cmp.PartialEqU8 left right = ok (decide (left = right)) := by
  induction left generalizing right with
  | nil => cases right <;> rfl
  | cons first rest ih =>
      cases right with
      | nil => rfl
      | cons second tail =>
          by_cases same : first = second
          · simp [same, AuthsNativeRecipe.NativeModel.equalLists, core.cmp.PartialEqU8, ih]
          · simp [AuthsNativeRecipe.NativeModel.equalLists, core.cmp.PartialEqU8, same, ih]

@[step] theorem native_byte_prefix_exact (input prefix : Slice Std.U8) :
    AuthsNativeRecipe.core.slice.Slice.starts_with core.cmp.PartialEqU8 input prefix ⦃ actual =>
      actual = decide ((schemaSliceBytes input).take (schemaSliceBytes prefix).length = schemaSliceBytes prefix) ⦄ := by
  unfold AuthsNativeRecipe.core.slice.Slice.starts_with
  by_cases short : input.val.length < prefix.val.length
  · have different : (schemaSliceBytes input).take (schemaSliceBytes prefix).length ≠ schemaSliceBytes prefix := by
      intro same
      have length := congrArg List.length same
      simp [schemaSliceBytes, List.length_take, Nat.min_eq_right (Nat.le_of_lt short)] at length
      omega
    simp [short, different]
  · rw [if_neg short, native_prefix_lists_equal]
    simp [schemaSliceBytes, List.take_map, native_byte_list_injective.eq_iff, spec_ok]

@[step] theorem native_pointer_descends_exact (child parent : Slice Std.U8) :
    AuthsNativeRecipe.recipe.validate.pointer_descends child parent ⦃ actual =>
      actual = decide (Descends (schemaSliceBytes child) (schemaSliceBytes parent)) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.pointer_descends
  step with native_byte_prefix_exact child parent as ⟨prefix, prefixMeaning⟩
  cases prefix with
  | false => simp [Descends, ← prefixMeaning]
  | true =>
      simp only [Bool.true_eq_true, ↓reduceIte,
        AuthsNativeRecipe.core.slice.Slice.get, core.slice.Slice.get,
        core.slice.index.SliceIndexUsizeSlice, core.slice.index.Usize.get,
        Slice.getElem?_Usize_eq]
      cases selected : child.val[parent.val.length]? <;>
        simp [AuthsNativeRecipe.core.option.Option.Insts.CoreCmpPartialEqOption.eq,
          core.cmp.PartialEqShared, core.cmp.PartialEqU8, Descends,
          ← prefixMeaning, schemaSliceBytes, List.getElem?_map, selected, UScalar.eq_equiv]

/-- Equal byte strings and slash-delimited ancestry overlap. A common byte
prefix without the following slash is not ancestry. No pointer normalization,
UTF-8 truncation or provider interpretation is introduced. -/
@[step] theorem native_pointers_overlap_exact (left right : Str) :
    AuthsNativeRecipe.recipe.validate.pointers_overlap left right ⦃ actual =>
      actual = pointersOverlap (schemaSliceBytes left) (schemaSliceBytes right) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.pointers_overlap
    AuthsNativeRecipe.core.str.Str.as_bytes _root_.core.str.Str.as_bytes
  simp only [bind_tc_ok]
  step with native_schema_byte_equality left right as ⟨equal, equality⟩
  cases equal with
  | true => simp [pointersOverlap, ← equality]
  | false =>
      simp only [Bool.false_eq_true, ↓reduceIte]
      step with native_pointer_descends_exact left right as ⟨leftBelow, leftMeaning⟩
      cases leftBelow with
      | true => simp [pointersOverlap, ← equality, ← leftMeaning]
      | false =>
          simp only [Bool.false_eq_true, ↓reduceIte]
          apply spec_mono (native_pointer_descends_exact right left)
          intro actual rightMeaning
          simpa [pointersOverlap, ← equality, ← leftMeaning] using rightMeaning

/-- A successful ordinary-token check earns UTF-8 conversion from complete
original bytes. The conversion result is proved, never supplied by an Auths
validator flag or an opaque parsing implementation. -/
@[step] theorem native_ascii_token_utf8_exact (token : Slice Std.U8)
    (valid : OperationIdentity.validToken (schemaSliceBytes token) 64 = true) :
    AuthsNativeRecipe.core.str.converts.from_utf8 token ⦃ actual => actual = .Ok token ⦄ := by
  obtain ⟨name, decoded, original⟩ := Rules.ascii_has_lossless_name (schemaSliceBytes token)
    (Rules.token_bytes_are_ascii _ _ valid)
  have converted : String.fromUTF8? (Auths.Codec.StdModel.bytes token) = some name := by
    rw [← native_str_decode_exact]
    exact decoded
  simp [AuthsNativeRecipe.core.str.converts.from_utf8, converted, spec_ok]

end Auths.Product.NativeCompiler.Refinement
