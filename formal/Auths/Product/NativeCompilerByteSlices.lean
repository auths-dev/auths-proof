import Auths.Product.NativeCompilerText
import Auths.Product.RecipeOriginAdmission

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.StdModel

@[step] theorem native_str_size_exact (input : Str) :
    AuthsNativeRecipe.core.str.Str.len input ⦃ actual => actual.val = input.val.length ⦄ := by
  simp [AuthsNativeRecipe.core.str.Str.len, spec_ok]

private theorem native_u8_lists_equal (left right : List Std.U8) :
    AuthsNativeRecipe.NativeModel.equalLists core.cmp.PartialEqU8 left right = ok (decide (left = right)) := by
  induction left generalizing right with
  | nil => cases right <;> rfl
  | cons first rest ih =>
      cases right with
      | nil => rfl
      | cons second tail =>
          by_cases same : first = second
          · subst second
            simp [AuthsNativeRecipe.NativeModel.equalLists, core.cmp.PartialEqU8, ih]
          · simp [AuthsNativeRecipe.NativeModel.equalLists, core.cmp.PartialEqU8, same, ih]

@[step] theorem native_byte_suffix_exact (input suffix : Slice Std.U8) :
    AuthsNativeRecipe.core.slice.Slice.ends_with core.cmp.PartialEqU8 input suffix ⦃ actual =>
      actual = decide (RecipeOriginAdmission.EndsWith (schemaSliceBytes input) (schemaSliceBytes suffix)) ⦄ := by
  unfold AuthsNativeRecipe.core.slice.Slice.ends_with
  by_cases size : suffix.val.length ≤ input.val.length
  · have large : ¬input.val.length < suffix.val.length := by omega
    rw [if_neg large, native_u8_lists_equal]
    simp [RecipeOriginAdmission.EndsWith, schemaSliceBytes, size, List.drop_map,
      native_byte_list_injective.eq_iff, spec_ok]
  · have short : input.val.length < suffix.val.length := by omega
    simp [short, RecipeOriginAdmission.EndsWith, schemaSliceBytes, size]

private theorem native_any_u8_equal (input : List Std.U8) (wanted : Std.U8) :
    List.anyM (core.cmp.PartialEqU8.eq wanted) input = ok (decide (wanted ∈ input)) := by
  induction input with
  | nil => rfl
  | cons first rest ih =>
      by_cases same : wanted = first
      · subst first
        simp [List.anyM, core.cmp.PartialEqU8]
      · simp [List.anyM, core.cmp.PartialEqU8, same, ih]

@[step] theorem native_byte_contains_exact (input : Slice Std.U8) (wanted : Std.U8) :
    core.slice.Slice.contains core.cmp.PartialEqU8 input wanted ⦃ actual =>
      actual = decide (wanted.val ∈ schemaSliceBytes input) ⦄ := by
  unfold core.slice.Slice.contains
  rw [native_any_u8_equal]
  have same : wanted.val ∈ schemaSliceBytes input ↔ wanted ∈ input.val := by
    simp only [schemaSliceBytes, List.mem_map]
    constructor
    · rintro ⟨value, member, equal⟩
      have identical : value = wanted := UScalar.eq_of_val_eq equal
      simpa only [identical] using member
    · intro member
      exact ⟨wanted, member, rfl⟩
  simp [same, spec_ok]

end Auths.Product.NativeCompiler.StdModel
