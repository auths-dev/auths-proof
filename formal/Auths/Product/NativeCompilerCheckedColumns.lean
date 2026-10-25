import Auths.Product.NativeCompilerCredentialPlans
import Auths.Product.NativeCompilerText

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 6000000

@[step] theorem native_optional_slice_column {T : Type} (input : Option (NativeVec T)) :
    AuthsNativeRecipe.core.option.Option.as_deref (core.ops.deref.DerefVec T) input ⦃ actual =>
      actual = input.map AuthsNativeRecipe.alloc.vec.Vec.deref ⦄ := by
  cases input <;> rfl

@[step] theorem native_optional_reference_column {T : Type} (input : Option T) :
    AuthsNativeRecipe.core.option.Option.as_ref input ⦃ actual => actual = input ⦄ := by rfl

@[step] theorem native_str_byte_column (input : Str) :
    AuthsNativeRecipe.core.str.Str.as_bytes input ⦃ actual => actual = input ⦄ := by rfl

/-- These getters preserve the supplied record. They do not prove that the
private Rust constructor's validation sequence was executed. -/
@[step] theorem native_checked_source_column (checked : NativeCheckedSource) :
    AuthsNativeRecipe.recipe.validate.ValidatedSource.impl.source checked ⦃ actual => actual = checked.source ⦄ := by
  rfl

@[step] theorem native_checked_field_column (checked : NativeCheckedSource) :
    AuthsNativeRecipe.recipe.validate.ValidatedSource.impl.field_specs checked ⦃ actual =>
      actual.val = checked.field_specs.val ⦄ := by
  rfl

@[step] theorem native_checked_host_column (checked : NativeCheckedSource)
    (bounded : checked.parsed_host.toByteArray.size ≤ U32.max) :
    AuthsNativeRecipe.recipe.validate.ValidatedSource.impl.parsed_host checked ⦃ actual =>
      schemaSliceBytes actual = textBytes checked.parsed_host ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.ValidatedSource.impl.parsed_host
  apply spec_mono (native_deref_text_exact checked.parsed_host (by
    unfold TextFits
    scalar_tac))
  rintro actual ⟨original, meaning⟩
  exact meaning

@[step] theorem native_field_column_copy (fields : Slice NativeFieldSpec) :
    AuthsNativeRecipe.alloc.slice.Slice.to_vec
      AuthsNativeRecipe.auths_gateway_kernel.field_projection.FieldSpec.Insts.CoreCloneClone fields ⦃ actual =>
        actual.val = fields.val ⦄ := by
  unfold AuthsNativeRecipe.alloc.slice.Slice.to_vec
  step with Aeneas.Std.alloc.slice.Slice.to_vec_spec
    AuthsNativeRecipe.auths_gateway_kernel.field_projection.FieldSpec.Insts.CoreCloneClone fields
    (by
      intro field member
      obtain ⟨copied, evaluates, same⟩ := spec_imp_exists (native_schema_field_clone_exact field)
      simpa only [same] using evaluates) as ⟨copied, same⟩
  subst copied
  simp [AuthsNativeRecipe.alloc.vec.Vec.ofBase, AuthsNativeRecipe.alloc.vec.Vec.val,
    auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.Vec.val,
    auths_composition.alloc.vec.SizedList.toList_ofList]

end Auths.Product.NativeCompiler.Refinement
