import Auths.Product.NativeCompilerNamespace
import Auths.Product.NativeCompilerSchemaFields
import Auths.Product.ProfileSchema

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 22000000
set_option maxRecDepth 4096

private theorem native_field_schema_suffix (fields : Slice NativeFieldSpec) (wanted : Slice Std.U8)
    (position : Std.Usize) (within : position.val ≤ fields.val.length) :
    AuthsNativeRecipe.auths_gateway_kernel.field_projection.schema_for_loop fields wanted position ⦃ actual =>
      actual.map nativeScalarMeaning = FieldProjection.schemaFor (schemaSliceBytes wanted)
        ((nativeFieldColumn fields).drop position.val) ⦄ := by
  generalize remaining : fields.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.field_projection.schema_for_loop
      by_cases inside : position.val < fields.val.length
      · have nativeInside : position < fields.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        step with Slice.index_usize_spec fields position inside as ⟨field, fieldAt⟩
        step with native_schema_byte_equality (AuthsNativeRecipe.alloc.vec.Vec.deref field.«name») wanted
          as ⟨same, equality⟩
        have originalEquality : same = decide ((nativeFieldMeaning field).name = schemaSliceBytes wanted) := by
          simpa [nativeFieldMeaning, schemaSliceBytes, bytes, native_deref_contents] using equality
        have suffix : (nativeFieldColumn fields).drop position.val = nativeFieldMeaning field ::
            (nativeFieldColumn fields).drop (position.val + 1) := by
          simpa [nativeFieldColumn, List.drop_map, fieldAt] using
            congrArg (List.map nativeFieldMeaning) (List.drop_eq_getElem_cons inside)
        cases same with
        | true => simp [suffix, FieldProjection.schemaFor, ← originalEquality, nativeFieldMeaning]
        | false =>
            simp only [Bool.false_eq_true, ↓reduceIte]
            step as ⟨next, nextValue⟩
            apply spec_mono (ih _ (by omega) next (by omega) rfl)
            intro actual meaning
            simpa [suffix, FieldProjection.schemaFor, ← originalEquality, nextValue] using meaning
      · have nativeEnded : ¬position < fields.len := by scalar_tac
        have ended : (nativeFieldColumn fields).length ≤ position.val := by simp [nativeFieldColumn]; omega
        simp [nativeEnded, List.drop_eq_nil_of_le ended, FieldProjection.schemaFor]

/-- Full original field/name/schema lookup, including first-match and absent
outcomes. No original schema/key admission or selected field is a premise. -/
@[step] theorem native_field_spec_schema_for_exact (fields : Slice NativeFieldSpec) (wanted : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.field_projection.schema_for fields wanted ⦃ actual =>
      actual.map nativeScalarMeaning = FieldProjection.schemaFor (schemaSliceBytes wanted) (nativeFieldColumn fields) ⦄ := by
  simpa [AuthsNativeRecipe.auths_gateway_kernel.field_projection.schema_for] using
    native_field_schema_suffix fields wanted 0#usize (by simp)

private theorem native_single_binding_variant (variants : NativeVec (NativeVec Std.U8))
    (variant : NativeVec Std.U8) (singleton : variants.val = [variant]) :
    AuthsNativeRecipe.alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice (NativeVec Std.U8))
      variants 0#usize ⦃ actual => actual = variant ⦄ := by
  change Slice.index_usize (AuthsNativeRecipe.alloc.vec.Vec.deref variants) 0#usize ⦃ actual => actual = variant ⦄
  apply spec_mono (Slice.index_usize_spec (AuthsNativeRecipe.alloc.vec.Vec.deref variants) 0#usize (by simp [singleton]))
  intro actual meaning
  simpa [singleton, native_deref_contents] using meaning

/-- Actual reserved binding validation: one namespace enum variant equal to
the original namespace bytes, bounded operation-id String, and exact 64-byte
digest String. General schema validity is earned separately by profile parsing. -/
@[step] theorem native_binding_fields_match_exact (fields : Slice NativeFieldSpec) (namespaceBytes : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.profile_schema.binding_fields_match fields namespaceBytes ⦃ actual =>
      actual = ProfileSchema.bindingFieldsMatch (nativeFieldColumn fields) (schemaSliceBytes namespaceBytes) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.profile_schema.binding_fields_match
  simp only [lift, Array.to_slice, Array.make, bind_tc_ok]
  step with native_field_spec_schema_for_exact fields (toStr "operator_namespace") as ⟨namespaceSchema, namespaceMeaning⟩
  cases namespaceSchema with
  | none => simp_all [ProfileSchema.bindingFieldsMatch, ProfileSchema.namespaceName, schemaSliceBytes]
  | some namespaceSchema =>
      cases namespaceSchema with
      | Enum variants =>
          by_cases singleton : variants.val.length = 1
          · obtain ⟨variant, original⟩ := List.length_eq_one.mp singleton
            have nativeSize : AuthsNativeRecipe.alloc.vec.Vec.len variants = 1#usize := by scalar_tac
            simp only [nativeSize, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
            step with native_single_binding_variant variants variant original as ⟨selected, selectedMeaning⟩
            subst selected
            step with native_schema_byte_equality (AuthsNativeRecipe.alloc.vec.Vec.deref variant) namespaceBytes
              as ⟨same, equality⟩
            have originalEquality : same = decide (bytes variant = schemaSliceBytes namespaceBytes) := by
              simpa [schemaSliceBytes, bytes, native_deref_contents] using equality
            cases same with
            | false =>
                simp_all [ProfileSchema.bindingFieldsMatch, nativeScalarMeaning, original,
                  ProfileSchema.namespaceName, schemaSliceBytes]
            | true =>
                simp only [Bool.true_eq_true, ↓reduceIte, lift, Array.to_slice, Array.make, bind_tc_ok]
                step with native_field_spec_schema_for_exact fields (toStr "operation_id") as ⟨operationSchema, operationMeaning⟩
                cases operationSchema with
                | none =>
                    simp_all [ProfileSchema.bindingFieldsMatch, nativeScalarMeaning, original,
                      ProfileSchema.namespaceName, ProfileSchema.operationName, schemaSliceBytes]
                | some operationSchema =>
                    cases operationSchema with
                    | String minimum maximum =>
                        by_cases minimumBound : 1 ≤ minimum.val
                        · have nativeMinimum : ¬minimum < 1#usize := by scalar_tac
                          simp only [nativeMinimum, ↓reduceIte]
                          by_cases maximumBound : maximum.val ≤ 128
                          · have nativeMaximum : ¬maximum > 128#usize := by scalar_tac
                            simp only [nativeMaximum, ↓reduceIte, lift, Array.to_slice, Array.make, bind_tc_ok]
                            step with native_field_spec_schema_for_exact fields (toStr "recipe_digest") as ⟨digestSchema, digestMeaning⟩
                            cases digestSchema with
                            | none =>
                                simp_all [ProfileSchema.bindingFieldsMatch, nativeScalarMeaning, original,
                                  ProfileSchema.namespaceName, ProfileSchema.operationName, ProfileSchema.digestName, schemaSliceBytes]
                            | some digestSchema =>
                                cases digestSchema <;>
                                  simp_all [ProfileSchema.bindingFieldsMatch, nativeScalarMeaning, original,
                                    ProfileSchema.namespaceName, ProfileSchema.operationName, ProfileSchema.digestName,
                                    schemaSliceBytes, UScalar.eq_equiv, UScalar.le_equiv, UScalar.lt_equiv]
                          · have nativeMaximum : maximum > 128#usize := by scalar_tac
                            simp_all [ProfileSchema.bindingFieldsMatch, nativeScalarMeaning, original,
                              ProfileSchema.namespaceName, ProfileSchema.operationName, schemaSliceBytes,
                              UScalar.le_equiv, UScalar.lt_equiv]
                        · have nativeMinimum : minimum < 1#usize := by scalar_tac
                          simp_all [ProfileSchema.bindingFieldsMatch, nativeScalarMeaning, original,
                            ProfileSchema.namespaceName, ProfileSchema.operationName, schemaSliceBytes,
                            UScalar.le_equiv, UScalar.lt_equiv]
                    | Enum _ | Integer _ _ | Boolean =>
                        simp_all [ProfileSchema.bindingFieldsMatch, nativeScalarMeaning, original,
                          ProfileSchema.namespaceName, ProfileSchema.operationName, schemaSliceBytes]
          · have nativeSize : AuthsNativeRecipe.alloc.vec.Vec.len variants ≠ 1#usize := by scalar_tac
            cases shape : variants.val with
            | nil => simp_all [ProfileSchema.bindingFieldsMatch, nativeScalarMeaning, ProfileSchema.namespaceName, schemaSliceBytes]
            | cons first rest =>
                cases rest <;> simp_all [ProfileSchema.bindingFieldsMatch, nativeScalarMeaning,
                  ProfileSchema.namespaceName, schemaSliceBytes]
      | String _ _ | Integer _ _ | Boolean =>
          simp_all [ProfileSchema.bindingFieldsMatch, nativeScalarMeaning, ProfileSchema.namespaceName, schemaSliceBytes]

@[step] theorem native_validate_binding_fields_exact (fields : Slice NativeFieldSpec)
    (namespaceValue : AuthsNativeRecipe.recipe.OperatorNamespace) (fits : TextFits namespaceValue) :
    AuthsNativeRecipe.recipe.validate_binding_fields fields namespaceValue ⦃ actual =>
      actual = if ProfileSchema.BindingFields (nativeFieldColumn fields) (textBytes namespaceValue)
        then .Ok () else .Err .ProfileMismatch ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate_binding_fields AuthsNativeRecipe.recipe.OperatorNamespace.as_str
  step with native_deref_view_exact namespaceValue fits as ⟨borrowed, original⟩
  subst borrowed
  simp only [core.str.Str.as_bytes, _root_.core.str.Str.as_bytes, bind_tc_ok]
  step with native_binding_fields_match_exact fields (nativeTextView namespaceValue fits) as ⟨valid, validity⟩
  have admission : valid = true ↔ ProfileSchema.BindingFields (nativeFieldColumn fields) (textBytes namespaceValue) := by
    rw [validity]
    simpa [native_text_view_bytes] using ProfileSchema.binding_boolean_exact (nativeFieldColumn fields) (textBytes namespaceValue)
  cases valid <;> simp_all

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

/-- The binding decision is earned from the actual constructor trace and the
namespace returned by the actual namespace parser. It is not inferred from
record access or supplied as a successful helper input. -/
theorem native_constructor_success_earns_binding_fields (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (checked : NativeConstructorRecord) (fits : TextFits source.operator_namespace)
    (completed : AuthsNativeRecipe.recipe.validate.validate_source source lock canonical = ok (.Ok checked)) :
    ProfileSchema.BindingFields (nativeFieldsMeaning checked.field_specs) (textBytes source.operator_namespace) := by
  have trace := native_constructor_success_earns_original_trace source lock canonical checked completed
  obtain ⟨namespaceBytes, namespaceToken⟩ :=
    native_constructor_success_earns_namespace source lock canonical fits checked completed
  have sameNamespace : checked.«namespace» = source.operator_namespace := text_bytes_injective namespaceBytes
  have checkedFits : TextFits checked.«namespace» := by simpa [sameNamespace] using fits
  have semantic := native_validate_binding_fields_exact (AuthsNativeRecipe.alloc.vec.Vec.deref checked.field_specs)
    checked.«namespace» checkedFits
  rw [trace.bindingFields] at semantic
  by_contra invalid
  simp [spec_ok, nativeFieldColumn, nativeFieldsMeaning, native_deref_contents,
    namespaceBytes, invalid] at semantic

theorem native_compile_success_earns_binding_fields (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (fits : TextFits source.operator_namespace) (output : AuthsNativeRecipe.recipe.CompiledRecipe)
    (completed : AuthsNativeRecipe.recipe.compile_decoded source lock canonical = ok (.Ok output)) :
    output.source = source ∧ ∃ checked : NativeConstructorRecord,
      AuthsNativeRecipe.recipe.validate.validate_source source lock canonical = ok (.Ok checked) ∧
      ProfileSchema.BindingFields (nativeFieldsMeaning checked.field_specs) (textBytes source.operator_namespace) ∧
      output.«namespace» = checked.«namespace» ∧
      AuthsNativeRecipe.recipe.lower.plans checked = ok (.Ok output.plans) := by
  obtain ⟨checked, admitted, digest, plans, original, namespaceValue⟩ :=
    native_compile_success_keeps_all_stage_results source lock canonical output completed
  exact ⟨original, checked, admitted,
    native_constructor_success_earns_binding_fields source lock canonical checked fits admitted, namespaceValue, plans⟩

end Auths.Product.NativeCompiler.Refinement
