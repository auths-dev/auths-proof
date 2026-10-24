import Auths.Product.NativeCompilerSchemaLookup
import Auths.Product.ArgumentBinding

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def nativeNameColumn (input : Slice (NativeVec Std.U8)) : List (List Nat) := input.val.map bytes

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

private theorem native_index_suffix (fields : Slice (NativeVec Std.U8)) (wanted : Slice Std.U8)
    (position : Std.Usize) (found : Option Std.Usize)
    (positionBound : position.val ≤ fields.val.length) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.field_index_loop fields wanted position found ⦃ actual =>
      actual.map UScalar.val = match found with
        | some index => some index.val
        | none => (SchemaIndex.position ((nativeNameColumn fields).drop position.val)
            (schemaSliceBytes wanted)).map (position.val + ·) ⦄ := by
  generalize remaining : fields.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position found with
  | h count ih =>
    cases found with
    | some first =>
        unfold AuthsNativeRecipe.auths_gateway_kernel.construct.field_index_loop
        split <;> simp [core.option.Option.is_none]
    | none =>
        unfold AuthsNativeRecipe.auths_gateway_kernel.construct.field_index_loop
        split <;> rename_i within
        · have inside : position.val < fields.val.length := by simpa using within
          simp only [core.option.Option.is_none, Bool.true_eq_true, ↓reduceIte]
          step with Slice.index_usize_spec fields position inside as ⟨name, nameAt⟩
          step with native_schema_byte_equality (AuthsNativeRecipe.alloc.vec.Vec.deref name)
            wanted as ⟨same, sameMeaning⟩
          have dropped : (nativeNameColumn fields).drop position.val =
              bytes name :: (nativeNameColumn fields).drop (position.val + 1) := by
            simpa only [nativeNameColumn, List.drop_map, List.map_cons, nameAt] using
              congrArg (List.map bytes) (List.drop_eq_getElem_cons inside)
          have byteMeaning : same = decide (bytes name = schemaSliceBytes wanted) := by
            simpa only [schemaSliceBytes, bytes, native_deref_contents] using sameMeaning
          cases same with
          | true =>
              have matched : bytes name = schemaSliceBytes wanted := by simpa using byteMeaning.symm
              simp only [Bool.true_eq_true, ↓reduceIte, bind_tc_ok]
              step as ⟨next, nextValue⟩
              have nextBound : next.val ≤ fields.val.length := by omega
              have smaller : fields.val.length - next.val < count := by omega
              apply spec_mono (ih _ smaller next (some position) nextBound rfl)
              intro actual exact
              simpa only [dropped, SchemaIndex.position, matched, ↓reduceIte, Option.map_some, Nat.add_zero] using exact
          | false =>
              have different : bytes name ≠ schemaSliceBytes wanted := by simpa using byteMeaning.symm
              simp only [Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
              step as ⟨next, nextValue⟩
              have nextBound : next.val ≤ fields.val.length := by omega
              have smaller : fields.val.length - next.val < count := by omega
              apply spec_mono (ih _ smaller next none nextBound rfl)
              intro actual exact
              simpa [dropped, SchemaIndex.position, different, nextValue, Option.map_map,
                Function.comp_def, Nat.add_assoc] using exact
        · have ended : fields.val.length ≤ position.val := by simpa using within
          have modelEnded : (nativeNameColumn fields).length ≤ position.val := by
            simpa only [nativeNameColumn, List.length_map] using ended
          simp [List.drop_eq_nil_of_le modelEnded, SchemaIndex.position]

@[step] theorem native_schema_first_index_exact (fields : Slice (NativeVec Std.U8)) (wanted : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.field_index fields wanted ⦃ actual =>
      actual.map UScalar.val = SchemaIndex.position (nativeNameColumn fields) (schemaSliceBytes wanted) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.construct.field_index
  apply spec_mono (native_index_suffix fields wanted 0#usize none (by simp))
  intro actual exact
  simpa only [List.drop_zero, Nat.zero_add, Option.map_id] using exact

private theorem native_unique_suffix (fields : Slice (NativeVec Std.U8)) (position : Std.Usize)
    (positionBound : position.val ≤ fields.val.length)
    (checked : ∀ earlier, earlier < position.val → ∀ name,
      (nativeNameColumn fields)[earlier]? = some name →
        SchemaIndex.position (nativeNameColumn fields) name = some earlier) :
    AuthsNativeRecipe.auths_gateway_kernel.arguments.unique_fields_loop fields position ⦃ actual =>
      actual = decide (nativeNameColumn fields).Nodup ⦄ := by
  generalize remaining : fields.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position with
  | h count ih =>
    unfold AuthsNativeRecipe.auths_gateway_kernel.arguments.unique_fields_loop
    split <;> rename_i within
    · have inside : position.val < fields.val.length := by simpa using within
      step with Slice.index_usize_spec fields position inside as ⟨field, fieldAt⟩
      have atName : (nativeNameColumn fields)[position.val]? = some (bytes field) := by
        simp only [nativeNameColumn, List.getElem?_map,
          List.getElem?_eq_getElem inside, Option.map_some, fieldAt]
      step with native_schema_first_index_exact fields
        (AuthsNativeRecipe.alloc.vec.Vec.deref field) as ⟨first, firstMeaning⟩
      have firstSpec : first.map UScalar.val = SchemaIndex.position (nativeNameColumn fields) (bytes field) := by
        simpa only [schemaSliceBytes, bytes, native_deref_contents] using firstMeaning
      cases first with
      | none =>
          have duplicate : ¬(nativeNameColumn fields).Nodup := by
            intro unique
            have required := (ArgumentBinding.nodup_iff_first_positions _).mp unique position.val (bytes field) atName
            simp only [← firstSpec, Option.map_none] at required
            contradiction
          simp [duplicate]
      | some first =>
          by_cases current : first = position
          · simp only [current, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
            step as ⟨next, nextValue⟩
            have nextBound : next.val ≤ fields.val.length := by omega
            have nextChecked : ∀ earlier, earlier < next.val → ∀ name,
                (nativeNameColumn fields)[earlier]? = some name →
                  SchemaIndex.position (nativeNameColumn fields) name = some earlier := by
              intro earlier before name nameAt
              by_cases previous : earlier < position.val
              · exact checked earlier previous name nameAt
              · have sameIndex : earlier = position.val := by omega
                subst earlier
                have sameName : name = bytes field := by simpa only [atName, Option.some.injEq] using nameAt.symm
                simpa only [sameName, current, Option.map_some] using firstSpec.symm
            have smaller : fields.val.length - next.val < count := by omega
            exact ih _ smaller next nextBound nextChecked rfl
          · have duplicate : ¬(nativeNameColumn fields).Nodup := by
              intro unique
              have required := (ArgumentBinding.nodup_iff_first_positions _).mp unique position.val (bytes field) atName
              rw [← firstSpec] at required
              have equalValues : first.val = position.val := Option.some.inj required
              exact current (UScalar.eq_of_val_eq equalValues)
            simp [current, duplicate]
    · have ended : fields.val.length ≤ position.val := by simpa using within
      have unique : (nativeNameColumn fields).Nodup := by
        apply (ArgumentBinding.nodup_iff_first_positions _).mpr
        intro earlier name atName
        have inside : earlier < (nativeNameColumn fields).length := (List.getElem?_eq_some_iff.mp atName).1
        exact checked earlier (by simp only [nativeNameColumn, List.length_map] at inside; omega) name atName
      simp [unique]

/-- The native uniqueness check compares exact original names and their first
positions. No sortedness, prevalidated unique set or selected field is assumed. -/
@[step] theorem native_schema_unique_names_exact (fields : Slice (NativeVec Std.U8)) :
    AuthsNativeRecipe.auths_gateway_kernel.arguments.unique_fields fields ⦃ actual =>
      actual = decide (nativeNameColumn fields).Nodup ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.arguments.unique_fields
  exact native_unique_suffix fields 0#usize (by simp) (by simp)

@[step] theorem native_schema_scalar_clone_exact (input : NativeScalarSchema) :
    AuthsNativeRecipe.auths_gateway_kernel.scalars.ScalarSchema.Insts.CoreCloneClone.clone input ⦃ actual =>
      actual = input ⦄ := by
  cases input with
  | String minimum maximum =>
      simp [AuthsNativeRecipe.auths_gateway_kernel.scalars.ScalarSchema.Insts.CoreCloneClone.clone,
        core.clone.impls.CloneUsize.clone]
  | Integer minimum maximum =>
      simp [AuthsNativeRecipe.auths_gateway_kernel.scalars.ScalarSchema.Insts.CoreCloneClone.clone,
        core.clone.impls.CloneI64.clone]
  | Boolean => simp [AuthsNativeRecipe.auths_gateway_kernel.scalars.ScalarSchema.Insts.CoreCloneClone.clone]
  | Enum variants =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.scalars.ScalarSchema.Insts.CoreCloneClone.clone
      step with native_vector_clone_exact
        (AuthsNativeRecipe.core.clone.CloneallocvecVec core.clone.CloneU8) variants
        (by
          intro value _
          exact native_vector_clone_result core.clone.CloneU8 value (by intro byte _; rfl)) as ⟨copied, same⟩
      simpa only [same]

@[step] theorem native_schema_field_clone_exact (input : NativeFieldSpec) :
    AuthsNativeRecipe.auths_gateway_kernel.field_projection.FieldSpec.Insts.CoreCloneClone.clone input ⦃ actual =>
      actual = input ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.field_projection.FieldSpec.Insts.CoreCloneClone.clone
  step with native_vector_clone_exact core.clone.CloneU8 input.name
    (by intro byte _; rfl) as ⟨copiedName, sameName⟩
  step with native_schema_scalar_clone_exact input.schema as ⟨copiedSchema, sameSchema⟩
  cases input
  simp_all

end Auths.Product.NativeCompiler.Refinement
