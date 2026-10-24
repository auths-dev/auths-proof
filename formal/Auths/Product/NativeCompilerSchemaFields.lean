import Auths.Product.NativeCompilerSchemaAtoms

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def nativeFieldColumn (fields : Slice NativeFieldSpec) : List FieldProjection.Field :=
  fields.val.map nativeFieldMeaning

def NativeFieldsLexical (fields : List FieldProjection.Field) : Prop :=
  ∀ field ∈ fields, OperationIdentity.validToken field.name 64 = true

instance (fields : List FieldProjection.Field) : Decidable (NativeFieldsLexical fields) := by
  unfold NativeFieldsLexical
  infer_instance

def nativeNamesResult : core.result.Result (NativeVec (NativeVec Std.U8)) NativeConstructError →
    Except NativeConstructError (List (List Nat))
  | .Ok names => .ok (names.val.map bytes)
  | .Err error => .error error

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

private theorem native_copy_names_suffix (fields : Slice NativeFieldSpec)
    (position : Std.Usize) (output : NativeVec (NativeVec Std.U8))
    (positionBound : position.val ≤ fields.val.length)
    (room : output.val.length + (fields.val.length - position.val) ≤ Usize.max) :
    AuthsNativeRecipe.auths_gateway_kernel.field_projection.copy_field_names_loop fields output position ⦃ actual =>
      nativeNamesResult actual =
        if NativeFieldsLexical ((nativeFieldColumn fields).drop position.val) then
          .ok (output.val.map bytes ++ FieldProjection.names ((nativeFieldColumn fields).drop position.val))
        else .error .ArgumentMismatch ⦄ := by
  generalize remaining : fields.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position output with
  | h count ih =>
    unfold AuthsNativeRecipe.auths_gateway_kernel.field_projection.copy_field_names_loop
    split <;> rename_i within
    · have inside : position.val < fields.val.length := by simpa using within
      step with Slice.index_usize_spec fields position inside as ⟨field, fieldAt⟩
      have sourceSuffix : (nativeFieldColumn fields).drop position.val =
          nativeFieldMeaning field :: (nativeFieldColumn fields).drop (position.val + 1) := by
        simpa only [nativeFieldColumn, List.drop_map, List.map_cons, fieldAt] using
          congrArg (List.map nativeFieldMeaning) (List.drop_eq_getElem_cons inside)
      step with native_schema_token_exact (AuthsNativeRecipe.alloc.vec.Vec.deref field.name)
        64#usize as ⟨valid, validMeaning⟩
      have tokenMeaning : valid = OperationIdentity.validToken (bytes field.name) 64 := by
        simpa only [schemaSliceBytes, bytes, native_deref_contents] using validMeaning
      cases valid with
      | false =>
          have invalid : ¬NativeFieldsLexical ((nativeFieldColumn fields).drop position.val) := by
            intro all
            have head := all (nativeFieldMeaning field) (by simp only [sourceSuffix, List.mem_cons]; exact Or.inl rfl)
            simpa only [nativeFieldMeaning, ← tokenMeaning] using head
          simp [invalid, nativeNamesResult]
      | true =>
          have lexical : OperationIdentity.validToken (bytes field.name) 64 = true := tokenMeaning.symm
          simp only [Bool.true_eq_true, ↓reduceIte]
          step with native_schema_copy_bytes (AuthsNativeRecipe.alloc.vec.Vec.deref field.name)
            as ⟨copied, copiedMeaning⟩
          have copiedBytes : bytes copied = bytes field.name := by
            simpa only [bytes, native_deref_contents] using congrArg (List.map (·.val)) copiedMeaning
          have capacity : output.val.length < Usize.max := by omega
          step with native_push_exact output copied capacity as ⟨updated, appended⟩
          have updatedLength : updated.val.length = output.val.length + 1 := by
            simp only [appended, List.length_append, List.length_singleton]
          step as ⟨next, nextValue⟩
          have nextBound : next.val ≤ fields.val.length := by omega
          have nextRoom : updated.val.length + (fields.val.length - next.val) ≤ Usize.max := by omega
          have smaller : fields.val.length - next.val < count := by omega
          apply spec_mono (ih _ smaller next updated nextBound nextRoom rfl)
          intro actual exact
          simpa [sourceSuffix, nextValue, NativeFieldsLexical, FieldProjection.names,
            nativeFieldMeaning, lexical, appended, List.map_append, copiedBytes,
            List.append_assoc] using exact
    · have ended : fields.val.length ≤ position.val := by simpa using within
      have modelEnded : (nativeFieldColumn fields).length ≤ position.val := by
        simpa only [nativeFieldColumn, List.length_map] using ended
      simp [List.drop_eq_nil_of_le modelEnded, NativeFieldsLexical, FieldProjection.names, nativeNamesResult]

@[step] theorem native_schema_copy_names_exact (fields : Slice NativeFieldSpec) :
    AuthsNativeRecipe.auths_gateway_kernel.field_projection.copy_field_names fields ⦃ actual =>
      nativeNamesResult actual =
        if (nativeFieldColumn fields).length ≤ 32 ∧ NativeFieldsLexical (nativeFieldColumn fields) then
          .ok (FieldProjection.names (nativeFieldColumn fields)) else .error .ArgumentMismatch ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.field_projection.copy_field_names
    AuthsNativeRecipe.auths_gateway_kernel.arguments.MAX_PROFILE_FIELDS
  by_cases large : 32 < fields.val.length
  · have nativeLarge : fields.len > 32#usize := by scalar_tac
    simp [nativeLarge, nativeFieldColumn, Nat.not_le.mpr large, nativeNamesResult]
  · have bounded : fields.val.length ≤ 32 := by omega
    have nativeBound : ¬fields.len > 32#usize := by scalar_tac
    have capacity : fields.val.length ≤ Usize.max := fields.property
    simp only [nativeBound, ↓reduceIte]
    apply spec_mono (native_copy_names_suffix fields 0#usize
      (AuthsNativeRecipe.alloc.vec.Vec.new (NativeVec Std.U8)) (by simp)
      (by simpa only [native_empty_contents, List.length_nil, Nat.zero_add, Nat.sub_zero] using capacity))
    intro actual exact
    simpa only [native_empty_contents, List.drop_zero, List.map_nil, List.nil_append,
      nativeFieldColumn, List.length_map, bounded, true_and] using exact

/-- The actual native parser's layout gate is exactly the independent bounded,
unique, lexical field layout. Successful results preserve the complete original
name column; every refusal retains the actual stable ArgumentMismatch kind. -/
@[step] theorem native_schema_field_names_exact (fields : Slice NativeFieldSpec) :
    AuthsNativeRecipe.auths_gateway_kernel.field_projection.field_names fields ⦃ actual =>
      nativeNamesResult actual =
        if FieldProjection.LayoutValid (nativeFieldColumn fields) then
          .ok (FieldProjection.names (nativeFieldColumn fields)) else .error .ArgumentMismatch ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.field_projection.field_names
  step with native_schema_copy_names_exact fields as ⟨copied, copiedMeaning⟩
  cases copied with
  | Err error =>
      have invalid : ¬((nativeFieldColumn fields).length ≤ 32 ∧ NativeFieldsLexical (nativeFieldColumn fields)) := by
        intro valid
        simp [valid, nativeNamesResult] at copiedMeaning
      have invalidLayout : ¬FieldProjection.LayoutValid (nativeFieldColumn fields) :=
        fun valid => invalid ⟨valid.1, valid.2.2⟩
      simpa [invalid, invalidLayout, nativeNamesResult] using copiedMeaning
  | Ok copied =>
      have admitted : (nativeFieldColumn fields).length ≤ 32 ∧ NativeFieldsLexical (nativeFieldColumn fields) := by
        by_contra refused
        simp [refused, nativeNamesResult] at copiedMeaning
      have copiedNames : copied.val.map bytes = FieldProjection.names (nativeFieldColumn fields) := by
        simpa only [admitted, ↓reduceIte, nativeNamesResult, Except.ok.injEq] using copiedMeaning
      step with native_schema_unique_names_exact (AuthsNativeRecipe.alloc.vec.Vec.deref copied)
        as ⟨unique, uniqueMeaning⟩
      have uniqueSpec : unique = decide (FieldProjection.names (nativeFieldColumn fields)).Nodup := by
        simpa only [nativeNameColumn, native_deref_contents, copiedNames] using uniqueMeaning
      cases unique with
      | false =>
          have duplicate : ¬(FieldProjection.names (nativeFieldColumn fields)).Nodup := by
            simpa using uniqueSpec.symm
          simp [nativeNamesResult, FieldProjection.LayoutValid, duplicate]
      | true =>
          have distinct : (FieldProjection.names (nativeFieldColumn fields)).Nodup := by
            simpa using uniqueSpec.symm
          have layout : FieldProjection.LayoutValid (nativeFieldColumn fields) :=
            ⟨admitted.1, distinct, admitted.2⟩
          simp only [Bool.true_eq_true, ↓reduceIte]
          step with native_vector_clone_exact
            (AuthsNativeRecipe.core.clone.CloneallocvecVec core.clone.CloneU8) copied
            (by
              intro value _
              exact native_vector_clone_result core.clone.CloneU8 value (by intro byte _; rfl))
            as ⟨completeCopy, same⟩
          simp only [nativeNamesResult, same, copiedNames, layout, ↓reduceIte]

end Auths.Product.NativeCompiler.Refinement
