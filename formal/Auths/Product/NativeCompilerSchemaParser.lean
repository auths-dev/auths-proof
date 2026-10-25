import Auths.Product.NativeCompilerSchemaFields
import Auths.Product.NativeCompilerJson

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

private theorem native_parse_enum_suffix (values : Slice SchemaNode)
    (position : Std.Usize) (variants : NativeVec (NativeVec Std.U8))
    (original : List ProfileSchema.Value) (positionBound : position.val ≤ values.val.length)
    (paired : SchemaMeanings (values.val.drop position.val) original)
    (room : variants.val.length + (values.val.length - position.val) ≤ Usize.max) :
    AuthsNativeRecipe.auths_gateway_kernel.profile_schema.enum_schema_loop values variants position ⦃ actual =>
      actual.1.map nativeScalarMeaning = ProfileSchema.enumFold (variants.val.map bytes) original ⦄ := by
  generalize remaining : values.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position variants original with
  | h count ih =>
    unfold AuthsNativeRecipe.auths_gateway_kernel.profile_schema.enum_schema_loop
    split <;> rename_i finished
    · have ended : values.val.length ≤ position.val := by simpa using finished
      have originalEmpty : original = [] := by
        apply List.eq_nil_of_length_eq_zero
        simpa only [List.drop_eq_nil_of_le ended, List.length_nil] using (schema_values_count paired).symm
      step with native_schema_enum_limits_exact (AuthsNativeRecipe.alloc.vec.Vec.deref variants)
        as ⟨valid, validMeaning⟩
      cases valid <;> simp_all [originalEmpty, ProfileSchema.enumFold, nativeScalarMeaning,
        nativeNameColumn, native_deref_contents]
    · have inside : position.val < values.val.length := by simpa using finished
      step with Slice.index_usize_spec values position inside as ⟨value, valueAt⟩
      have nativeSuffix : values.val.drop position.val = value :: values.val.drop (position.val + 1) := by
        simpa only [valueAt] using List.drop_eq_getElem_cons inside
      rw [nativeSuffix] at paired
      cases original with
      | nil => cases paired
      | cons originalHead originalTail =>
          cases paired with
          | cons head tail =>
              cases head with
              | text text =>
                  step with native_schema_enum_variant_exact (AuthsNativeRecipe.alloc.vec.Vec.deref text)
                    as ⟨allowed, allowedMeaning⟩
                  have byteMeaning : allowed = decide (ScalarProjection.EnumVariant (bytes text)) := by
                    simpa only [schemaSliceBytes, bytes, native_deref_contents] using allowedMeaning
                  cases allowed with
                  | false =>
                      have invalid : ¬ScalarProjection.EnumVariant (bytes text) := by simpa using byteMeaning.symm
                      simp [ProfileSchema.enumFold, invalid]
                  | true =>
                      have admitted : ScalarProjection.EnumVariant (bytes text) := by simpa using byteMeaning.symm
                      simp only [Bool.true_eq_true, ↓reduceIte]
                      step with native_schema_copy_bytes (AuthsNativeRecipe.alloc.vec.Vec.deref text)
                        as ⟨copied, copiedMeaning⟩
                      have copiedBytes : bytes copied = bytes text := by
                        simpa only [bytes, native_deref_contents] using congrArg (List.map (·.val)) copiedMeaning
                      have capacity : variants.val.length < Usize.max := by omega
                      step with native_push_exact variants copied capacity as ⟨updated, appended⟩
                      have updatedLength : updated.val.length = variants.val.length + 1 := by
                        simp only [appended, List.length_append, List.length_singleton]
                      step as ⟨next, nextValue⟩
                      have nextBound : next.val ≤ values.val.length := by omega
                      have nextPairs : SchemaMeanings (values.val.drop next.val) originalTail := by
                        simpa only [nextValue] using tail
                      have nextRoom : updated.val.length + (values.val.length - next.val) ≤ Usize.max := by omega
                      have smaller : values.val.length - next.val < count := by omega
                      apply spec_mono (ih _ smaller next updated originalTail nextBound nextPairs nextRoom rfl)
                      intro actual exact
                      simpa only [ProfileSchema.enumFold, admitted, ↓reduceIte,
                        appended, List.map_append, List.map_singleton, copiedBytes] using exact
              | _ => simp [ProfileSchema.enumFold]

@[step] theorem native_schema_parse_enum_exact (values : Slice SchemaNode)
    (original : List ProfileSchema.Value) (paired : SchemaMeanings values.val original) :
    AuthsNativeRecipe.auths_gateway_kernel.profile_schema.enum_schema values ⦃ actual =>
      actual.map nativeScalarMeaning = ProfileSchema.enumResult original ⦄ := by
  have sizes := schema_values_count paired
  unfold AuthsNativeRecipe.auths_gateway_kernel.profile_schema.enum_schema
    AuthsNativeRecipe.auths_gateway_kernel.scalars.MAX_ENUM_VARIANTS
  by_cases empty : values.val = []
  · have modelEmpty : original = [] := List.eq_nil_of_length_eq_zero (by simpa only [empty, List.length_nil] using sizes.symm)
    simp [empty, core.slice.Slice.is_empty, modelEmpty, ProfileSchema.enumResult, ProfileSchema.texts,
      ScalarProjection.EnumSchema]
  · simp only [core.slice.Slice.is_empty, List.isEmpty_eq_false.mpr empty, bind_tc_ok,
      Bool.false_eq_true, ↓reduceIte]
    by_cases large : 32 < values.val.length
    · have nativeLarge : values.len > 32#usize := by scalar_tac
      have refused := ProfileSchema.enum_result_count_refusal original (Or.inr (by omega))
      simp [nativeLarge, refused]
    · have nativeBound : ¬values.len > 32#usize := by scalar_tac
      simp only [nativeBound, ↓reduceIte]
      step with native_parse_enum_suffix values 0#usize
        (AuthsNativeRecipe.alloc.vec.Vec.new (NativeVec Std.U8)) original (by simp)
        (by simpa only [List.drop_zero] using paired)
        (by simpa only [native_empty_contents, List.length_nil, Nat.zero_add, Nat.sub_zero] using values.property)
        as ⟨actual, exact⟩
      cases control : actual.2 <;> simpa only [control, bind_tc_ok, spec_ok,
        native_empty_contents, List.map_nil, ProfileSchema.enum_fold_start] using exact

/- This inline-expression lemma matches the generated enum-member branch. It
does not replace an Auths function or assume a parser verdict: every option and
every original kind is covered, and only the native array arm calls the parser. -/
private theorem native_enum_member_exact (input : Option SchemaNode)
    (original : Option ProfileSchema.Value) (meaning : MaybeSchemaMeaning input original) :
    (do
      match input with
      | some (.Array values) => AuthsNativeRecipe.auths_gateway_kernel.profile_schema.enum_schema
          (AuthsNativeRecipe.alloc.vec.Vec.deref values)
      | _ => ok none) ⦃ actual => actual.map nativeScalarMeaning =
        match original with | some (.array values) => ProfileSchema.enumResult values | _ => none ⦄ := by
  cases input with
  | none =>
      have absent : original = none := (maybe_schema_absence meaning).mp rfl
      simp [absent]
  | some input =>
      cases original with
      | none => simp [MaybeSchemaMeaning] at meaning
      | some original =>
          have paired : SchemaMeaning input original := meaning
          cases paired with
          | array children =>
              apply native_schema_parse_enum_exact _ _
              simpa only [native_deref_contents] using children
          | _ => simp

/-- Complete scalar acceptance/refusal for every represented native schema
tree with its independent original meaning. Exact key sets, kinds, all numeric
bounds and complete enum contents are checked by actual source functions. -/
@[step] theorem native_schema_parse_scalar_exact (input : SchemaNode)
    (original : ProfileSchema.Value) (meaning : SchemaMeaning input original) :
    AuthsNativeRecipe.auths_gateway_kernel.profile_schema.parse_scalar input ⦃ actual =>
      actual.map nativeScalarMeaning = ProfileSchema.parseScalar original ⦄ := by
  cases meaning with
  | @object members originalMembers children =>
      have sourceOrder := ProfileSchema.scalar_source_order_exact originalMembers
      unfold AuthsNativeRecipe.auths_gateway_kernel.profile_schema.parse_scalar
      repeat' first
        | step with native_schema_member_exact _ _ _ children
        | step with native_schema_text_exact
        | step with native_schema_one_key_exact _ _ children
        | step with native_schema_two_keys_exact _ _ children
        | step with native_schema_three_keys_exact _ _ children
        | step with native_schema_string_bound_exact
        | step with native_schema_signed_bound_exact
        | step with native_schema_string_limits_exact
        | step with native_schema_integer_limits_exact
        | step with native_enum_member_exact
        | step
        | split
      all_goals simp_all [← sourceOrder, ProfileSchema.scalarSourceOrder,
        nativeScalarMeaning, ProfileSchema.kindKey, ProfileSchema.typeKey,
        ProfileSchema.variantsKey, ProfileSchema.minimumKey, ProfileSchema.maximumKey,
        ProfileSchema.enumTag, ProfileSchema.booleanTag, ProfileSchema.stringTag,
        ProfileSchema.integerTag, schemaSliceBytes, MaybeSchemaMeaning,
        native_deref_contents, UScalar.eq_equiv, UScalar.le_equiv]
  | _ => simp [AuthsNativeRecipe.auths_gateway_kernel.profile_schema.parse_scalar, ProfileSchema.parseScalar]

@[step] theorem native_schema_parse_field_exact (input : SchemaMember)
    (original : List Nat × ProfileSchema.Value) (meaning : NativeSchemaMemberMeaning input original) :
    AuthsNativeRecipe.auths_gateway_kernel.profile_schema.parse_field input ⦃ actual =>
      actual.map nativeFieldMeaning = sourceFieldParse original ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.profile_schema.parse_field
  step with native_schema_token_exact (AuthsNativeRecipe.alloc.vec.Vec.deref input.name) 64#usize
    as ⟨valid, validMeaning⟩
  have tokenMeaning : valid = OperationIdentity.validToken original.1 64 := by
    simpa only [schemaSliceBytes, bytes, native_deref_contents, meaning.1] using validMeaning
  cases valid with
  | false => simp [sourceFieldParse, ← tokenMeaning]
  | true =>
      simp only [Bool.true_eq_true, ↓reduceIte]
      step with native_schema_parse_scalar_exact input.value original.2 meaning.2 as ⟨parsed, parsedMeaning⟩
      cases parsed with
      | none => simp_all [sourceFieldParse]
      | some schema =>
          step with native_schema_scalar_clone_exact schema as ⟨copiedSchema, sameSchema⟩
          step with native_schema_copy_bytes (AuthsNativeRecipe.alloc.vec.Vec.deref input.name)
            as ⟨copiedName, sameName⟩
          have nameMeaning : bytes copiedName = original.1 := by
            calc
              bytes copiedName = bytes input.name := by
                simpa only [bytes, native_deref_contents] using congrArg (List.map (·.val)) sameName
              _ = original.1 := meaning.1
          simp_all [sourceFieldParse, nativeFieldMeaning]

end Auths.Product.NativeCompiler.Refinement
