import Auths.Product.NativeCompilerBytes
import Auths.Product.ProfileSchemaCorrectness

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

private theorem schema_member_suffix (members : Slice SchemaMember) (wanted : Slice Std.U8)
    (position : Std.Usize) (original : List (List Nat × ProfileSchema.Value))
    (positionBound : position.val ≤ members.val.length)
    (paired : List.Forall₂ NativeSchemaMemberMeaning (members.val.drop position.val) original) :
    AuthsNativeRecipe.auths_gateway_kernel.profile_schema.member_loop members wanted position ⦃ actual =>
      MaybeSchemaMeaning actual (ProfileSchema.member (schemaSliceBytes wanted) original) ⦄ := by
  generalize remaining : members.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position original with
  | h count ih =>
    unfold AuthsNativeRecipe.auths_gateway_kernel.profile_schema.member_loop
    split <;> rename_i within
    · have inside : position.val < members.val.length := by simpa using within
      step with Slice.index_usize_spec members position inside as ⟨current, currentAt⟩
      have nativeSuffix : members.val.drop position.val = current :: members.val.drop (position.val + 1) := by
        simpa only [currentAt] using List.drop_eq_getElem_cons inside
      rw [nativeSuffix] at paired
      cases original with
      | nil => cases paired
      | cons originalHead originalTail =>
          rcases originalHead with ⟨originalName, originalValue⟩
          cases paired with
          | cons head tail =>
              step with native_schema_byte_equality
                (AuthsNativeRecipe.alloc.vec.Vec.deref current.name) wanted as ⟨same, sameMeaning⟩
              have nameMeaning : schemaSliceBytes (AuthsNativeRecipe.alloc.vec.Vec.deref current.name) = originalName := by
                simpa only [schemaSliceBytes, bytes, native_deref_contents] using head.1
              cases same with
              | true =>
                  have matches : originalName = schemaSliceBytes wanted := by
                    simpa [nameMeaning] using sameMeaning.symm
                  simpa only [Bool.true_eq_true, ↓reduceIte, spec_ok, ProfileSchema.member,
                    matches, if_pos rfl, MaybeSchemaMeaning] using head.2
              | false =>
                  have different : originalName ≠ schemaSliceBytes wanted := by
                    simpa [nameMeaning] using sameMeaning.symm
                  simp only [Bool.false_eq_true, ↓reduceIte]
                  step as ⟨next, nextValue⟩
                  have nextBound : next.val ≤ members.val.length := by omega
                  have nextPairs : List.Forall₂ NativeSchemaMemberMeaning
                      (members.val.drop next.val) originalTail := by
                    simpa only [nextValue] using tail
                  have smaller : members.val.length - next.val < count := by omega
                  apply spec_mono (ih _ smaller next originalTail nextBound nextPairs rfl)
                  intro actual exact
                  simpa only [ProfileSchema.member, different, ↓reduceIte] using exact
    · have ended : members.val.length ≤ position.val := by simpa using within
      have originalEmpty : original = [] := by
        apply List.eq_nil_of_length_eq_zero
        simpa only [List.drop_eq_nil_of_le ended, List.length_nil] using paired.length_eq.symm
      simp only [spec_ok, originalEmpty, ProfileSchema.member, MaybeSchemaMeaning]
      trivial

/-- Complete native lookup agrees with the independent first exact-name
lookup over the full original column, including absent and duplicate names. -/
@[step] theorem native_schema_member_exact (members : Slice SchemaMember) (wanted : Slice Std.U8)
    (original : List (List Nat × ProfileSchema.Value))
    (paired : SchemaMemberMeanings members.val original) :
    AuthsNativeRecipe.auths_gateway_kernel.profile_schema.member members wanted ⦃ actual =>
      MaybeSchemaMeaning actual (ProfileSchema.member (schemaSliceBytes wanted) original) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.profile_schema.member
  apply schema_member_suffix members wanted 0#usize original (by simp)
  simpa only [List.drop_zero] using schema_members_as_pairs paired

@[step] theorem native_schema_text_exact (input : Option SchemaNode) (original : Option ProfileSchema.Value)
    (meaning : MaybeSchemaMeaning input original) (expected : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.profile_schema.text_is input expected ⦃ actual =>
      actual = decide (original = some (.text (schemaSliceBytes expected))) ⦄ := by
  cases input with
  | none =>
      have absent : original = none := (maybe_schema_absence meaning).mp rfl
      simp [AuthsNativeRecipe.auths_gateway_kernel.profile_schema.text_is, absent]
  | some input =>
      cases original with
      | none => simp [MaybeSchemaMeaning] at meaning
      | some original =>
          have paired : SchemaMeaning input original := meaning
          cases paired with
          | text value =>
              unfold AuthsNativeRecipe.auths_gateway_kernel.profile_schema.text_is
              apply spec_mono (native_schema_byte_equality (AuthsNativeRecipe.alloc.vec.Vec.deref value) expected)
              intro actual exact
              simpa only [schemaSliceBytes, bytes, native_deref_contents, Option.some.injEq,
                ProfileSchema.Value.text.injEq] using exact
          | _ => simp [AuthsNativeRecipe.auths_gateway_kernel.profile_schema.text_is]

@[step] theorem native_schema_one_key_exact (members : Slice SchemaMember)
    (original : List (List Nat × ProfileSchema.Value))
    (paired : SchemaMemberMeanings members.val original) (first : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.profile_schema.one_key members first ⦃ actual =>
      actual = decide (ProfileSchema.ExactKeys original [schemaSliceBytes first]) ⦄ := by
  have independent := ProfileSchema.exact_keys_from_presence original [schemaSliceBytes first] (by simp)
  have sizes := schema_members_count paired
  unfold AuthsNativeRecipe.auths_gateway_kernel.profile_schema.one_key
  repeat' first
    | (step with native_schema_member_exact members first original paired as ⟨found, foundMeaning⟩
       have presence := maybe_schema_presence foundMeaning)
    | split
  all_goals simp_all [independent, core.option.Option.is_some, UScalar.eq_equiv]

@[step] theorem native_schema_two_keys_exact (members : Slice SchemaMember)
    (original : List (List Nat × ProfileSchema.Value))
    (paired : SchemaMemberMeanings members.val original) (first second : Slice Std.U8)
    (distinct : schemaSliceBytes first ≠ schemaSliceBytes second) :
    AuthsNativeRecipe.auths_gateway_kernel.profile_schema.two_keys members first second ⦃ actual =>
      actual = decide (ProfileSchema.ExactKeys original [schemaSliceBytes first, schemaSliceBytes second]) ⦄ := by
  have independent := ProfileSchema.exact_keys_from_presence original
    [schemaSliceBytes first, schemaSliceBytes second] (by simp [distinct])
  have sizes := schema_members_count paired
  unfold AuthsNativeRecipe.auths_gateway_kernel.profile_schema.two_keys
  repeat' first
    | (step with native_schema_member_exact members _ original paired as ⟨found, foundMeaning⟩
       have presence := maybe_schema_presence foundMeaning)
    | split
  all_goals simp_all [independent, core.option.Option.is_some, UScalar.eq_equiv]

@[step] theorem native_schema_three_keys_exact (members : Slice SchemaMember)
    (original : List (List Nat × ProfileSchema.Value))
    (paired : SchemaMemberMeanings members.val original) (first second third : Slice Std.U8)
    (distinct : ([schemaSliceBytes first, schemaSliceBytes second, schemaSliceBytes third] : List (List Nat)).Nodup) :
    AuthsNativeRecipe.auths_gateway_kernel.profile_schema.three_keys members first second third ⦃ actual =>
      actual = decide (ProfileSchema.ExactKeys original
        [schemaSliceBytes first, schemaSliceBytes second, schemaSliceBytes third]) ⦄ := by
  have independent := ProfileSchema.exact_keys_from_presence original
    [schemaSliceBytes first, schemaSliceBytes second, schemaSliceBytes third] distinct
  have sizes := schema_members_count paired
  unfold AuthsNativeRecipe.auths_gateway_kernel.profile_schema.three_keys
  repeat' first
    | (step with native_schema_member_exact members _ original paired as ⟨found, foundMeaning⟩
       have presence := maybe_schema_presence foundMeaning)
    | split
  all_goals simp_all [independent, core.option.Option.is_some, UScalar.eq_equiv]

@[step] theorem native_schema_string_bound_exact (input : Option SchemaNode)
    (original : Option ProfileSchema.Value) (meaning : MaybeSchemaMeaning input original) :
    AuthsNativeRecipe.auths_gateway_kernel.profile_schema.string_bound input ⦃ actual =>
      actual.map UScalar.val = ProfileSchema.stringBound original ⦄ := by
  cases input with
  | none =>
      have absent : original = none := (maybe_schema_absence meaning).mp rfl
      simp [AuthsNativeRecipe.auths_gateway_kernel.profile_schema.string_bound, absent, ProfileSchema.stringBound]
  | some input =>
      cases original with
      | none => simp [MaybeSchemaMeaning] at meaning
      | some original =>
          have paired : SchemaMeaning input original := meaning
          cases paired <;> simp only [AuthsNativeRecipe.auths_gateway_kernel.profile_schema.string_bound]
          all_goals first
            | simp [ProfileSchema.stringBound, ProfileSchema.numeric]
            | (split_ifs <;> simp_all [ProfileSchema.stringBound, ProfileSchema.numeric] <;> scalar_tac)

@[step] theorem native_schema_signed_bound_exact (input : Option SchemaNode)
    (original : Option ProfileSchema.Value) (meaning : MaybeSchemaMeaning input original) :
    AuthsNativeRecipe.auths_gateway_kernel.profile_schema.signed_bound input ⦃ actual =>
      actual.map IScalar.val = ProfileSchema.signedBound original ⦄ := by
  cases input with
  | none =>
      have absent : original = none := (maybe_schema_absence meaning).mp rfl
      simp [AuthsNativeRecipe.auths_gateway_kernel.profile_schema.signed_bound, absent, ProfileSchema.signedBound]
  | some input =>
      cases original with
      | none => simp [MaybeSchemaMeaning] at meaning
      | some original =>
          have paired : SchemaMeaning input original := meaning
          cases paired <;> simp only [AuthsNativeRecipe.auths_gateway_kernel.profile_schema.signed_bound]
          all_goals first
            | simp [ProfileSchema.signedBound]
            | (split_ifs <;> simp_all [ProfileSchema.signedBound, UScalar.le_equiv] <;> scalar_tac)

@[step] theorem native_schema_string_limits_exact (minimum maximum : Std.Usize) :
    AuthsNativeRecipe.auths_gateway_kernel.scalars.string_schema_valid minimum maximum ⦃ actual =>
      actual = decide (ScalarProjection.StringSchema minimum.val maximum.val) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.scalars.string_schema_valid
    AuthsNativeRecipe.auths_gateway_kernel.scalars.MAX_TEXT_BYTES ScalarProjection.StringSchema
  split <;> simp_all [UScalar.le_equiv]

@[step] theorem native_schema_integer_limits_exact (minimum maximum : Std.I64) :
    AuthsNativeRecipe.auths_gateway_kernel.scalars.integer_schema_valid minimum maximum ⦃ actual =>
      actual = decide (ScalarProjection.IntegerSchema minimum.val maximum.val) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.scalars.integer_schema_valid
    AuthsNativeRecipe.auths_gateway_kernel.scalars.MAX_JSON_INTEGER ScalarProjection.IntegerSchema
  repeat' first | step | split
  all_goals simp_all [IScalar.le_equiv]

end Auths.Product.NativeCompiler.Refinement
