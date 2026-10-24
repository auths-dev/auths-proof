import Auths.Product.NativeCompilerSchemaParser

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def nativeProfileResult : core.result.Result (NativeVec NativeFieldSpec) AuthsNativeRecipe.recipe.GatewayRecipeError →
    Except AuthsNativeRecipe.recipe.GatewayRecipeError (List FieldProjection.Field)
  | .Ok fields => .ok (nativeFieldsMeaning fields)
  | .Err error => .error error

def sourceProfileVerdict (original : ProfileSchema.Value) :
    Except AuthsNativeRecipe.recipe.GatewayRecipeError (List FieldProjection.Field) :=
  match ProfileSchema.parseRoot original with
  | some fields => .ok fields
  | none => .error .InvalidProfileLock

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

private theorem native_parse_fields_suffix (members : Slice SchemaMember)
    (position : Std.Usize) (fields : NativeVec NativeFieldSpec)
    (original : List (List Nat × ProfileSchema.Value))
    (positionBound : position.val ≤ members.val.length)
    (paired : SchemaMemberMeanings (members.val.drop position.val) original)
    (room : fields.val.length + (members.val.length - position.val) ≤ Usize.max) :
    AuthsNativeRecipe.auths_gateway_kernel.profile_schema.parse_fields_loop members fields position ⦃ actual =>
      actual.map nativeFieldsMeaning = ProfileSchema.fieldsFold (nativeFieldsMeaning fields) original ⦄ := by
  generalize remaining : members.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position fields original with
  | h count ih =>
    unfold AuthsNativeRecipe.auths_gateway_kernel.profile_schema.parse_fields_loop
    split <;> rename_i finished
    · have ended : members.val.length ≤ position.val := by simpa using finished
      have originalEmpty : original = [] := by
        apply List.eq_nil_of_length_eq_zero
        simpa only [List.drop_eq_nil_of_le ended, List.length_nil] using (schema_members_count paired).symm
      step with native_schema_field_names_exact (AuthsNativeRecipe.alloc.vec.Vec.deref fields)
        as ⟨names, namesMeaning⟩
      have column : nativeFieldColumn (AuthsNativeRecipe.alloc.vec.Vec.deref fields) = nativeFieldsMeaning fields := rfl
      cases names with
      | Err error =>
          have invalid : ¬FieldProjection.LayoutValid (nativeFieldsMeaning fields) := by
            intro valid
            simp only [column, valid, ↓reduceIte, nativeNamesResult] at namesMeaning
            contradiction
          simp [originalEmpty, ProfileSchema.fieldsFold, invalid]
      | Ok names =>
          have valid : FieldProjection.LayoutValid (nativeFieldsMeaning fields) := by
            by_contra invalid
            simp only [column, invalid, ↓reduceIte, nativeNamesResult] at namesMeaning
            contradiction
          simp [originalEmpty, ProfileSchema.fieldsFold, valid]
    · have inside : position.val < members.val.length := by simpa using finished
      step with Slice.index_usize_spec members position inside as ⟨member, memberAt⟩
      have nativeSuffix : members.val.drop position.val = member :: members.val.drop (position.val + 1) := by
        simpa only [memberAt] using List.drop_eq_getElem_cons inside
      rw [nativeSuffix] at paired
      cases original with
      | nil => cases paired
      | cons originalHead originalTail =>
          cases paired with
          | cons head tail =>
              have memberMeaning : NativeSchemaMemberMeaning member originalHead := ⟨rfl, head⟩
              step with native_schema_parse_field_exact member originalHead memberMeaning
                as ⟨parsed, parsedMeaning⟩
              cases parsed with
              | none =>
                  have refused : sourceFieldParse originalHead = none := by
                    simpa only [Option.map_none] using parsedMeaning.symm
                  simp only [spec_ok, Option.map_none, refused_field_stops_fold _ _ _ refused]
              | some field =>
                  have parsedField : sourceFieldParse originalHead = some (nativeFieldMeaning field) := by
                    simpa only [Option.map_some] using parsedMeaning.symm
                  have advance := accepted_field_advances_fold (nativeFieldsMeaning fields)
                    originalHead originalTail (nativeFieldMeaning field) parsedField
                  step with native_schema_field_clone_exact field as ⟨copiedField, sameField⟩
                  have capacity : fields.val.length < Usize.max := by omega
                  step with native_push_exact fields copiedField capacity as ⟨updated, appended⟩
                  have updatedLength : updated.val.length = fields.val.length + 1 := by
                    simp only [appended, List.length_append, List.length_singleton]
                  step as ⟨next, nextValue⟩
                  have nextBound : next.val ≤ members.val.length := by omega
                  have nextPairs : SchemaMemberMeanings (members.val.drop next.val) originalTail := by
                    simpa only [nextValue] using tail
                  have nextRoom : updated.val.length + (members.val.length - next.val) ≤ Usize.max := by omega
                  have smaller : members.val.length - next.val < count := by omega
                  apply spec_mono (ih _ smaller next updated originalTail nextBound nextPairs nextRoom rfl)
                  intro actual exact
                  simpa only [advance, nativeFieldsMeaning, appended, List.map_append,
                    List.map_singleton, sameField] using exact

@[step] theorem native_schema_parse_fields_exact (members : Slice SchemaMember)
    (original : List (List Nat × ProfileSchema.Value))
    (paired : SchemaMemberMeanings members.val original) :
    AuthsNativeRecipe.auths_gateway_kernel.profile_schema.parse_fields members ⦃ actual =>
      actual.map nativeFieldsMeaning = ProfileSchema.parseFields original ⦄ := by
  have sizes := schema_members_count paired
  unfold AuthsNativeRecipe.auths_gateway_kernel.profile_schema.parse_fields
    AuthsNativeRecipe.auths_gateway_kernel.arguments.MAX_PROFILE_FIELDS
  by_cases empty : members.val = []
  · have originalEmpty : original = [] := List.eq_nil_of_length_eq_zero (by simpa only [empty, List.length_nil] using sizes.symm)
    simp [empty, core.slice.Slice.is_empty, originalEmpty, ProfileSchema.parseFields]
  · have originalNonempty : original ≠ [] := by
      intro absent
      have nativeEmpty := List.eq_nil_of_length_eq_zero (by simpa only [absent, List.length_nil] using sizes)
      exact empty nativeEmpty
    simp only [core.slice.Slice.is_empty, List.isEmpty_eq_false.mpr empty, bind_tc_ok,
      Bool.false_eq_true, ↓reduceIte]
    by_cases large : 32 < members.val.length
    · have nativeLarge : members.len > 32#usize := by scalar_tac
      have modelLarge : 32 < original.length := by omega
      simp [nativeLarge, ProfileSchema.parseFields, modelLarge]
    · have bounded : members.val.length ≤ 32 := by omega
      have nativeBound : ¬members.len > 32#usize := by scalar_tac
      have originalBound : original.length ≤ 32 := by omega
      simp only [nativeBound, ↓reduceIte]
      apply spec_mono (native_parse_fields_suffix members 0#usize
        (AuthsNativeRecipe.alloc.vec.Vec.new NativeFieldSpec) original (by simp)
        (by simpa only [List.drop_zero] using paired)
        (by simpa only [native_empty_contents, List.length_nil, Nat.zero_add, Nat.sub_zero] using members.property))
      intro actual exact
      simpa only [nativeFieldsMeaning, native_empty_contents, List.map_nil,
        ProfileSchema.fields_fold_start original ⟨originalNonempty, originalBound⟩] using exact

private theorem native_fields_member_exact (input : Option SchemaNode)
    (original : Option ProfileSchema.Value) (meaning : MaybeSchemaMeaning input original) :
    (do
      match input with
      | some (.Object members) => AuthsNativeRecipe.auths_gateway_kernel.profile_schema.parse_fields
          (AuthsNativeRecipe.alloc.vec.Vec.deref members)
      | _ => ok none) ⦃ actual => actual.map nativeFieldsMeaning =
        match original with | some (.object members) => ProfileSchema.parseFields members | _ => none ⦄ := by
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
          | object children =>
              apply native_schema_parse_fields_exact _ _
              simpa only [native_deref_contents] using children
          | _ => simp

@[step] theorem native_schema_parse_root_exact (input : SchemaNode)
    (original : ProfileSchema.Value) (meaning : SchemaMeaning input original) :
    AuthsNativeRecipe.auths_gateway_kernel.profile_schema.parse_root input ⦃ actual =>
      actual.map nativeFieldsMeaning = ProfileSchema.parseRoot original ⦄ := by
  cases meaning with
  | @object members originalMembers children =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.profile_schema.parse_root
      repeat' first
        | step with native_schema_two_keys_exact _ _ children
        | step with native_schema_member_exact _ _ _ children
        | step with native_schema_text_exact
        | step with native_fields_member_exact
        | step
        | split
      all_goals simp_all [ProfileSchema.parseRoot, ProfileSchema.kindKey,
        ProfileSchema.fieldsKey, ProfileSchema.objectTag, schemaSliceBytes,
        MaybeSchemaMeaning, native_deref_contents, UScalar.eq_equiv]
  | _ => simp [AuthsNativeRecipe.auths_gateway_kernel.profile_schema.parse_root, ProfileSchema.parseRoot]

/-- The actual public native adapter earns an independent original JSON meaning
and its complete schema verdict, including the actual InvalidProfileLock error.
No accepted schema, desired field layout or kernel-parser result is a premise. -/
@[step] theorem native_profile_root_earns_verdict (input : Json) (bounded : JsonBounds input) :
    AuthsNativeRecipe.recipe.profile.parse_root input ⦃ actual =>
      ∃ original, JsonMeaning input original ∧ nativeProfileResult actual = sourceProfileVerdict original ⦄ := by
  unfold AuthsNativeRecipe.recipe.profile.parse_root
  step with native_schema_has_original_meaning input bounded as ⟨converted, original, source, target⟩
  step with native_schema_parse_root_exact converted original target as ⟨parsed, parsedMeaning⟩
  cases parsed with
  | none =>
      refine ⟨original, source, ?_⟩
      simp only [Option.map_none] at parsedMeaning
      simp only [nativeProfileResult, sourceProfileVerdict, ← parsedMeaning]
  | some fields =>
      refine ⟨original, source, ?_⟩
      simp only [Option.map_some] at parsedMeaning
      simp only [nativeProfileResult, sourceProfileVerdict, ← parsedMeaning]

/-- Full native acceptance/refusal against an independently stated meaning of
the original decoded JSON. Original-meaning determinacy removes any freedom in
the witness produced by conversion; no parsed schema is assumed. -/
theorem native_profile_root_exact (input : Json) (bounded : JsonBounds input)
    (original : ProfileSchema.Value) (meaning : JsonMeaning input original) :
    AuthsNativeRecipe.recipe.profile.parse_root input ⦃ actual =>
      nativeProfileResult actual = sourceProfileVerdict original ⦄ := by
  apply spec_mono (native_profile_root_earns_verdict input bounded)
  rintro actual ⟨earned, source, verdict⟩
  have same : earned = original := json_meaning_unique source meaning
  simpa only [same] using verdict

theorem native_profile_root_has_exact_semantics (input : Json) (bounded : JsonBounds input)
    (original : ProfileSchema.Value) (meaning : JsonMeaning input original) :
    AuthsNativeRecipe.recipe.profile.parse_root input ⦃ actual =>
      match actual with
      | .Ok fields => ProfileSchema.RootMeaning original (nativeFieldsMeaning fields)
      | .Err error => error = .InvalidProfileLock ∧
          ¬∃ fields, ProfileSchema.RootMeaning original fields ⦄ := by
  apply spec_mono (native_profile_root_exact input bounded original meaning)
  intro actual exact
  cases parsed : ProfileSchema.parseRoot original with
  | none =>
      cases actual with
      | Ok fields => simp [nativeProfileResult, sourceProfileVerdict, parsed] at exact
      | Err error =>
          have same : error = AuthsNativeRecipe.recipe.GatewayRecipeError.InvalidProfileLock := by
            simpa only [nativeProfileResult, sourceProfileVerdict, parsed, Except.error.injEq] using exact
          exact ⟨same, (ProfileSchema.root_refusal_exact original).mp parsed⟩
  | some fields =>
      have accepted := (ProfileSchema.root_parse_exact original fields).mp parsed
      cases actual with
      | Err error => simp [nativeProfileResult, sourceProfileVerdict, parsed] at exact
      | Ok native =>
          have same : nativeFieldsMeaning native = fields := by
            simpa only [nativeProfileResult, sourceProfileVerdict, parsed, Except.ok.injEq] using exact
          simpa only [same] using accepted

/-- Useful acceptance starts from independent root/field/schema meaning, not a
successful source or kernel parser. The source must produce all original fields. -/
theorem native_profile_root_useful_acceptance (input : Json) (bounded : JsonBounds input)
    (original : ProfileSchema.Value) (meaning : JsonMeaning input original)
    (fields : List FieldProjection.Field) (valid : ProfileSchema.RootMeaning original fields) :
    AuthsNativeRecipe.recipe.profile.parse_root input ⦃ actual =>
      ∃ native : NativeVec NativeFieldSpec, actual = .Ok native ∧ nativeFieldsMeaning native = fields ⦄ := by
  have parsed := (ProfileSchema.root_parse_exact original fields).mpr valid
  apply spec_mono (native_profile_root_exact input bounded original meaning)
  intro actual exact
  cases actual with
  | Err error => simp [nativeProfileResult, sourceProfileVerdict, parsed] at exact
  | Ok native =>
      refine ⟨native, rfl, ?_⟩
      simpa only [nativeProfileResult, sourceProfileVerdict, parsed, Except.ok.injEq] using exact

theorem native_profile_root_invalid_refuses (input : Json) (bounded : JsonBounds input)
    (original : ProfileSchema.Value) (meaning : JsonMeaning input original)
    (invalid : ¬∃ fields, ProfileSchema.RootMeaning original fields) :
    AuthsNativeRecipe.recipe.profile.parse_root input ⦃ actual => actual = .Err .InvalidProfileLock ⦄ := by
  have parsed := (ProfileSchema.root_refusal_exact original).mpr invalid
  apply spec_mono (native_profile_root_exact input bounded original meaning)
  intro actual exact
  cases actual with
  | Ok native => simp [nativeProfileResult, sourceProfileVerdict, parsed] at exact
  | Err error =>
      have same : error = AuthsNativeRecipe.recipe.GatewayRecipeError.InvalidProfileLock := by
        simpa only [nativeProfileResult, sourceProfileVerdict, parsed, Except.error.injEq] using exact
      simp only [same]

end Auths.Product.NativeCompiler.Refinement
