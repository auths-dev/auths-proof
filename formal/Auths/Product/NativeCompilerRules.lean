import Auths.Product.NativeCompilerRuleInterfaces
import Auths.Product.NativeCompilerRuleNames
import Auths.Product.NativeCompilerSchemaRoot

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

private theorem native_rule_fields_suffix (iterator : core.slice.iter.Iter NativeFieldSpec)
    (output : NativeRuleMap)
    (room : output.entries.val.length + (iterator.slice.val.length - iterator.i) ≤ Usize.max) :
    AuthsNativeRecipe.recipe.profile.rule_fields_loop iterator output ⦃ actual =>
      nativeRuleResult actual = sourceRuleVerdict (nativeRuleMapMeaning output)
        ((iterator.slice.val.drop iterator.i).map nativeFieldMeaning) ⦄ := by
  generalize remaining : iterator.slice.val.length - iterator.i = count
  induction count using Nat.strong_induction_on generalizing iterator output with
  | h count ih =>
    unfold AuthsNativeRecipe.recipe.profile.rule_fields_loop
    by_cases inside : iterator.i < iterator.slice.val.length
    · simp only [core.slice.iter.IteratorSliceIter.next, dif_pos inside, bind_tc_ok]
      let field := iterator.slice.val[iterator.i]
      let next : core.slice.iter.Iter NativeFieldSpec := { iterator with i := iterator.i + 1 }
      have originalSuffix : iterator.slice.val.drop iterator.i = field :: iterator.slice.val.drop next.i := by
        simpa only [field, next] using List.drop_eq_getElem_cons inside
      step with native_vector_clone_exact core.clone.CloneU8 field.name
        (by intro byte _; rfl) as ⟨copiedName, sameName⟩
      step with native_rule_name_decode copiedName as ⟨nameResult, nameMeaning⟩
      have decoded : utf8StringValue nameResult = Rules.decodeName (bytes field.name) := by
        simpa only [sameName] using nameMeaning
      cases nameResult with
      | Err error =>
          have invalid : Rules.decodeName (bytes field.name) = none := by
            simpa only [utf8StringValue] using decoded.symm
          simp only [nativeRuleResult, sourceRuleVerdict, originalSuffix, List.map_cons,
            nativeFieldMeaning, Rules.build, invalid, Except.mapError, spec_ok]
      | Ok name =>
          have nameAt : Rules.decodeName (bytes field.name) = some name := by
            simpa only [utf8StringValue] using decoded.symm
          step with native_schema_scalar_clone_exact field.schema as ⟨copiedSchema, sameSchema⟩
          have capacity : output.entries.val.length < Usize.max := by omega
          step with native_rule_map_insert output name copiedSchema capacity as ⟨inserted, previous, contents⟩
          have insertedView :
              (inserted.1.map nativeScalarMeaning, nativeRuleMapMeaning inserted.2) =
                Rules.insert name (nativeScalarMeaning field.schema) (nativeRuleMapMeaning output) := by
            simpa only [nativeRuleMapMeaning, previous, contents, sameSchema] using
              Rules.insert_map nativeScalarMeaning name field.schema output.entries.val
          have insertedLength : inserted.2.entries.val.length ≤ output.entries.val.length + 1 := by
            rw [contents]
            exact Rules.insert_length name copiedSchema output.entries.val
          cases previousAt : inserted.1 with
          | some old =>
              have replaced : (Rules.insert name (nativeScalarMeaning field.schema)
                  (nativeRuleMapMeaning output)).1 = some (nativeScalarMeaning old) := by
                simpa only [previousAt, Option.map_some] using (congrArg Prod.fst insertedView).symm
              simp only [previousAt, core.option.Option.is_some, Bool.true_eq_true, ↓reduceIte,
                nativeRuleResult, sourceRuleVerdict, originalSuffix, List.map_cons,
                nativeFieldMeaning, Rules.build, nameAt, replaced, Option.isSome_some, Except.mapError, spec_ok]
          | none =>
              have fresh : (Rules.insert name (nativeScalarMeaning field.schema)
                  (nativeRuleMapMeaning output)).1 = none := by
                simpa only [previousAt, Option.map_none] using (congrArg Prod.fst insertedView).symm
              have updated : nativeRuleMapMeaning inserted.2 =
                  (Rules.insert name (nativeScalarMeaning field.schema) (nativeRuleMapMeaning output)).2 :=
                congrArg Prod.snd insertedView
              simp only [previousAt, core.option.Option.is_some, Bool.false_eq_true, ↓reduceIte]
              have nextRoom : inserted.2.entries.val.length + (next.slice.val.length - next.i) ≤ Usize.max := by
                simp only [next]
                omega
              have smaller : next.slice.val.length - next.i < count := by
                simp only [next] at *
                omega
              apply spec_mono (ih _ smaller next inserted.2 nextRoom rfl)
              intro actual exact
              simpa only [sourceRuleVerdict, originalSuffix, List.map_cons, nativeFieldMeaning,
                Rules.build, nameAt, fresh, Option.isSome_none, ↓reduceIte, updated,
                next] using exact
    · have ended : iterator.slice.val.length ≤ iterator.i := by omega
      simp only [core.slice.iter.IteratorSliceIter.next, dif_neg inside, bind_tc_ok,
        nativeRuleResult, sourceRuleVerdict, List.drop_eq_nil_of_le ended, List.map_nil,
        Rules.build, Except.mapError, spec_ok]

/-- Complete native rule construction for all represented input field lists.
Both malformed UTF-8 and duplicate native names return InvalidProfileLock;
success retains every original schema association in actual BTreeMap key order. -/
@[step] theorem native_rule_fields_exact (fields : Slice NativeFieldSpec) :
    AuthsNativeRecipe.recipe.profile.rule_fields fields ⦃ actual =>
      nativeRuleResult actual = sourceRuleVerdict [] (nativeFieldColumn fields) ⦄ := by
  unfold AuthsNativeRecipe.recipe.profile.rule_fields
    AuthsNativeRecipe.alloc.collections.btree.map.BTreeMapKVGlobal.new
    SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter
  simp only [bind_tc_ok]
  apply spec_mono (native_rule_fields_suffix ⟨fields, 0⟩
    ⟨AuthsNativeRecipe.alloc.vec.Vec.new (String × NativeScalarSchema)⟩
    (by simpa only [native_empty_contents, List.length_nil, Nat.zero_add, Nat.sub_zero] using fields.property))
  intro actual exact
  simpa only [nativeRuleMapMeaning, native_empty_contents, List.map_nil,
    List.drop_zero, nativeFieldColumn] using exact

theorem native_rule_fields_success_has_original_meaning (fields : Slice NativeFieldSpec) :
    AuthsNativeRecipe.recipe.profile.rule_fields fields ⦃ actual =>
      match actual with
      | .Ok output => Rules.Meaning (nativeFieldColumn fields) (nativeRuleMapMeaning output)
      | .Err error => error = .InvalidProfileLock ∧ ¬Rules.Admitted (nativeFieldColumn fields) ⦄ := by
  apply spec_mono (native_rule_fields_exact fields)
  intro actual exact
  cases model : Rules.build [] (nativeFieldColumn fields) with
  | error unit =>
      cases unit
      cases actual with
      | Ok output => simp [nativeRuleResult, sourceRuleVerdict, model] at exact
      | Err error =>
          have same : error = AuthsNativeRecipe.recipe.GatewayRecipeError.InvalidProfileLock := by
            simpa only [nativeRuleResult, sourceRuleVerdict, model, Except.mapError, Except.error.injEq] using exact
          exact ⟨same, (Rules.build_refusal_exact _).mp model⟩
  | ok output =>
      have meaning := Rules.build_has_original_meaning (nativeFieldColumn fields) output model
      cases actual with
      | Err error => simp [nativeRuleResult, sourceRuleVerdict, model] at exact
      | Ok native =>
          have same : nativeRuleMapMeaning native = output := by
            simpa only [nativeRuleResult, sourceRuleVerdict, model, Except.mapError, Except.ok.injEq] using exact
          simpa only [same] using meaning

/-- Independently valid parsed field layouts earn UTF-8 validity and uniqueness
before the native builder runs. No String decode or map success is assumed. -/
theorem native_rule_fields_useful_layout (fields : Slice NativeFieldSpec)
    (layout : FieldProjection.LayoutValid (nativeFieldColumn fields)) :
    AuthsNativeRecipe.recipe.profile.rule_fields fields ⦃ actual =>
      ∃ output : NativeRuleMap, actual = .Ok output ∧
        Rules.Meaning (nativeFieldColumn fields) (nativeRuleMapMeaning output) ⦄ := by
  have admitted := Rules.layout_earns_rule_admission (nativeFieldColumn fields) layout
  obtain ⟨model, built⟩ := Rules.admitted_has_useful_build (nativeFieldColumn fields) admitted
  apply spec_mono (native_rule_fields_exact fields)
  intro actual exact
  cases actual with
  | Err error => simp [nativeRuleResult, sourceRuleVerdict, built] at exact
  | Ok output =>
      have same : nativeRuleMapMeaning output = model := by
        simpa only [nativeRuleResult, sourceRuleVerdict, built, Except.mapError, Except.ok.injEq] using exact
      refine ⟨output, rfl, ?_⟩
      simpa only [same] using Rules.build_has_original_meaning (nativeFieldColumn fields) model built

theorem native_rule_fields_invalid_refuses (fields : Slice NativeFieldSpec)
    (invalid : ¬Rules.Admitted (nativeFieldColumn fields)) :
    AuthsNativeRecipe.recipe.profile.rule_fields fields ⦃ actual => actual = .Err .InvalidProfileLock ⦄ := by
  have refused := (Rules.build_refusal_exact _).mpr invalid
  apply spec_mono (native_rule_fields_exact fields)
  intro actual exact
  cases actual with
  | Ok output => simp [nativeRuleResult, sourceRuleVerdict, refused] at exact
  | Err error =>
      have same : error = AuthsNativeRecipe.recipe.GatewayRecipeError.InvalidProfileLock := by
        simpa only [nativeRuleResult, sourceRuleVerdict, refused, Except.mapError, Except.error.injEq] using exact
      simp only [same]

theorem native_rule_fields_retains_full_pairs (fields : Slice NativeFieldSpec)
    (layout : FieldProjection.LayoutValid (nativeFieldColumn fields)) :
    AuthsNativeRecipe.recipe.profile.rule_fields fields ⦃ actual =>
      ∃ output : NativeRuleMap, actual = .Ok output ∧
        (nativeRuleMapMeaning output).length = (nativeFieldColumn fields).length ∧
        (∀ field ∈ nativeFieldColumn fields, ∃ entry ∈ nativeRuleMapMeaning output,
          textBytes entry.1 = field.name ∧ entry.2 = field.schema) ∧
        (∀ entry ∈ nativeRuleMapMeaning output, ∃ field ∈ nativeFieldColumn fields,
          textBytes entry.1 = field.name ∧ entry.2 = field.schema) ⦄ := by
  apply spec_mono (native_rule_fields_useful_layout fields layout)
  rintro actual ⟨output, same, meaning⟩
  exact ⟨output, same, Rules.meaning_keeps_complete_count _ _ meaning,
    Rules.meaning_keeps_every_original _ _ meaning, Rules.meaning_has_no_extra_entries _ _ meaning⟩

/-- A native parser result earned from independent original schema meaning is
itself a sufficient input for useful native rule-map construction. This composes
these two source components; intervening binding/installation checks and the
complete native validator/driver remain separate obligations. -/
theorem native_profile_root_yields_useful_rule_input (input : Json) (bounded : JsonBounds input)
    (original : ProfileSchema.Value) (meaning : JsonMeaning input original)
    (fields : List FieldProjection.Field) (valid : ProfileSchema.RootMeaning original fields) :
    AuthsNativeRecipe.recipe.profile.parse_root input ⦃ actual =>
      ∃ parsed : NativeVec NativeFieldSpec, actual = .Ok parsed ∧ nativeFieldsMeaning parsed = fields ∧
        (AuthsNativeRecipe.recipe.profile.rule_fields (AuthsNativeRecipe.alloc.vec.Vec.deref parsed) ⦃ rules =>
          ∃ output : NativeRuleMap, rules = .Ok output ∧ Rules.Meaning fields (nativeRuleMapMeaning output) ⦄) ⦄ := by
  have originalLayout := (ProfileSchema.root_meaning_earns_complete_valid_layout original fields valid).2.1
  apply spec_mono (native_profile_root_useful_acceptance input bounded original meaning fields valid)
  rintro actual ⟨parsed, same, originalFields⟩
  refine ⟨parsed, same, originalFields, ?_⟩
  have nativeLayout : FieldProjection.LayoutValid
      (nativeFieldColumn (AuthsNativeRecipe.alloc.vec.Vec.deref parsed)) := by
    change FieldProjection.LayoutValid (nativeFieldsMeaning parsed)
    simpa only [originalFields] using originalLayout
  apply spec_mono (native_rule_fields_useful_layout _ nativeLayout)
  rintro rules ⟨output, sameRules, ruleMeaning⟩
  refine ⟨output, sameRules, ?_⟩
  change Rules.Meaning (nativeFieldsMeaning parsed) (nativeRuleMapMeaning output) at ruleMeaning
  simpa only [originalFields] using ruleMeaning

end Auths.Product.NativeCompiler.Refinement
