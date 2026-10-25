import Auths.Product.NativeCompilerPathRules
import Auths.Product.NativeCompilerReadPointers

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.StdModel

private theorem owned_rule_lookup (values : List (String × NativeScalarSchema)) (wanted : String) :
    AuthsNativeRecipe.NativeModel.lookupBorrowed (AuthsNativeRecipe.core.borrow.Borrow.Blanket String)
      AuthsNativeRecipe.alloc.string.String.Insts.CoreCmpOrd wanted values ⦃ actual =>
      actual.map nativeScalarMeaning = RecipeConsumption.schemaFor wanted
        (values.map fun entry => (entry.1, nativeScalarMeaning entry.2)) ⦄ := by
  induction values with
  | nil => simp [AuthsNativeRecipe.NativeModel.lookupBorrowed, RecipeConsumption.schemaFor]
  | cons first rest ih =>
      rcases first with ⟨key, schema⟩
      simp only [AuthsNativeRecipe.NativeModel.lookupBorrowed,
        AuthsNativeRecipe.core.borrow.Borrow.Blanket.borrow, bind_tc_ok, native_string_order_exact]
      by_cases same : wanted = key
      · simp [same, RecipeConsumption.schemaFor]
      · have different : compare wanted key ≠ .eq := by simpa [Std.compare_eq_iff_eq] using same
        simpa [different, RecipeConsumption.schemaFor, Ne.symm same] using ih

@[step] theorem native_rule_map_contains_owned (fields : NativeRuleMap) (wanted : String) :
    AuthsNativeRecipe.alloc.collections.btree.map.BTreeMap.contains_key core.core.clone.CloneGlobal
      (AuthsNativeRecipe.core.borrow.Borrow.Blanket String)
      AuthsNativeRecipe.alloc.string.String.Insts.CoreCmpOrd
      AuthsNativeRecipe.alloc.string.String.Insts.CoreCmpOrd fields wanted ⦃ actual =>
      actual = (RecipeConsumption.schemaFor wanted (nativeRuleMapMeaning fields)).isSome ⦄ := by
  unfold AuthsNativeRecipe.alloc.collections.btree.map.BTreeMap.contains_key
    AuthsNativeRecipe.alloc.collections.btree.map.BTreeMap.get
  step with owned_rule_lookup fields.entries.val wanted as ⟨selected, meaning⟩
  cases selected <;> simp [← meaning, nativeRuleMapMeaning]

end Auths.Product.NativeCompiler.StdModel

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 16000000
set_option maxRecDepth 4096

/-- The complete native observation rule keeps path-prefix effects even if a
later response bound, pointer or expected-field check refuses. It may consume
the original operation_id, but never operator_namespace or recipe_digest. -/
@[step] theorem native_observation_admission_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : AuthsNativeRecipe.recipe.source.ObservationSource)
    (pathFits : ∀ segment ∈ source.path.val, RulePathFits segment)
    (pointerFits : TextFits source.json_pointer) (expectedFits : TextFits source.expected_field)
    (fieldFits : ∀ entry ∈ input.fields.entries.val, TextFits entry.1)
    (ordered : ConsumptionOrdered input.consumed)
    (room : source.path.val.length ≤ 16 →
      input.consumed.all.elements.val.length + source.path.val.length + 1 ≤ Usize.max) :
    AuthsNativeRecipe.recipe.validate.Rules.observation input source ⦃ actual =>
      ClaimMeaning input (RecipeRuleAdmission.observation (nativeRuleMapMeaning input.fields)
        (ruleObservation source) (consumptionState input.consumed)) actual ∧
      actual.2.consumed.all.elements.val.length ≤ input.consumed.all.elements.val.length + source.path.val.length + 1 ∧
      actual.2.consumed.body = input.consumed.body ∧ actual.2.consumed.binds = input.consumed.binds ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.Rules.observation
  step with native_path_rules_exact input (AuthsNativeRecipe.alloc.vec.Vec.deref source.path) .Observation
    pathFits fieldFits ordered (by intro bounded; have capacity := room bounded; omega)
    as ⟨walked, pathMeaning, growth, sameBody, sameBinds⟩
  let pathModel := RecipeRuleAdmission.path (nativeRuleMapMeaning input.fields) .observation
    (source.path.val.map ruleSegment) (consumptionState input.consumed)
  have sameFields : walked.2.fields = input.fields := pathMeaning.2.2.1
  have sameState : consumptionState walked.2.consumed = pathModel.2 := pathMeaning.2.1
  have nextOrdered := pathMeaning.2.2.2
  cases verdict : pathModel.1 with
  | error error =>
      have refused : walked.1 = .Err (consumptionError error) := by
        simpa [pathModel, rulePathRole, verdict, consumptionVerdict] using pathMeaning.1
      simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, ClaimMeaning,
        RecipeRuleAdmission.observation, ruleObservation, RecipeRuleAdmission.andThen,
        ← pathModel, verdict, sameState, sameFields, nextOrdered,
        consumptionVerdict, sameBody, sameBinds]
      omega
  | ok unit =>
      cases unit
      have accepted : walked.1 = .Ok () := by
        simpa [pathModel, rulePathRole, verdict, consumptionVerdict] using pathMeaning.1
      have pathCount : source.path.val.length ≤ 16 := by
        unfold pathModel RecipeRuleAdmission.path at verdict
        split at verdict <;> rename_i admitted
        · simpa using admitted.2
        · simp [RecipeRuleAdmission.refused] at verdict
      have insertionRoom := room pathCount
      simp only [accepted, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      by_cases zero : source.maximum_response_bytes.val = 0
      · have nativeZero : source.maximum_response_bytes = 0#usize := by scalar_tac
        simp [nativeZero, ClaimMeaning, RecipeRuleAdmission.observation, ruleObservation,
          RecipeAdmissionAtoms.ReadBound, zero, RecipeRuleAdmission.andThen, ← pathModel,
          verdict, sameState, sameFields, nextOrdered, RecipeRuleAdmission.refused,
          consumptionVerdict, consumptionError, sameBody, sameBinds]
        omega
      · have nativePositive : source.maximum_response_bytes ≠ 0#usize := by scalar_tac
        simp only [nativePositive, ↓reduceIte]
        by_cases large : 65536 < source.maximum_response_bytes.val
        · have nativeLarge : source.maximum_response_bytes > 65536#usize := by scalar_tac
          simp [nativeLarge, ClaimMeaning, RecipeRuleAdmission.observation, ruleObservation,
            RecipeAdmissionAtoms.ReadBound, Nat.not_le.mpr large, RecipeRuleAdmission.andThen,
            ← pathModel, verdict, sameState, sameFields, nextOrdered,
            RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, sameBody, sameBinds]
          omega
        · have readBound : RecipeAdmissionAtoms.ReadBound source.maximum_response_bytes.val := by
            unfold RecipeAdmissionAtoms.ReadBound; omega
          have nativeWithin : ¬source.maximum_response_bytes > 65536#usize := by scalar_tac
          simp only [nativeWithin, ↓reduceIte]
          step with native_deref_view_exact source.json_pointer pointerFits as ⟨pointer, pointerView⟩
          subst pointer
          step with native_response_pointer_exact (nativeTextView source.json_pointer pointerFits) as ⟨valid, validity⟩
          cases valid with
          | false =>
              have invalid : ¬RecipeAdmissionAtoms.ResponsePointer (textBytes source.json_pointer) := by
                simpa [RecipeAdmissionAtoms.responsePointer, native_text_view_bytes] using validity.symm
              simp [ClaimMeaning, RecipeRuleAdmission.observation, ruleObservation, invalid,
                RecipeRuleAdmission.andThen, ← pathModel, verdict, sameState, sameFields,
                nextOrdered, RecipeRuleAdmission.refused, consumptionVerdict, consumptionError,
                sameBody, sameBinds]
              omega
          | true =>
              have pointerValid : RecipeAdmissionAtoms.ResponsePointer (textBytes source.json_pointer) := by
                simpa [RecipeAdmissionAtoms.responsePointer, native_text_view_bytes] using validity.symm
              simp only [Bool.true_eq_true, ↓reduceIte]
              step with native_rule_map_contains_owned walked.2.fields source.expected_field as ⟨present, presence⟩
              cases present with
              | false =>
                  simp [ClaimMeaning, RecipeRuleAdmission.observation, ruleObservation,
                    RecipeRuleAdmission.andThen, ← pathModel, verdict, readBound, pointerValid,
                    ← presence, sameState, sameFields, nextOrdered, RecipeRuleAdmission.refused,
                    consumptionVerdict, consumptionError, sameBody, sameBinds]
                  omega
              | true =>
                  simp only [Bool.true_eq_true, ↓reduceIte]
                  step with native_deref_view_exact source.expected_field expectedFits as ⟨expected, expectedView⟩
                  subst expected
                  step with native_namespace_recipe_field_exact source.expected_field expectedFits as ⟨reserved, reservedMeaning⟩
                  cases reserved with
                  | true =>
                      simp [ClaimMeaning, RecipeRuleAdmission.observation, ruleObservation,
                        RecipeRuleAdmission.andThen, ← pathModel, verdict, readBound, pointerValid,
                        ← reservedMeaning, sameState, sameFields, nextOrdered, RecipeRuleAdmission.refused,
                        consumptionVerdict, consumptionError, sameBody, sameBinds]
                      omega
                  | false =>
                      simp only [Bool.false_eq_true, ↓reduceIte]
                      have capacity : walked.2.consumed.all.elements.val.length < Usize.max := by omega
                      step with native_consume_exact walked.2 source.expected_field expectedFits nextOrdered capacity
                        as ⟨updated, used, finalFields, finalOrder, finalGrowth, finalBody, finalBinds⟩
                      refine ⟨?_, by omega, finalBody.trans sameBody, finalBinds.trans sameBinds⟩
                      simp [ClaimMeaning, RecipeRuleAdmission.observation, ruleObservation,
                        RecipeRuleAdmission.andThen, ← pathModel, verdict, readBound, pointerValid,
                        ← reservedMeaning, ← presence, sameState, sameFields, finalFields,
                        used, finalOrder, RecipeRuleAdmission.accepted, consumptionVerdict]

/-- The native pre-entry rule first validates/consumes its path, then checks
the complete original pointer set and response bound. Failed pointer sets do
not undo path consumption or alter body/bind carriers. -/
@[step] theorem native_pre_entry_admission_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : AuthsNativeRecipe.recipe.source.PreEntrySource)
    (pathFits : ∀ segment ∈ source.path.val, RulePathFits segment)
    (pointerFits : ∀ pointer ∈ source.pointers.val, TextFits pointer)
    (fieldFits : ∀ entry ∈ input.fields.entries.val, TextFits entry.1)
    (ordered : ConsumptionOrdered input.consumed)
    (room : source.path.val.length ≤ 16 →
      input.consumed.all.elements.val.length + source.path.val.length ≤ Usize.max) :
    AuthsNativeRecipe.recipe.validate.Rules.pre_entry input source ⦃ actual =>
      ClaimMeaning input (RecipeRuleAdmission.preEntry (nativeRuleMapMeaning input.fields)
        (rulePreEntry source) (consumptionState input.consumed)) actual ∧
      actual.2.consumed.all.elements.val.length ≤ input.consumed.all.elements.val.length + source.path.val.length ∧
      actual.2.consumed.body = input.consumed.body ∧ actual.2.consumed.binds = input.consumed.binds ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.Rules.pre_entry
  step with native_path_rules_exact input (AuthsNativeRecipe.alloc.vec.Vec.deref source.path) .PreEntry
    pathFits fieldFits ordered room as ⟨walked, pathMeaning, growth, sameBody, sameBinds⟩
  let pathModel := RecipeRuleAdmission.path (nativeRuleMapMeaning input.fields) .preEntry
    (source.path.val.map ruleSegment) (consumptionState input.consumed)
  have sameFields : walked.2.fields = input.fields := pathMeaning.2.2.1
  have sameState : consumptionState walked.2.consumed = pathModel.2 := pathMeaning.2.1
  have nextOrdered := pathMeaning.2.2.2
  cases verdict : pathModel.1 with
  | error error =>
      have refused : walked.1 = .Err (consumptionError error) := by
        simpa [pathModel, rulePathRole, verdict, consumptionVerdict] using pathMeaning.1
      simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, ClaimMeaning,
        RecipeRuleAdmission.preEntry, rulePreEntry, RecipeRuleAdmission.andThen,
        ← pathModel, verdict, sameState, sameFields, nextOrdered,
        consumptionVerdict, growth, sameBody, sameBinds]
  | ok unit =>
      cases unit
      have accepted : walked.1 = .Ok () := by
        simpa [pathModel, rulePathRole, verdict, consumptionVerdict] using pathMeaning.1
      simp only [accepted, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      step with native_pre_entry_pointers_exact (AuthsNativeRecipe.alloc.vec.Vec.deref source.pointers)
        source.maximum_response_bytes pointerFits as ⟨valid, validity⟩
      cases valid with
      | false =>
          have invalid : ¬RecipeAdmissionAtoms.PreEntryPointers
              (source.pointers.val.map textBytes) source.maximum_response_bytes.val := by simpa using validity.symm
          simp [ClaimMeaning, RecipeRuleAdmission.preEntry, rulePreEntry, RecipeRuleAdmission.andThen,
            ← pathModel, verdict, invalid, sameState, sameFields, nextOrdered,
            RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, growth, sameBody, sameBinds]
      | true =>
          have admitted : RecipeAdmissionAtoms.PreEntryPointers
              (source.pointers.val.map textBytes) source.maximum_response_bytes.val := by simpa using validity.symm
          simp [ClaimMeaning, RecipeRuleAdmission.preEntry, rulePreEntry, RecipeRuleAdmission.andThen,
            ← pathModel, verdict, admitted, sameState, sameFields, nextOrdered,
            RecipeRuleAdmission.accepted, consumptionVerdict, growth, sameBody, sameBinds]

end Auths.Product.NativeCompiler.Refinement
