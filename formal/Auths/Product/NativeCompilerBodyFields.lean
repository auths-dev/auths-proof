import Auths.Product.NativeCompilerRuleState
import Auths.Product.NativeCompilerEmitterState

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.StdModel

theorem native_text_name_decode (name : String) (fits : TextFits name) :
    Rules.decodeName (textBytes name) = some name := by
  have parsed := native_str_decode_exact (nativeTextView name fits)
  simpa [native_text_view_bytes, native_text_view_array] using parsed

@[step] theorem native_rule_map_contains_borrowed (fields : NativeRuleMap) (name : String)
    (nameFits : TextFits name) (fieldFits : ∀ entry ∈ fields.entries.val, TextFits entry.1) :
    AuthsNativeRecipe.alloc.collections.btree.map.BTreeMap.contains_key core.core.clone.CloneGlobal
      AuthsNativeRecipe.alloc.string.String.Insts.CoreBorrowBorrowStr
      AuthsNativeRecipe.alloc.string.String.Insts.CoreCmpOrd
      AuthsNativeRecipe.Str.Insts.CoreCmpOrd fields (nativeTextView name nameFits) ⦃ actual =>
      actual = (RecipeConsumption.schemaFor name (nativeRuleMapMeaning fields)).isSome ⦄ := by
  unfold AuthsNativeRecipe.alloc.collections.btree.map.BTreeMap.contains_key
  step with native_rule_map_lookup fields name nameFits fieldFits as ⟨selected, meaning⟩
  cases selected <;> simp [← meaning]

end Auths.Product.NativeCompiler.StdModel

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 12000000
set_option maxRecDepth 4096

/-- Exact native rendering-field admission. It first checks the complete
original field map, then token/reserved-name grammar, then records the same
owned name in both all/body sets. Refusal preserves the original ledger. -/
@[step] theorem native_body_field_ref_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (name : String) (fits : TextFits name)
    (fieldFits : ∀ entry ∈ input.fields.entries.val, TextFits entry.1)
    (ordered : ConsumptionOrdered input.consumed)
    (allRoom : input.consumed.all.elements.val.length < Usize.max)
    (bodyRoom : input.consumed.body.elements.val.length < Usize.max) :
    AuthsNativeRecipe.recipe.validate.Rules.field_ref input (nativeTextView name fits) ⦃ actual =>
      ClaimMeaning input
        (RecipeRuleAdmission.fieldRef (nativeRuleMapMeaning input.fields) (textBytes name)
          (consumptionState input.consumed)) actual ∧
      actual.2.consumed.all.elements.val.length ≤ input.consumed.all.elements.val.length + 1 ∧
      actual.2.consumed.body.elements.val.length ≤ input.consumed.body.elements.val.length + 1 ∧
      actual.2.consumed.binds = input.consumed.binds ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.Rules.field_ref
  step with native_rule_map_contains_borrowed input.fields name fits fieldFits as ⟨present, presence⟩
  cases present with
  | false =>
      simp [ClaimMeaning, RecipeRuleAdmission.fieldRef, native_text_name_decode name fits,
        ← presence, RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, ordered]
  | true =>
      simp only [Bool.true_eq_true, ↓reduceIte,
        AuthsNativeRecipe.core.str.Str.as_bytes, _root_.core.str.Str.as_bytes, bind_tc_ok]
      step with native_rendered_field_exact (nativeTextView name fits) as ⟨allowed, allowedMeaning⟩
      cases allowed with
      | false =>
          simp [ClaimMeaning, RecipeRuleAdmission.fieldRef, native_text_name_decode name fits,
            native_text_view_bytes, ← allowedMeaning, RecipeRuleAdmission.refused,
            consumptionVerdict, consumptionError, ordered]
      | true =>
          simp only [Bool.true_eq_true, ↓reduceIte]
          step with native_consume_exact input name fits ordered allRoom
            as ⟨used, usedState, sameFields, usedOrder, allGrowth, sameBody, sameBinds⟩
          step with native_text_view_owned name fits as ⟨owned, sameName⟩
          subst owned
          have nextBodyRoom : used.consumed.body.elements.val.length < Usize.max := by simpa [sameBody] using bodyRoom
          step with native_name_set_insert used.consumed.body name usedOrder.2.1 nextBodyRoom
            as ⟨inserted, flag, bodyMembers, bodyOrder, bodyCount, originals⟩
          have allMembers : nameSet used.consumed.all = insert name (nameSet input.consumed.all) := by
            simpa [consumptionState, RecipeConsumption.consume] using congrArg RecipeConsumption.State.all usedState
          have bodyGrowth : inserted.2.elements.val.length ≤ input.consumed.body.elements.val.length + 1 := by
            rw [bodyCount, sameBody]
            split <;> omega
          have nextOrdered : ConsumptionOrdered { used.consumed with body := inserted.2 } :=
            ⟨usedOrder.1, bodyOrder, usedOrder.2.2⟩
          simp [ClaimMeaning, RecipeRuleAdmission.fieldRef, native_text_name_decode name fits,
            native_text_view_bytes, ← allowedMeaning, ← presence, RecipeRuleAdmission.accepted,
            consumptionVerdict, consumptionState, RecipeConsumption.render, allMembers,
            bodyMembers, sameBody, sameBinds, sameFields, nextOrdered, allGrowth, bodyGrowth]

/-- Original-field containment and sortedness earn actual insertion room,
including at refusal. The schema table is the one in this same native state;
no expected field list or successful validation result is supplied. -/
@[step] theorem native_body_field_ref_on_domain (input : AuthsNativeRecipe.recipe.validate.Rules)
    (name : String) (fits : TextFits name) (domain : RuleStateDomain input) :
    AuthsNativeRecipe.recipe.validate.Rules.field_ref input (nativeTextView name fits) ⦃ actual =>
      ClaimMeaning input
        (RecipeRuleAdmission.fieldRef (nativeRuleMapMeaning input.fields) (textBytes name)
          (consumptionState input.consumed)) actual ∧
      RuleStateDomain actual.2 ∧ actual.2.consumed.binds = input.consumed.binds ⦄ := by
  obtain ⟨allBound, bodyBound, bindBound⟩ := rule_state_storage input domain
  apply spec_mono (native_body_field_ref_exact input name fits domain.fieldNames domain.ordered
    (by scalar_tac) (by scalar_tac))
  rintro actual ⟨meaning, allGrowth, bodyGrowth, binds⟩
  have known : RecipeConsumption.WellFormed (nativeRuleMapMeaning input.fields) (consumptionState actual.2.consumed) := by
    rw [meaning.2.1]
    exact RecipeRuleAdmission.field_ref_well_formed _ _ _ domain.known
  exact ⟨meaning, rule_state_transfer input actual.2 domain meaning.2.2.1 meaning.2.2.2 known, binds⟩

@[step] theorem native_form_field_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (name : String) (nameFits : TextFits name)
    (fieldFits : ∀ entry ∈ input.fields.entries.val, TextFits entry.1) :
    AuthsNativeRecipe.recipe.validate.Rules.form_field input (nativeTextView name nameFits) ⦃ actual =>
      actual = RecipeConsumption.fieldTest RecipeConsumption.formSchema (nativeRuleMapMeaning input.fields) name ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.Rules.form_field
  step with native_rule_map_lookup input.fields name nameFits fieldFits as ⟨selected, meaning⟩
  cases selected with
  | none => simp [RecipeConsumption.fieldTest, ← meaning]
  | some schema =>
      cases schema <;> simp [RecipeConsumption.fieldTest, ← meaning, nativeScalarMeaning,
        RecipeConsumption.formSchema,
        AuthsNativeRecipe.auths_gateway_kernel.scalars.ScalarSchema.Insts.Auths_gatewayRecipeFieldSchemaRuntime.is_form_scalar,
        AuthsNativeRecipe.auths_gateway_kernel.scalars.form_schema_allowed]

end Auths.Product.NativeCompiler.Refinement
