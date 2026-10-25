import Auths.Product.NativeCompilerRelativeBinds

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def BindConsumptionMeaning (before : AuthsNativeRecipe.recipe.validate.Rules)
    (sources : List RecipeRuleAdmission.Bind) (after : AuthsNativeRecipe.recipe.validate.Rules) : Prop :=
  after.fields = before.fields ∧
    consumptionState after.consumed = RecipeRuleAdmission.consumeBinds sources (consumptionState before.consumed) ∧
    RuleStateDomain after ∧ after.consumed.body = before.consumed.body

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 18000000
set_option maxRecDepth 4096

private theorem native_consume_bind_suffix (fields : NativeRuleMap)
    (consumed : AuthsNativeRecipe.recipe.validate.Consumption) (binds : Slice NativeBind) (position : Std.Usize)
    (positionBound : position.val ≤ binds.val.length) (domain : RuleStateDomain ⟨fields, consumed⟩)
    (fits : ∀ source ∈ binds.val, TextFits source.field)
    (known : ∀ source ∈ binds.val.drop position.val,
      RecipeConsumption.fieldTest RecipeConsumption.formSchema (nativeRuleMapMeaning fields) source.field = true) :
    AuthsNativeRecipe.recipe.validate.Rules.consume_binds_loop fields consumed binds position ⦃ actual =>
      BindConsumptionMeaning ⟨fields, consumed⟩ ((binds.val.drop position.val).map ruleBind) ⟨actual.1, actual.2⟩ ⦄ := by
  generalize remaining : binds.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing fields consumed position with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.Rules.consume_binds_loop
      by_cases inside : position.val < binds.val.length
      · have nativeInside : position < binds.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        step with Slice.index_usize_spec binds position inside as ⟨source, sourceAt⟩
        have sourceFits := fits source (by rw [sourceAt]; exact List.getElem_mem inside)
        have suffix : binds.val.drop position.val = source :: binds.val.drop (position.val + 1) := by
          simpa [sourceAt] using List.drop_eq_getElem_cons inside
        have originalField : source.field ∈ (nativeRuleMapMeaning fields).map Prod.fst :=
          RecipeConsumption.field_test_earns_presence _ _ _ (known source (by simp [suffix]))
        step with native_deref_view_exact source.field sourceFits as ⟨view, viewMeaning⟩
        subst view
        obtain ⟨allCount, bodyCount, bindCount⟩ := rule_state_storage ⟨fields, consumed⟩ domain
        step with native_consume_exact ⟨fields, consumed⟩ source.field sourceFits domain.ordered (by scalar_tac)
          as ⟨used, usedState, sameFields, usedOrder, allGrowth, sameBody, sameBinds⟩
        step as ⟨owned, ownership⟩
        subst owned
        have bindRoom : used.consumed.binds.elements.val.length < Usize.max := by rw [sameBinds]; scalar_tac
        step with native_name_set_insert used.consumed.binds source.field usedOrder.2.2 bindRoom
          as ⟨inserted, flag, bindMembers, bindOrder, bindSize, originals⟩
        let nextConsumption := { used.consumed with binds := inserted.2 }
        have nextState : consumptionState nextConsumption = RecipeConsumption.bind (consumptionState consumed) source.field := by
          have allMembers := congrArg RecipeConsumption.State.all usedState
          simp [nextConsumption, consumptionState, RecipeConsumption.bind,
            RecipeConsumption.consume, bindMembers, sameBody, allMembers]
        have nextDomain : RuleStateDomain ⟨used.fields, nextConsumption⟩ := by
          apply rule_state_transfer ⟨fields, consumed⟩ _ domain sameFields
          · exact ⟨usedOrder.1, usedOrder.2.1, bindOrder⟩
          · rw [nextState]
            exact RecipeConsumption.bind_well_formed _ _ _ domain.known originalField
        step as ⟨next, nextValue⟩
        have nextKnown : ∀ bind ∈ binds.val.drop next.val,
            RecipeConsumption.fieldTest RecipeConsumption.formSchema (nativeRuleMapMeaning used.fields) bind.field = true := by
          intro bind present
          rw [sameFields]
          exact known bind (by simp [suffix, nextValue, present])
        apply spec_mono (ih _ (by omega) used.fields nextConsumption next (by omega) nextDomain nextKnown rfl)
        intro actual meaning
        rcases meaning with ⟨finalFields, finalState, finalDomain, finalBody⟩
        refine ⟨finalFields.trans sameFields, ?_, finalDomain, ?_⟩
        · simpa [suffix, nextValue, RecipeRuleAdmission.consumeBinds, ruleBind, nextState] using finalState
        · exact finalBody.trans sameBody
      · have nativeEnded : ¬position < binds.len := by scalar_tac
        have ended : binds.val.length ≤ position.val := by omega
        simp [nativeEnded, BindConsumptionMeaning, List.drop_eq_nil_of_le ended,
          RecipeRuleAdmission.consumeBinds, domain]

/-- Complete actual bind consumption retains the same original field map and
body carrier. Every inserted name is earned from the original schema map;
the real relative-bind validator supplies this fact in the caller. Native
insertion room follows from the 32-field domain at each iteration. -/
@[step] theorem native_consume_binds_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (binds : Slice NativeBind) (domain : RuleStateDomain input)
    (fits : ∀ source ∈ binds.val, TextFits source.field)
    (known : ∀ source ∈ binds.val,
      RecipeConsumption.fieldTest RecipeConsumption.formSchema (nativeRuleMapMeaning input.fields) source.field = true) :
    AuthsNativeRecipe.recipe.validate.Rules.consume_binds input binds ⦃ actual =>
      BindConsumptionMeaning input (binds.val.map ruleBind) actual ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.Rules.consume_binds
  step with native_consume_bind_suffix input.fields input.consumed binds 0#usize (by simp) domain fits
    (by simpa using known) as ⟨actual, meaning⟩
  simpa using meaning

theorem native_consumed_binds_storage (input : AuthsNativeRecipe.recipe.validate.Rules)
    (binds : Slice NativeBind) (domain : RuleStateDomain input)
    (fits : ∀ source ∈ binds.val, TextFits source.field)
    (known : ∀ source ∈ binds.val,
      RecipeConsumption.fieldTest RecipeConsumption.formSchema (nativeRuleMapMeaning input.fields) source.field = true) :
    AuthsNativeRecipe.recipe.validate.Rules.consume_binds input binds ⦃ actual =>
      actual.consumed.all.elements.val.length ≤ 32 ∧ actual.consumed.body.elements.val.length ≤ 32 ∧
        actual.consumed.binds.elements.val.length ≤ 32 ⦄ := by
  apply spec_mono (native_consume_binds_exact input binds domain fits known)
  intro actual meaning
  exact rule_state_storage actual meaning.2.2.1

end Auths.Product.NativeCompiler.Refinement
