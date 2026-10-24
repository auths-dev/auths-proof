import Auths.Product.NativeCompilerSourceRuleStages

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 28000000
set_option maxRecDepth 4096

private theorem native_source_bound_tail_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : NativeRecipeSource) (fields : NativeRuleMap) (model : TemplateAst.Body)
    (fits : SourceRulesFit source) (domain : RuleStateDomain input) (original : input.fields = fields) :
    nativeSourceBoundTail input source fields ⦃ actual =>
      actual = consumptionVerdict (RecipeRuleAdmission.sourceBoundTail (nativeRuleMapMeaning fields)
        (ruleSource source model) (consumptionState input.consumed)).1 ⦄ := by
  unfold nativeSourceBoundTail
  step with native_bound_group_on_rule_domain input source model fits.scope fits.bounds domain
    as ⟨checked, boundMeaning, boundDomain, bodyFrame, bindFrame⟩
  let boundModel := RecipeRuleAdmission.boundRules (nativeRuleMapMeaning fields)
    (ruleSource source model) (consumptionState input.consumed)
  have meaning : ClaimMeaning input boundModel checked := by simpa [boundModel, original] using boundMeaning
  have state : consumptionState checked.2.consumed = boundModel.2 := meaning.2.1
  cases verdict : boundModel.1 with
  | error error =>
      have refused : checked.1 = .Err (consumptionError error) := by simpa [verdict, consumptionVerdict] using meaning.1
      simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, RecipeRuleAdmission.sourceBoundTail,
        ← boundModel, verdict, RecipeRuleAdmission.andThen, consumptionVerdict]
  | ok unit =>
      cases unit
      have accepted : checked.1 = .Ok () := by simpa [verdict, consumptionVerdict] using meaning.1
      simp only [accepted, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      have names : ∀ entry ∈ fields.entries.val, TextFits entry.1 := by simpa [original] using domain.fieldNames
      step with native_all_fields_consumed_exact fields checked.2.consumed.all names as ⟨used, useMeaning⟩
      have originalUse : used = RecipeConsumption.allFieldsConsumed (nativeRuleMapMeaning fields) boundModel.2 := by
        simpa [← state, RecipeConsumption.allFieldsConsumed, consumptionState] using useMeaning
      cases used <;> simp [RecipeRuleAdmission.sourceBoundTail, ← boundModel, verdict,
        RecipeRuleAdmission.andThen, RecipeRuleAdmission.sourceFieldUse, ← originalUse,
        RecipeRuleAdmission.accepted, RecipeRuleAdmission.refused, consumptionVerdict, consumptionError]

private theorem native_source_header_tail_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : NativeRecipeSource) (fields : NativeRuleMap) (model : TemplateAst.Body)
    (fits : SourceRulesFit source) (domain : RuleStateDomain input) (original : input.fields = fields) :
    nativeSourceHeaderTail input source fields ⦃ actual =>
      actual = consumptionVerdict (RecipeRuleAdmission.sourceHeaderTail (nativeRuleMapMeaning fields)
        (ruleSource source model) (consumptionState input.consumed)).1 ⦄ := by
  unfold nativeSourceHeaderTail
  step with native_header_guard_group_exact source model fits.headers as ⟨checked, meaning⟩
  cases verdict : RecipeRuleAdmission.headerGuardRules (ruleSource source model) with
  | error error =>
      have refused : checked = .Err (consumptionError error) := by simpa [verdict, consumptionVerdict] using meaning
      simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, RecipeRuleAdmission.sourceHeaderTail,
        verdict, RecipeRuleAdmission.applyPure, RecipeRuleAdmission.andThen, consumptionVerdict]
  | ok unit =>
      cases unit
      have accepted : checked = .Ok () := by simpa [verdict, consumptionVerdict] using meaning
      simp only [accepted, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      apply spec_mono (native_source_bound_tail_exact input source fields model fits domain original)
      intro actual exact
      simpa [RecipeRuleAdmission.sourceHeaderTail, verdict, RecipeRuleAdmission.applyPure,
        RecipeRuleAdmission.andThen] using exact

private theorem native_source_fact_tail_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : NativeRecipeSource) (fields : NativeRuleMap) (model : TemplateAst.Body)
    (fits : SourceRulesFit source) (domain : RuleStateDomain input) (original : input.fields = fields) :
    nativeSourceFactTail input source fields ⦃ actual =>
      actual = consumptionVerdict (RecipeRuleAdmission.sourceFactTail (nativeRuleMapMeaning fields)
        (ruleSource source model) (consumptionState input.consumed)).1 ⦄ := by
  unfold nativeSourceFactTail
  step with native_fact_group_exact input source model fits.facts domain as ⟨checked, factMeaning, factDomain⟩
  let factModel := RecipeRuleAdmission.factRules (nativeRuleMapMeaning fields)
    (ruleSource source model) (consumptionState input.consumed)
  have meaning : ClaimMeaning input factModel checked := by simpa [factModel, original] using factMeaning
  have state : consumptionState checked.2.consumed = factModel.2 := meaning.2.1
  have fieldsKept : checked.2.fields = fields := meaning.2.2.1.trans original
  cases verdict : factModel.1 with
  | error error =>
      have refused : checked.1 = .Err (consumptionError error) := by simpa [verdict, consumptionVerdict] using meaning.1
      simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, RecipeRuleAdmission.sourceFactTail,
        ← factModel, verdict, RecipeRuleAdmission.andThen, consumptionVerdict]
  | ok unit =>
      cases unit
      have accepted : checked.1 = .Ok () := by simpa [verdict, consumptionVerdict] using meaning.1
      simp only [accepted, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      apply spec_mono (native_source_header_tail_exact checked.2 source fields model fits factDomain fieldsKept)
      intro actual exact
      simpa [state, RecipeRuleAdmission.sourceFactTail, ← factModel, verdict,
        RecipeRuleAdmission.andThen] using exact

private theorem native_source_response_tail_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : NativeRecipeSource) (fields : NativeRuleMap) (model : TemplateAst.Body)
    (bodyMeaning : BodySourceMeaning source.write.body model) (fits : SourceRulesFit source)
    (domain : RuleStateDomain input) (original : input.fields = fields) :
    nativeSourceResponseTail input source fields ⦃ actual =>
      actual = consumptionVerdict (RecipeRuleAdmission.sourceResponseTail (nativeRuleMapMeaning fields)
        (ruleSource source model) (consumptionState input.consumed)).1 ⦄ := by
  unfold nativeSourceResponseTail
  step with native_response_group_exact input source model bodyMeaning fits.response domain
    as ⟨checked, responseMeaning, responseDomain, bodyFrame, bindFrame⟩
  let responseModel := RecipeRuleAdmission.responseRules (nativeRuleMapMeaning fields)
    (ruleSource source model) (consumptionState input.consumed)
  have meaning : ClaimMeaning input responseModel checked := by simpa [responseModel, original] using responseMeaning
  have state : consumptionState checked.2.consumed = responseModel.2 := meaning.2.1
  have fieldsKept : checked.2.fields = fields := meaning.2.2.1.trans original
  cases verdict : responseModel.1 with
  | error error =>
      have refused : checked.1 = .Err (consumptionError error) := by simpa [verdict, consumptionVerdict] using meaning.1
      simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, RecipeRuleAdmission.sourceResponseTail,
        ← responseModel, verdict, RecipeRuleAdmission.andThen, consumptionVerdict]
  | ok unit =>
      cases unit
      have accepted : checked.1 = .Ok () := by simpa [verdict, consumptionVerdict] using meaning.1
      simp only [accepted, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      apply spec_mono (native_source_fact_tail_exact checked.2 source fields model fits responseDomain fieldsKept)
      intro actual exact
      simpa [state, RecipeRuleAdmission.sourceResponseTail, ← responseModel, verdict,
        RecipeRuleAdmission.andThen] using exact

private theorem native_source_all_stages_exact (source : NativeRecipeSource) (fields : NativeRuleMap)
    (model : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body model)
    (fits : SourceRulesFit source) (count : fields.entries.val.length ≤ 32)
    (names : ∀ entry ∈ fields.entries.val, TextFits entry.1) :
    nativeSourceAllStages source fields ⦃ actual =>
      actual = consumptionVerdict (RecipeRuleAdmission.validate (nativeRuleMapMeaning fields) (ruleSource source model)).1 ⦄ := by
  unfold nativeSourceAllStages
  step with native_consumption_default as ⟨consumed, empty, ordered⟩
  let initial : AuthsNativeRecipe.recipe.validate.Rules := ⟨fields, consumed⟩
  have domain : RuleStateDomain initial := by
    refine ⟨count, names, ordered, ?_⟩
    change RecipeConsumption.WellFormed (nativeRuleMapMeaning fields) (consumptionState consumed)
    rw [empty]
    exact RecipeConsumption.empty_well_formed _
  step with native_write_group_admission_exact initial source model bodyMeaning fits.write domain
    as ⟨checked, writeMeaning, writeDomain, bindsFrame⟩
  let writeModel := RecipeRuleAdmission.writeRules (nativeRuleMapMeaning fields)
    (ruleSource source model) RecipeConsumption.empty
  have meaning : ClaimMeaning initial writeModel checked := by simpa [initial, writeModel, empty] using writeMeaning
  have state : consumptionState checked.2.consumed = writeModel.2 := meaning.2.1
  have fieldsKept : checked.2.fields = fields := meaning.2.2.1
  cases verdict : writeModel.1 with
  | error error =>
      have refused : checked.1 = .Err (consumptionError error) := by simpa [verdict, consumptionVerdict] using meaning.1
      simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, RecipeRuleAdmission.validate,
        RecipeRuleAdmission.validate_from_original_stages, ← writeModel, verdict,
        RecipeRuleAdmission.andThen, consumptionVerdict]
  | ok unit =>
      cases unit
      have accepted : checked.1 = .Ok () := by simpa [verdict, consumptionVerdict] using meaning.1
      simp only [accepted, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      apply spec_mono (native_source_response_tail_exact checked.2 source fields model bodyMeaning fits writeDomain fieldsKept)
      intro actual exact
      simpa [state, RecipeRuleAdmission.validate, RecipeRuleAdmission.validate_from_original_stages,
        ← writeModel, verdict, RecipeRuleAdmission.andThen] using exact

/-- Complete actual source-rule validation from the real default ledger,
through all five actual groups and the final scan of the original field map.
Every group earns the next native domain. No child success or compiler result
is an input; count/name representation is for the constructor to earn. -/
@[step] theorem native_source_rules_admission_exact (source : NativeRecipeSource) (fields : NativeRuleMap)
    (model : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body model)
    (fits : SourceRulesFit source) (count : fields.entries.val.length ≤ 32)
    (names : ∀ entry ∈ fields.entries.val, TextFits entry.1) :
    AuthsNativeRecipe.recipe.validate.validate_source_rules source fields ⦃ actual =>
      actual = consumptionVerdict (RecipeRuleAdmission.validate (nativeRuleMapMeaning fields) (ruleSource source model)).1 ⦄ := by
  rw [native_source_rules_use_original_stages]
  exact native_source_all_stages_exact source fields model bodyMeaning fits count names

theorem native_source_rules_success (source : NativeRecipeSource) (fields : NativeRuleMap)
    (model : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body model)
    (fits : SourceRulesFit source) (count : fields.entries.val.length ≤ 32)
    (names : ∀ entry ∈ fields.entries.val, TextFits entry.1) :
    AuthsNativeRecipe.recipe.validate.validate_source_rules source fields ⦃ actual =>
      actual = .Ok () → (RecipeRuleAdmission.validate (nativeRuleMapMeaning fields) (ruleSource source model)).1 = .ok () ⦄ := by
  apply spec_mono (native_source_rules_admission_exact source fields model bodyMeaning fits count names)
  intro actual meaning accepted
  cases verdict : (RecipeRuleAdmission.validate (nativeRuleMapMeaning fields) (ruleSource source model)).1 <;>
    simp_all [consumptionVerdict]

theorem native_source_rules_useful (source : NativeRecipeSource) (fields : NativeRuleMap)
    (model : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body model)
    (fits : SourceRulesFit source) (count : fields.entries.val.length ≤ 32)
    (names : ∀ entry ∈ fields.entries.val, TextFits entry.1)
    (admitted : (RecipeRuleAdmission.validate (nativeRuleMapMeaning fields) (ruleSource source model)).1 = .ok ()) :
    AuthsNativeRecipe.recipe.validate.validate_source_rules source fields ⦃ actual => actual = .Ok () ⦄ := by
  apply spec_mono (native_source_rules_admission_exact source fields model bodyMeaning fits count names)
  intro actual meaning
  simpa [admitted, consumptionVerdict] using meaning

theorem native_source_rules_refusal (source : NativeRecipeSource) (fields : NativeRuleMap)
    (model : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body model)
    (fits : SourceRulesFit source) (count : fields.entries.val.length ≤ 32)
    (names : ∀ entry ∈ fields.entries.val, TextFits entry.1) (error : RecipeConsumption.Error)
    (refused : (RecipeRuleAdmission.validate (nativeRuleMapMeaning fields) (ruleSource source model)).1 = .error error) :
    AuthsNativeRecipe.recipe.validate.validate_source_rules source fields ⦃ actual => actual = .Err (consumptionError error) ⦄ := by
  apply spec_mono (native_source_rules_admission_exact source fields model bodyMeaning fits count names)
  intro actual meaning
  simpa [refused, consumptionVerdict] using meaning

end Auths.Product.NativeCompiler.Refinement
