import Auths.Product.NativeCompilerRuleDomainTransfers

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

structure FactGroupFits (source : NativeRecipeSource) : Prop where
  relative : ∀ ceiling, source.relative_ceiling = some ceiling → RelativeFits ceiling
  preconditions : ∀ current, source.preconditions = some current → PreconditionsAdmissionFits current

def nativeFactPreconditionStage (input : AuthsNativeRecipe.recipe.validate.Rules) (source : NativeRecipeSource) :
    Result (core.result.Result Unit AuthsNativeRecipe.recipe.GatewayRecipeError ×
      AuthsNativeRecipe.recipe.validate.Rules) := do
  match source.preconditions with
  | none => ok (.Ok (), input)
  | some current =>
      let observation ← core.option.Option.as_ref source.observation
      let (result, next) ← AuthsNativeRecipe.recipe.validate.Rules.preconditions input current observation
      let flow ← core.result.Result.Insts.CoreOpsTry.branch result
      match flow with
      | .Continue _ => ok (.Ok (), next)
      | .Break residual =>
          let refused ← core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
            Unit (core.convert.FromSame AuthsNativeRecipe.recipe.GatewayRecipeError) residual
          ok (refused, next)

def factPreconditionStageModel (fields : RecipeRuleAdmission.Fields) (source : NativeRecipeSource)
    (state : RecipeConsumption.State) : RecipeConsumption.Outcome :=
  match source.preconditions with
  | none => RecipeRuleAdmission.accepted state
  | some current => RecipeRuleAdmission.preconditions fields (rulePreconditions current)
      (source.observation.map ruleObservation) state

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 24000000
set_option maxRecDepth 4096

private theorem native_fact_precondition_stage_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : NativeRecipeSource) (fits : FactGroupFits source) (domain : RuleStateDomain input) :
    nativeFactPreconditionStage input source ⦃ actual =>
      ClaimMeaning input (factPreconditionStageModel (nativeRuleMapMeaning input.fields) source
        (consumptionState input.consumed)) actual ∧ RuleStateDomain actual.2 ⦄ := by
  unfold nativeFactPreconditionStage
  cases present : source.preconditions with
  | none =>
      simp [factPreconditionStageModel, present, ClaimMeaning, RecipeRuleAdmission.accepted,
        consumptionVerdict, domain, domain.ordered]
  | some current =>
      simp only [core.option.Option.as_ref, bind_tc_ok]
      step with native_preconditions_on_rule_domain input current source.observation
        (fits.preconditions current present) domain as ⟨checked, meaning, nextDomain⟩
      cases result : checked.1 <;>
        simp_all [core.result.Result.Insts.CoreOpsTry.branch,
          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
          core.convert.FromSame, core.convert.FromSame.from, factPreconditionStageModel,
          present, ClaimMeaning]

/-- Complete actual third rule group. Relative-ceiling/bind/path validation
earns the precondition input state. The real precondition caller then checks
the original observation, subject and verified names. A later refusal retains
all claims made by earlier source stages, and the original field map remains. -/
@[step] theorem native_fact_group_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : NativeRecipeSource) (model : TemplateAst.Body) (fits : FactGroupFits source)
    (domain : RuleStateDomain input) :
    AuthsNativeRecipe.recipe.validate.validate_fact_rules input source ⦃ actual =>
      ClaimMeaning input (RecipeRuleAdmission.factRules (nativeRuleMapMeaning input.fields)
        (ruleSource source model) (consumptionState input.consumed)) actual ∧ RuleStateDomain actual.2 ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.validate_fact_rules
  cases relativeAt : source.relative_ceiling with
  | none =>
      apply spec_mono (native_fact_precondition_stage_exact input source fits domain)
      intro actual meaning
      simpa [RecipeRuleAdmission.factRules, ruleSource, relativeAt, factPreconditionStageModel,
        RecipeRuleAdmission.andThen, RecipeRuleAdmission.accepted, nativeFactPreconditionStage] using meaning
  | some ceiling =>
      step with native_relative_ceiling_exact input ceiling (fits.relative ceiling relativeAt) domain
        as ⟨checked, relativeMeaning, relativeDomain, bodyFrame⟩
      let relativeModel := RecipeRuleAdmission.relativeCeiling (nativeRuleMapMeaning input.fields)
        (ruleRelativeCeiling ceiling) (consumptionState input.consumed)
      have fields : checked.2.fields = input.fields := relativeMeaning.2.2.1
      have state : consumptionState checked.2.consumed = relativeModel.2 := relativeMeaning.2.1
      cases verdict : relativeModel.1 with
      | error error =>
          have refused : checked.1 = .Err (consumptionError error) := by
            simpa [relativeModel, verdict, consumptionVerdict] using relativeMeaning.1
          simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame, core.convert.FromSame.from, ClaimMeaning,
            RecipeRuleAdmission.factRules, ruleSource, relativeAt, ← relativeModel,
            RecipeRuleAdmission.andThen, verdict, state, fields, relativeDomain,
            relativeDomain.ordered, consumptionVerdict]
      | ok unit =>
          cases unit
          have accepted : checked.1 = .Ok () := by simpa [relativeModel, verdict, consumptionVerdict] using relativeMeaning.1
          simp only [accepted, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
          apply spec_mono (native_fact_precondition_stage_exact checked.2 source fits relativeDomain)
          rintro actual ⟨meaning, nextDomain⟩
          refine ⟨?_, nextDomain⟩
          simpa [ClaimMeaning, factPreconditionStageModel, fields, state,
            RecipeRuleAdmission.factRules, ruleSource, relativeAt, ← relativeModel,
            RecipeRuleAdmission.andThen, verdict, nativeFactPreconditionStage] using meaning

theorem native_fact_group_storage (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : NativeRecipeSource) (model : TemplateAst.Body) (fits : FactGroupFits source)
    (domain : RuleStateDomain input) :
    AuthsNativeRecipe.recipe.validate.validate_fact_rules input source ⦃ actual =>
      actual.2.consumed.all.elements.val.length ≤ 32 ∧ actual.2.consumed.body.elements.val.length ≤ 32 ∧
        actual.2.consumed.binds.elements.val.length ≤ 32 ∧ actual.2.fields = input.fields ⦄ := by
  apply spec_mono (native_fact_group_exact input source model fits domain)
  rintro actual ⟨meaning, nextDomain⟩
  obtain ⟨all, body, binds⟩ := rule_state_storage actual.2 nextDomain
  exact ⟨all, body, binds, meaning.2.2.1⟩

end Auths.Product.NativeCompiler.Refinement
