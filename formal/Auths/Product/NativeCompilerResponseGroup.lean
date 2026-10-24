import Auths.Product.NativeCompilerRuleDomainTransfers
import Auths.Product.NativeCompilerEchoAdmission

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

structure ResponseGroupFits (source : NativeRecipeSource) : Prop where
  body : BodyBounds source.write.body
  observation : ∀ read, source.observation = some read → ObservationAdmissionFits read
  echo : ∀ echo, source.echo = some echo → EchoFits echo
  preEntry : ∀ read, source.pre_entry = some read → PreEntryAdmissionFits read

def nativeResponsePreEntryStage (input : AuthsNativeRecipe.recipe.validate.Rules) (source : NativeRecipeSource) :
    Result (core.result.Result Unit AuthsNativeRecipe.recipe.GatewayRecipeError ×
      AuthsNativeRecipe.recipe.validate.Rules) := do
  match source.pre_entry with
  | none => ok (.Ok (), input)
  | some current =>
      let (result, next) ← AuthsNativeRecipe.recipe.validate.Rules.pre_entry input current
      let flow ← core.result.Result.Insts.CoreOpsTry.branch result
      match flow with
      | .Continue _ => ok (.Ok (), next)
      | .Break residual =>
          let refused ← core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
            Unit (core.convert.FromSame AuthsNativeRecipe.recipe.GatewayRecipeError) residual
          ok (refused, next)

def nativeResponseEchoStage (input : AuthsNativeRecipe.recipe.validate.Rules) (source : NativeRecipeSource) :
    Result (core.result.Result Unit AuthsNativeRecipe.recipe.GatewayRecipeError ×
      AuthsNativeRecipe.recipe.validate.Rules) := do
  match source.echo with
  | none => nativeResponsePreEntryStage input source
  | some echo =>
      let observation ← core.option.Option.as_ref source.observation
      let checkedRead ← core.option.Option.ok_or observation .EchoWithoutObservation
      let readFlow ← core.result.Result.Insts.CoreOpsTry.branch checkedRead
      match readFlow with
      | .Break residual =>
          let refused ← core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
            Unit (core.convert.FromSame AuthsNativeRecipe.recipe.GatewayRecipeError) residual
          ok (refused, input)
      | .Continue read =>
          let checked ← AuthsNativeRecipe.recipe.validate.validate_echo echo source.write.body read
          let flow ← core.result.Result.Insts.CoreOpsTry.branch checked
          match flow with
          | .Continue _ => nativeResponsePreEntryStage input source
          | .Break residual =>
              let refused ← core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
                Unit (core.convert.FromSame AuthsNativeRecipe.recipe.GatewayRecipeError) residual
              ok (refused, input)

def responsePreEntryStageModel (fields : RecipeRuleAdmission.Fields) (source : NativeRecipeSource)
    (state : RecipeConsumption.State) : RecipeConsumption.Outcome :=
  match source.pre_entry with
  | none => RecipeRuleAdmission.accepted state
  | some read => RecipeRuleAdmission.preEntry fields (rulePreEntry read) state

def responseEchoStageModel (fields : RecipeRuleAdmission.Fields) (source : NativeRecipeSource)
    (body : TemplateAst.Body) (state : RecipeConsumption.State) : RecipeConsumption.Outcome :=
  let echoed := match source.echo with
    | none => RecipeRuleAdmission.accepted state
    | some echo => match source.observation with
      | none => RecipeRuleAdmission.refused .echoWithoutObservation state
      | some read => RecipeRuleAdmission.applyPure (RecipeRuleAdmission.echo (ruleEcho echo) body (ruleObservation read)) state
  RecipeRuleAdmission.andThen echoed fun next => responsePreEntryStageModel fields source next

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 26000000
set_option maxRecDepth 4096

private theorem native_response_pre_entry_stage_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : NativeRecipeSource) (fits : ResponseGroupFits source) (domain : RuleStateDomain input) :
    nativeResponsePreEntryStage input source ⦃ actual =>
      ClaimMeaning input (responsePreEntryStageModel (nativeRuleMapMeaning input.fields) source
        (consumptionState input.consumed)) actual ∧ RuleStateDomain actual.2 ∧
      actual.2.consumed.body = input.consumed.body ∧ actual.2.consumed.binds = input.consumed.binds ⦄ := by
  unfold nativeResponsePreEntryStage
  cases present : source.pre_entry with
  | none =>
      simp [responsePreEntryStageModel, present, ClaimMeaning, RecipeRuleAdmission.accepted,
        consumptionVerdict, domain, domain.ordered]
  | some read =>
      step with native_pre_entry_on_rule_domain input read (fits.preEntry read present) domain
        as ⟨checked, meaning, nextDomain, body, binds⟩
      cases result : checked.1 <;>
        simp_all [core.result.Result.Insts.CoreOpsTry.branch,
          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
          core.convert.FromSame, core.convert.FromSame.from, responsePreEntryStageModel, present, ClaimMeaning]

private theorem native_response_echo_stage_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : NativeRecipeSource) (model : TemplateAst.Body)
    (original : BodySourceMeaning source.write.body model) (fits : ResponseGroupFits source)
    (domain : RuleStateDomain input) :
    nativeResponseEchoStage input source ⦃ actual =>
      ClaimMeaning input (responseEchoStageModel (nativeRuleMapMeaning input.fields) source model
        (consumptionState input.consumed)) actual ∧ RuleStateDomain actual.2 ∧
      actual.2.consumed.body = input.consumed.body ∧ actual.2.consumed.binds = input.consumed.binds ⦄ := by
  unfold nativeResponseEchoStage
  cases echoAt : source.echo with
  | none =>
      apply spec_mono (native_response_pre_entry_stage_exact input source fits domain)
      intro actual meaning
      simpa [responseEchoStageModel, echoAt, RecipeRuleAdmission.andThen, RecipeRuleAdmission.accepted] using meaning
  | some echo =>
      simp only [core.option.Option.as_ref, bind_tc_ok]
      cases readAt : source.observation with
      | none =>
          simp [readAt, core.option.Option.ok_or, core.result.Result.Insts.CoreOpsTry.branch,
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame, core.convert.FromSame.from, responseEchoStageModel, echoAt,
            RecipeRuleAdmission.andThen, RecipeRuleAdmission.refused, ClaimMeaning,
            consumptionVerdict, consumptionError, domain, domain.ordered]
      | some read =>
          simp only [readAt, core.option.Option.ok_or, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
          step with native_echo_admission_exact echo (fits.echo echo echoAt) source.write.body model fits.body
            original read (fits.observation read readAt).2.1 as ⟨checked, echoMeaning⟩
          cases verdict : RecipeRuleAdmission.echo (ruleEcho echo) model (ruleObservation read) with
          | error error =>
              have refused : checked = .Err (consumptionError error) := by simpa [verdict, consumptionVerdict] using echoMeaning
              simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
                core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                core.convert.FromSame, core.convert.FromSame.from, responseEchoStageModel, echoAt, readAt,
                verdict, RecipeRuleAdmission.andThen, RecipeRuleAdmission.applyPure, ClaimMeaning,
                consumptionVerdict, domain, domain.ordered]
          | ok unit =>
              cases unit
              have accepted : checked = .Ok () := by simpa [verdict, consumptionVerdict] using echoMeaning
              simp only [accepted, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
              apply spec_mono (native_response_pre_entry_stage_exact input source fits domain)
              intro actual meaning
              simpa [responseEchoStageModel, echoAt, readAt, verdict, RecipeRuleAdmission.andThen,
                RecipeRuleAdmission.applyPure] using meaning

/-- Complete actual second group. The actual observation earns the next
ledger; echo uses the same original body and observation, then pre-entry earns
its own path/pointer checks. First refusal and every prior claim are retained.
The original field map and raw body/bind carriers are preserved throughout. -/
@[step] theorem native_response_group_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : NativeRecipeSource) (model : TemplateAst.Body)
    (original : BodySourceMeaning source.write.body model) (fits : ResponseGroupFits source)
    (domain : RuleStateDomain input) :
    AuthsNativeRecipe.recipe.validate.validate_response_rules input source ⦃ actual =>
      ClaimMeaning input (RecipeRuleAdmission.responseRules (nativeRuleMapMeaning input.fields)
        (ruleSource source model) (consumptionState input.consumed)) actual ∧ RuleStateDomain actual.2 ∧
      actual.2.consumed.body = input.consumed.body ∧ actual.2.consumed.binds = input.consumed.binds ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.validate_response_rules
  cases observationAt : source.observation with
  | none =>
      apply spec_mono (native_response_echo_stage_exact input source model original fits domain)
      intro actual meaning
      simpa [RecipeRuleAdmission.responseRules, ruleSource, observationAt, responseEchoStageModel,
        responsePreEntryStageModel, RecipeRuleAdmission.andThen, RecipeRuleAdmission.accepted,
        nativeResponseEchoStage, nativeResponsePreEntryStage, ruleEcho] using meaning
  | some read =>
      step with native_observation_on_rule_domain input read (fits.observation read observationAt) domain
        as ⟨observed, observationMeaning, observationDomain, bodyFrame, bindFrame⟩
      let observedModel := RecipeRuleAdmission.observation (nativeRuleMapMeaning input.fields)
        (ruleObservation read) (consumptionState input.consumed)
      have fields : observed.2.fields = input.fields := observationMeaning.2.2.1
      have state : consumptionState observed.2.consumed = observedModel.2 := observationMeaning.2.1
      cases verdict : observedModel.1 with
      | error error =>
          have refused : observed.1 = .Err (consumptionError error) := by
            simpa [observedModel, verdict, consumptionVerdict] using observationMeaning.1
          simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame, core.convert.FromSame.from, ClaimMeaning,
            RecipeRuleAdmission.responseRules, ruleSource, observationAt, ← observedModel,
            RecipeRuleAdmission.andThen, verdict, state, fields, observationDomain,
            observationDomain.ordered, bodyFrame, bindFrame, consumptionVerdict]
      | ok unit =>
          cases unit
          have accepted : observed.1 = .Ok () := by simpa [observedModel, verdict, consumptionVerdict] using observationMeaning.1
          simp only [accepted, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
          apply spec_mono (native_response_echo_stage_exact observed.2 source model original fits observationDomain)
          rintro actual ⟨meaning, nextDomain, body, binds⟩
          refine ⟨?_, nextDomain, body.trans bodyFrame, binds.trans bindFrame⟩
          simpa [ClaimMeaning, fields, state, responseEchoStageModel, responsePreEntryStageModel,
            RecipeRuleAdmission.responseRules, ruleSource, observationAt, ← observedModel,
            RecipeRuleAdmission.andThen, verdict, nativeResponseEchoStage, nativeResponsePreEntryStage,
            ruleEcho] using meaning

theorem native_response_group_storage (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : NativeRecipeSource) (model : TemplateAst.Body)
    (original : BodySourceMeaning source.write.body model) (fits : ResponseGroupFits source)
    (domain : RuleStateDomain input) :
    AuthsNativeRecipe.recipe.validate.validate_response_rules input source ⦃ actual =>
      actual.2.consumed.all.elements.val.length ≤ 32 ∧ actual.2.consumed.body.elements.val.length ≤ 32 ∧
        actual.2.consumed.binds.elements.val.length ≤ 32 ∧ actual.2.fields = input.fields ⦄ := by
  apply spec_mono (native_response_group_exact input source model original fits domain)
  rintro actual ⟨meaning, nextDomain, bodyFrame, bindFrame⟩
  obtain ⟨all, body, binds⟩ := rule_state_storage actual.2 nextDomain
  exact ⟨all, body, binds, meaning.2.2.1⟩

end Auths.Product.NativeCompiler.Refinement
