import Auths.Product.NativeCompilerIdempotencyAdmission
import Auths.Product.NativeCompilerBodyAdmission
import Auths.Product.NativeCompilerRelativeAdmission

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def WriteGroupFits (source : NativeRecipeSource) : Prop :=
  (∀ segment ∈ source.write.path.val, RulePathFits segment) ∧
    BodyBounds source.write.body ∧
    (∀ current, source.write.idempotency = some current → IdempotencyFits current)

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 22000000
set_option maxRecDepth 4096

/-- Complete actual first validation group. The path earns the body input
state; the body earns the idempotency stage. Every stage reads the same original
field map/source, and first refusal retains the actual consumed prefix. Helper
successes, accepted source and expected plans are not theorem premises. -/
@[step] theorem native_write_group_admission_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : NativeRecipeSource) (model : TemplateAst.Body)
    (original : BodySourceMeaning source.write.body model) (fits : WriteGroupFits source)
    (domain : RuleStateDomain input) :
    AuthsNativeRecipe.recipe.validate.validate_write_rules input source ⦃ actual =>
      ClaimMeaning input (RecipeRuleAdmission.writeRules (nativeRuleMapMeaning input.fields)
        (ruleSource source model) (consumptionState input.consumed)) actual ∧
      RuleStateDomain actual.2 ∧ actual.2.consumed.binds = input.consumed.binds ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.validate_write_rules
  step with native_path_on_rule_domain input (AuthsNativeRecipe.alloc.vec.Vec.deref source.write.path)
    .Write fits.1 domain as ⟨walked, pathMeaning, pathDomain, pathBody, pathBinds⟩
  let pathModel := RecipeRuleAdmission.path (nativeRuleMapMeaning input.fields) .write
    (source.write.path.val.map ruleSegment) (consumptionState input.consumed)
  have pathFields : walked.2.fields = input.fields := pathMeaning.2.2.1
  have pathState : consumptionState walked.2.consumed = pathModel.2 := pathMeaning.2.1
  cases pathVerdict : pathModel.1 with
  | error error =>
      have refused : walked.1 = .Err (consumptionError error) := by
        simpa [pathModel, rulePathRole, pathVerdict, consumptionVerdict] using pathMeaning.1
      simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, ClaimMeaning,
        RecipeRuleAdmission.writeRules, ruleSource, RecipeRuleAdmission.andThen, ← pathModel,
        pathVerdict, pathState, pathFields, pathDomain, pathDomain.ordered,
        pathBinds, consumptionVerdict]
  | ok unit =>
      cases unit
      have pathAccepted : walked.1 = .Ok () := by
        simpa [pathModel, rulePathRole, pathVerdict, consumptionVerdict] using pathMeaning.1
      simp only [pathAccepted, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      step with native_body_admission_exact walked.2 source.write.body model fits.2.1 original pathDomain
        as ⟨rendered, bodyMeaning, bodyDomain, bodyBinds⟩
      let bodyModel := RecipeRuleAdmission.body (nativeRuleMapMeaning input.fields) model pathModel.2
      have bodyExact : ClaimMeaning walked.2 bodyModel rendered := by
        simpa [bodyModel, pathFields, pathState] using bodyMeaning
      have bodyFields : rendered.2.fields = input.fields := bodyExact.2.2.1.trans pathFields
      have bodyState : consumptionState rendered.2.consumed = bodyModel.2 := bodyExact.2.1
      have binds : rendered.2.consumed.binds = input.consumed.binds := bodyBinds.trans pathBinds
      cases bodyVerdict : bodyModel.1 with
      | error error =>
          have refused : rendered.1 = .Err (consumptionError error) := by
            simpa [bodyVerdict, consumptionVerdict] using bodyExact.1
          simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame, core.convert.FromSame.from, ClaimMeaning,
            RecipeRuleAdmission.writeRules, ruleSource, RecipeRuleAdmission.andThen, ← pathModel,
            pathVerdict, ← bodyModel, bodyVerdict, bodyState, bodyFields,
            bodyDomain, bodyDomain.ordered, binds, consumptionVerdict]
      | ok unit =>
          cases unit
          have bodyAccepted : rendered.1 = .Ok () := by simpa [bodyVerdict, consumptionVerdict] using bodyExact.1
          simp only [bodyAccepted, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
          cases idempotencyAt : source.write.idempotency with
          | none =>
              simp [RecipeRuleAdmission.writeRules, ruleSource, RecipeRuleAdmission.andThen, ← pathModel,
                pathVerdict, ← bodyModel, bodyVerdict, idempotencyAt,
                RecipeRuleAdmission.accepted, ClaimMeaning, consumptionVerdict,
                bodyState, bodyFields, bodyDomain, bodyDomain.ordered, binds]
          | some current =>
              step with native_idempotency_admission_exact current (fits.2.2 current idempotencyAt)
                source.write.body model fits.2.1 original as ⟨verdict, exactVerdict⟩
              cases outcome : RecipeRuleAdmission.idempotency (planIdempotency current) model with
              | error error =>
                  have refused : verdict = .Err (consumptionError error) := by simpa [outcome, consumptionVerdict] using exactVerdict
                  simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
                    core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                    core.convert.FromSame, core.convert.FromSame.from, ClaimMeaning,
                    RecipeRuleAdmission.writeRules, ruleSource, RecipeRuleAdmission.andThen,
                    ← pathModel, pathVerdict, ← bodyModel, bodyVerdict, idempotencyAt,
                    outcome, RecipeRuleAdmission.applyPure, bodyState, bodyFields,
                    bodyDomain, bodyDomain.ordered, binds, consumptionVerdict]
              | ok unit =>
                  cases unit
                  have admitted : verdict = .Ok () := by simpa [outcome, consumptionVerdict] using exactVerdict
                  simp [admitted, core.result.Result.Insts.CoreOpsTry.branch, ClaimMeaning,
                    RecipeRuleAdmission.writeRules, ruleSource, RecipeRuleAdmission.andThen,
                    ← pathModel, pathVerdict, ← bodyModel, bodyVerdict, idempotencyAt,
                    outcome, RecipeRuleAdmission.applyPure, bodyState, bodyFields,
                    bodyDomain, bodyDomain.ordered, binds, consumptionVerdict]

theorem native_write_group_storage (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : NativeRecipeSource) (model : TemplateAst.Body)
    (original : BodySourceMeaning source.write.body model) (fits : WriteGroupFits source)
    (domain : RuleStateDomain input) :
    AuthsNativeRecipe.recipe.validate.validate_write_rules input source ⦃ actual =>
      actual.2.fields = input.fields ∧ actual.2.consumed.binds = input.consumed.binds ∧
      actual.2.consumed.all.elements.val.length ≤ 32 ∧ actual.2.consumed.body.elements.val.length ≤ 32 ∧
      actual.2.consumed.binds.elements.val.length ≤ 32 ⦄ := by
  apply spec_mono (native_write_group_admission_exact input source model original fits domain)
  rintro actual ⟨meaning, nextDomain, binds⟩
  exact ⟨meaning.2.2.1, binds, rule_state_storage actual.2 nextDomain⟩

end Auths.Product.NativeCompiler.Refinement
