import Auths.Product.NativeCompilerGuardAdmission
import Auths.Product.NativeCompilerProviderHeaders

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

structure HeaderGuardGroupFits (source : NativeRecipeSource) : Prop where
  headers : ∀ headers, source.provider_headers = some headers →
    ∀ row ∈ headers.entries.val, TextFits row.1 ∧ TextFits row.2
  guard : ∀ guard, originalGuard source.credential = some guard → GuardAdmissionFits guard
  paths : GuardSourcePathsFit source

/-- The unchanged source suffix after optional provider-header admission. -/
def nativeGuardPolicyStage (source : NativeRecipeSource) :
    Result (core.result.Result Unit AuthsNativeRecipe.recipe.GatewayRecipeError) := do
  let guard ← AuthsNativeRecipe.recipe.source.CredentialSource.guard source.credential
  match guard with
  | none => ok (.Ok ())
  | some current =>
      let checked ← AuthsNativeRecipe.recipe.validate.validate_guard current source
      let flow ← core.result.Result.Insts.CoreOpsTry.branch checked
      match flow with
      | .Continue _ => ok (.Ok ())
      | .Break residual =>
          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
            Unit (core.convert.FromSame AuthsNativeRecipe.recipe.GatewayRecipeError) residual

def originalGuardPolicy (source : NativeRecipeSource) : Except RecipeConsumption.Error Unit :=
  match originalGuard source.credential with
  | none => .ok ()
  | some guard => RecipeCredentialAdmission.validateGuard .invalidCredentialGuard
      (ruleGuard guard) (ruleGuardSourcePaths source)

theorem original_header_guard_rule_model (source : NativeRecipeSource) (body : TemplateAst.Body) :
    RecipeRuleAdmission.headerGuardRules (ruleSource source body) = (do
      match source.provider_headers with
      | none => .ok ()
      | some headers =>
          if HeaderCompiler.VersionsValid (originalHeaders headers) then .ok () else .error .invalidProviderHeader
      originalGuardPolicy source) := by
  cases headerAt : source.provider_headers <;> cases guardAt : originalGuard source.credential <;>
    simp [RecipeRuleAdmission.headerGuardRules, ruleSource, headerAt, guardAt,
      originalGuardPolicy, original_guard_reservation_paths source body]

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel RecipeCredentialAdmission
set_option maxHeartbeats 24000000
set_option maxRecDepth 4096

private theorem native_guard_policy_stage_exact (source : NativeRecipeSource) (fits : HeaderGuardGroupFits source) :
    nativeGuardPolicyStage source ⦃ actual => actual = consumptionVerdict (originalGuardPolicy source) ⦄ := by
  unfold nativeGuardPolicyStage
  step with native_guard_choice_exact source.credential as ⟨guard, original⟩
  subst guard
  cases present : originalGuard source.credential with
  | none => simp [originalGuardPolicy, present, consumptionVerdict]
  | some guard =>
      step with native_guard_admission_exact guard source (fits.guard guard present) fits.paths
        as ⟨checked, meaning⟩
      by_cases admitted : GuardAdmitted (ruleGuard guard) (ruleGuardSourcePaths source)
      · have accepted : checked = .Ok () := by simpa [validateGuard, admitted, guardUnitVerdict] using meaning
        simp [accepted, core.result.Result.Insts.CoreOpsTry.branch, originalGuardPolicy,
          present, validateGuard, admitted, consumptionVerdict]
      · have refused : checked = .Err .InvalidCredentialGuard := by
          simpa [validateGuard, admitted, guardUnitVerdict] using meaning
        simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
          core.convert.FromSame, core.convert.FromSame.from, originalGuardPolicy,
          present, validateGuard, admitted, consumptionVerdict, consumptionError]

/-- The complete actual fourth group validates original provider headers,
then selects the original guard through the real credential getter and runs
the complete actual guard. Header refusal wins before any guard work. -/
@[step] theorem native_header_guard_group_exact (source : NativeRecipeSource) (body : TemplateAst.Body)
    (fits : HeaderGuardGroupFits source) :
    AuthsNativeRecipe.recipe.validate.validate_header_guard_rules source ⦃ actual =>
      actual = consumptionVerdict (RecipeRuleAdmission.headerGuardRules (ruleSource source body)) ⦄ := by
  rw [original_header_guard_rule_model]
  unfold AuthsNativeRecipe.recipe.validate.validate_header_guard_rules
  cases headerAt : source.provider_headers with
  | none =>
      apply spec_mono (native_guard_policy_stage_exact source fits)
      intro actual meaning
      simpa [headerAt, nativeGuardPolicyStage] using meaning
  | some headers =>
      step with native_provider_headers_admission_exact headers (fits.headers headers headerAt)
        as ⟨checked, headerMeaning⟩
      by_cases admitted : HeaderCompiler.VersionsValid (originalHeaders headers)
      · have accepted : checked = .Ok () := by simpa [admitted, consumptionVerdict] using headerMeaning
        simp only [accepted, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
        apply spec_mono (native_guard_policy_stage_exact source fits)
        intro actual meaning
        simpa [headerAt, admitted, nativeGuardPolicyStage] using meaning
      · have refused : checked = .Err .InvalidProviderHeader := by
          simpa [admitted, consumptionVerdict, consumptionError] using headerMeaning
        simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
          core.convert.FromSame, core.convert.FromSame.from, RecipeRuleAdmission.headerGuardRules,
          ruleSource, headerAt, admitted, consumptionVerdict, consumptionError]

theorem native_header_guard_group_useful (source : NativeRecipeSource) (body : TemplateAst.Body)
    (fits : HeaderGuardGroupFits source)
    (admitted : RecipeRuleAdmission.headerGuardRules (ruleSource source body) = .ok ()) :
    AuthsNativeRecipe.recipe.validate.validate_header_guard_rules source ⦃ actual => actual = .Ok () ⦄ := by
  apply spec_mono (native_header_guard_group_exact source body fits)
  intro actual meaning
  simpa [admitted, consumptionVerdict] using meaning

end Auths.Product.NativeCompiler.Refinement
