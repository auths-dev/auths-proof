import Auths.Product.NativeCompilerPlans
import Auths.Product.RecipePlanProperties

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement

/-- A successful actual full-plan caller earns the complete original body
compilation, checked write meaning and exact original schema pairs. The
remaining read bundle is tied to that same compiled write and name layout. -/
theorem native_plan_bundle_has_original_components (checked : NativeCheckedSource) (meaning : TemplateAst.Body)
    (original : BodySourceMeaning checked.source.write.body meaning) (bounded : PlanInputFits checked) :
    AuthsNativeRecipe.recipe.lower.plans checked ⦃ actual => ∀ output, actual = .Ok output →
      ∃ body compiled,
        RecipePlanModel.namedBody planErrors meaning (planSource checked.source meaning).echo = .ok body ∧
        RequestCompiler.compile (nativeFieldsMeaning checked.field_specs)
          (RecipePlanModel.writeSource (planSource checked.source meaning) (textBytes checked.parsed_host) body) = .ok compiled ∧
        RequestCompiler.CompilationMeaning (nativeFieldsMeaning checked.field_specs)
          (RecipePlanModel.writeSource (planSource checked.source meaning) (textBytes checked.parsed_host) body) compiled ∧
        RecipePlanModel.remainingPlans planErrors (nativeFieldsMeaning checked.field_specs)
          (planSource checked.source meaning) compiled = .ok (nativePlans output) ∧
        nativeFieldsMeaning output.field_schemas = nativeFieldsMeaning checked.field_specs ∧
        nativeWritePlan output.write = compiled.plan ⦄ := by
  apply spec_mono (native_plans_exact checked meaning original bounded)
  intro actual exact output accepted
  rw [accepted] at exact
  simpa [nativePlans, planSource] using RecipePlanModel.compile_success_components planErrors
    (nativeFieldsMeaning checked.field_specs) (textBytes checked.parsed_host)
    (planSource checked.source meaning) (nativePlans output)
    (by simpa only [nativeRecipeResult] using exact.symm)

end Auths.Product.NativeCompiler.Refinement
