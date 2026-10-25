import Auths.Product.NativeCompilerOutcome
import qualification.aeneas.generated.native_recipe.Funs

/-!
Structural provenance of the actual shipping compile caller. Successful return
is the observation being analysed, not an assumed helper verdict. The theorem
earns every child result from that return and preserves every returned column.
It does not establish source admission, hash correctness, termination, resource
bounds, or the foreign canonicalization relation; those require the child
refinements and explicit foreign contracts.
-/
open Aeneas Aeneas.Std Result

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.Outcome

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

/-- A successful complete native compile returns exactly the original source,
its actual staged digest/plans, and the namespace from that same checked record.
No validation, digest or lowering success is a premise. All are conclusions
about the successful complete caller, including its original error boundaries. -/
theorem native_compile_success_keeps_all_stage_results
    (source : AuthsNativeRecipe.recipe.source.RecipeSource)
    (lock : AuthsNativeRecipe.recipe.ProfileLockFile)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (output : AuthsNativeRecipe.recipe.CompiledRecipe)
    (completed : AuthsNativeRecipe.recipe.compile_decoded source lock canonical = ok (.Ok output)) :
    ∃ checked : AuthsNativeRecipe.recipe.validate.ValidatedSource,
      AuthsNativeRecipe.recipe.validate.validate_source source lock canonical = ok (.Ok checked) ∧
      AuthsNativeRecipe.recipe.validate.ValidatedSource.digest checked = ok (.Ok output.digest) ∧
      AuthsNativeRecipe.recipe.lower.plans checked = ok (.Ok output.plans) ∧
      output.source = source ∧ output.«namespace» = checked.«namespace» := by
  unfold AuthsNativeRecipe.recipe.compile_decoded at completed
  obtain ⟨admitted, admissionStep, afterAdmission⟩ := successful_bind _ _ (.Ok output) completed
  cases admitted with
  | Err error =>
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from] at afterAdmission
  | Ok checked =>
      simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok] at afterAdmission
      obtain ⟨digested, digestStep, afterDigest⟩ := successful_bind _ _ (.Ok output) afterAdmission
      cases digested with
      | Err error =>
          simp [core.result.Result.Insts.CoreOpsTry.branch,
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame, core.convert.FromSame.from] at afterDigest
      | Ok digest =>
          simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok] at afterDigest
          obtain ⟨lowered, planStep, afterPlans⟩ := successful_bind _ _ (.Ok output) afterDigest
          cases lowered with
          | Err error =>
              simp [core.result.Result.Insts.CoreOpsTry.branch,
                core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                core.convert.FromSame, core.convert.FromSame.from] at afterPlans
          | Ok plans =>
              simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok] at afterPlans
              have built : ({ source := source, «namespace» := checked.«namespace»,
                  digest := digest, plans := plans } : AuthsNativeRecipe.recipe.CompiledRecipe) = output := by
                simpa [AuthsNativeRecipe.recipe.validate.ValidatedSource.into_namespace] using afterPlans
              cases built
              exact ⟨checked, admissionStep, digestStep, planStep, rfl, rfl⟩

end Auths.Product.NativeCompiler.Refinement
