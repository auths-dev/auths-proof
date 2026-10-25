import Auths.Product.NativeCompilerGuardPaths
import Auths.Product.NativeCompilerProbeLiteral

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def ruleGuardProbe (source : AuthsNativeRecipe.recipe.source.ProbeSource) :
    RecipeCredentialAdmission.Probe := {
  path := planPath source.path
  pointer := textBytes source.json_pointer
  maximumResponseBytes := source.maximum_response_bytes.val
  equals := ruleProbeLiteral source.equals
}

def ruleGuardAccount (source : AuthsNativeRecipe.recipe.source.AccountReadSource) :
    RecipeCredentialAdmission.Read :=
  ⟨planPath source.path, textBytes source.json_pointer, source.maximum_response_bytes.val⟩

def GuardProbeFits (source : AuthsNativeRecipe.recipe.source.ProbeSource) : Prop :=
  (∀ segment ∈ source.path.val, GuardPathFits segment) ∧
    TextFits source.json_pointer ∧ ProbeLiteralFits source.equals

def GuardAccountFits (source : AuthsNativeRecipe.recipe.source.AccountReadSource) : Prop :=
  (∀ segment ∈ source.path.val, GuardPathFits segment) ∧ TextFits source.json_pointer

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel RecipeCredentialAdmission
set_option maxHeartbeats 18000000
set_option maxRecDepth 4096

theorem original_guard_path_ok (values : NativeVec String) (expected : Except Unit FixedPath)
    (same : guardPathBytes (.Ok values) = guardPathVerdict expected) :
    expected = .ok (values.val.map textBytes) := by
  cases expected <;> simp_all [guardPathBytes, guardPathVerdict]

theorem original_guard_path_error (error : AuthsNativeRecipe.recipe.GatewayRecipeError)
    (expected : Except Unit FixedPath)
    (same : guardPathBytes (.Err error) = guardPathVerdict expected) :
    expected = .error () ∧ error = .InvalidCredentialGuard := by
  cases expected <;> simp_all [guardPathBytes, guardPathVerdict]

/-- The actual fixed path result supplies the returned reservation path. The
remaining checks use the original pointer and read limit, without an admitted
read or a selected response being supplied. -/
@[step] theorem native_guard_account_read_exact
    (source : AuthsNativeRecipe.recipe.source.AccountReadSource) (fits : GuardAccountFits source) :
    AuthsNativeRecipe.recipe.validate.validate_account_read source ⦃ actual =>
      guardPathBytes actual = guardPathVerdict (accountReadResult (ruleGuardAccount source)) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.validate_account_read
  step with native_guard_fixed_path_exact (AuthsNativeRecipe.alloc.vec.Vec.deref source.path) fits.1
    as ⟨path, pathMeaning⟩
  cases path with
  | Err error =>
      obtain ⟨refused, errorValue⟩ := original_guard_path_error error _ pathMeaning
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, ruleGuardAccount,
        accountReadResult, planPath, native_deref_contents, refused, errorValue,
        guardPathBytes, guardPathVerdict]
  | Ok values =>
      have selected := original_guard_path_ok values _ pathMeaning
      simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      step with native_deref_view_exact source.json_pointer fits.2 as ⟨pointer, pointerMeaning⟩
      subst pointer
      step with native_response_pointer_exact (nativeTextView source.json_pointer fits.2)
        as ⟨pointerValid, pointerValidity⟩
      have pointerOriginal : pointerValid = decide (RecipeAdmissionAtoms.ResponsePointer (textBytes source.json_pointer)) := by
        simpa [native_text_view_bytes] using pointerValidity
      cases pointerValid with
      | false =>
          simp [accountReadResult, ruleGuardAccount, planPath, native_deref_contents,
            selected, ← pointerOriginal, guardPathBytes, guardPathVerdict]
      | true =>
          simp only [Bool.true_eq_true, ↓reduceIte]
          step with native_read_bound_exact source.maximum_response_bytes as ⟨bounded, boundMeaning⟩
          cases bounded <;> simp [accountReadResult, ruleGuardAccount, planPath,
            native_deref_contents, selected, ← pointerOriginal, ← boundMeaning,
            guardPathBytes, guardPathVerdict]

/-- The actual probe checks fixed path, original pointer, original literal,
then response limit. Refusal does not turn the fixed-path output into a fresh
permission, and success returns exactly that original path. -/
@[step] theorem native_guard_probe_exact
    (source : AuthsNativeRecipe.recipe.source.ProbeSource) (fits : GuardProbeFits source) :
    AuthsNativeRecipe.recipe.validate.validate_probe source ⦃ actual =>
      guardPathBytes actual = guardPathVerdict (probeResult (ruleGuardProbe source)) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.validate_probe
  step with native_guard_fixed_path_exact (AuthsNativeRecipe.alloc.vec.Vec.deref source.path) fits.1
    as ⟨path, pathMeaning⟩
  cases path with
  | Err error =>
      obtain ⟨refused, errorValue⟩ := original_guard_path_error error _ pathMeaning
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, ruleGuardProbe,
        probeResult, planPath, native_deref_contents, refused, errorValue,
        guardPathBytes, guardPathVerdict]
  | Ok values =>
      have selected := original_guard_path_ok values _ pathMeaning
      simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      step with native_deref_view_exact source.json_pointer fits.2.1 as ⟨pointer, pointerMeaning⟩
      subst pointer
      step with native_response_pointer_exact (nativeTextView source.json_pointer fits.2.1)
        as ⟨pointerValid, pointerValidity⟩
      have pointerOriginal : pointerValid = decide (RecipeAdmissionAtoms.ResponsePointer (textBytes source.json_pointer)) := by
        simpa [native_text_view_bytes] using pointerValidity
      cases pointerValid with
      | false =>
          simp [probeResult, ruleGuardProbe, planPath, native_deref_contents, selected,
            ← pointerOriginal, guardPathBytes, guardPathVerdict]
      | true =>
          simp only [Bool.true_eq_true, ↓reduceIte]
          step with native_probe_literal_exact source.equals fits.2.2 as ⟨literalValid, literalValidity⟩
          cases literalValid with
          | false =>
              simp [probeResult, ruleGuardProbe, planPath, native_deref_contents,
                selected, ← pointerOriginal, ← literalValidity, guardPathBytes, guardPathVerdict]
          | true =>
              simp only [Bool.true_eq_true, ↓reduceIte]
              step with native_read_bound_exact source.maximum_response_bytes as ⟨bounded, boundMeaning⟩
              cases bounded <;> simp [probeResult, ruleGuardProbe, planPath,
                native_deref_contents, selected, ← pointerOriginal, ← literalValidity,
                ← boundMeaning, guardPathBytes, guardPathVerdict]

theorem native_guard_account_success
    (source : AuthsNativeRecipe.recipe.source.AccountReadSource) (fits : GuardAccountFits source) :
    AuthsNativeRecipe.recipe.validate.validate_account_read source ⦃ actual =>
      ∀ values, actual = .Ok values → ReadAdmitted (ruleGuardAccount source) ∧
        fixedValues (ruleGuardAccount source).path = some (values.val.map textBytes) ⦄ := by
  apply spec_mono (native_guard_account_read_exact source fits)
  intro actual meaning values accepted
  rw [accepted] at meaning
  exact (account_read_result_ok _ _).mp (original_guard_path_ok values _ meaning)

theorem native_guard_probe_success
    (source : AuthsNativeRecipe.recipe.source.ProbeSource) (fits : GuardProbeFits source) :
    AuthsNativeRecipe.recipe.validate.validate_probe source ⦃ actual =>
      ∀ values, actual = .Ok values → ProbeAdmitted (ruleGuardProbe source) ∧
        fixedValues (ruleGuardProbe source).path = some (values.val.map textBytes) ⦄ := by
  apply spec_mono (native_guard_probe_exact source fits)
  intro actual meaning values accepted
  rw [accepted] at meaning
  exact (probe_result_ok _ _).mp (original_guard_path_ok values _ meaning)

end Auths.Product.NativeCompiler.Refinement
