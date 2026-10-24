import Auths.Product.RecipeDeniedReadSteps
import Auths.Product.NativeCompilerGuardPathIdentity

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def guardUnitVerdict (result : Except Unit Unit) :
    core.result.Result Unit AuthsNativeRecipe.recipe.GatewayRecipeError :=
  match result with
  | .ok _ => .Ok ()
  | .error _ => .Err .InvalidCredentialGuard

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel RecipeCredentialAdmission
set_option maxHeartbeats 20000000
set_option maxRecDepth 4096

/-- One actual denied-read step keeps all earlier paths at every refusal,
and appends precisely the original checked path only after method, status,
seen and reserved checks succeed. There is no supplied admitted/read flag. -/
@[step] theorem native_guard_denied_read_step_exact (read : NativeDeniedSource)
    (reserved : Slice (NativeVec String)) (seen : NativeVec (NativeVec String))
    (fits : GuardDeniedReadFits read) (reservedFits : FixedPathColumnFits reserved.val)
    (seenFits : FixedPathColumnFits seen.val) (room : seen.val.length < Usize.max) :
    AuthsNativeRecipe.recipe.validate.validate_denied_read read reserved seen ⦃ actual =>
      actual.1 = guardUnitVerdict (deniedReadStep (ruleGuardDeniedRead read)
        (fixedPathColumn reserved.val) (fixedPathColumn seen.val)).1 ∧
      fixedPathColumn actual.2.val = (deniedReadStep (ruleGuardDeniedRead read)
        (fixedPathColumn reserved.val) (fixedPathColumn seen.val)).2 ∧
      actual.2.val.length ≤ seen.val.length + 1 ∧ FixedPathColumnFits actual.2.val ∧
      (actual.1 = .Err .InvalidCredentialGuard → actual.2 = seen) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.validate_denied_read
  step with native_guard_fixed_path_exact (AuthsNativeRecipe.alloc.vec.Vec.deref read.path) fits.2
    as ⟨checked, checkMeaning⟩
  cases checked with
  | Err error =>
      have refused : fixedPathResult (planPath read.path) = .error () ∧ error = .InvalidCredentialGuard := by
        cases result : fixedPathResult (planPath read.path) <;>
          simp_all [guardPathBytes, guardPathVerdict, planPath, native_deref_contents]
      simp [deniedReadStep, ruleGuardDeniedRead, refused.1, refused.2, guardUnitVerdict,
        seenFits, Nat.le_add_right]
  | Ok path =>
      have selected : fixedPathResult (planPath read.path) = .ok (path.val.map textBytes) := by
        cases result : fixedPathResult (planPath read.path) <;>
          simp_all [guardPathBytes, guardPathVerdict, planPath, native_deref_contents]
      have pathFits := admitted_original_fixed_texts_fit _ path selected
      step with native_guard_denied_path_allowed_exact read (AuthsNativeRecipe.alloc.vec.Vec.deref path)
        (AuthsNativeRecipe.alloc.vec.Vec.deref seen) reserved fits.1 pathFits seenFits reservedFits
        as ⟨allowed, allowance⟩
      cases allowed with
      | false =>
          simp [deniedReadStep, ruleGuardDeniedRead, selected, ← allowance,
            native_deref_contents, guardUnitVerdict, seenFits, Nat.le_add_right]
      | true =>
          simp only [Bool.true_eq_true, ↓reduceIte]
          step with native_vector_clone_exact AuthsNativeRecipe.alloc.string.String.Insts.CoreCloneClone
            path (by intro value _; rfl) as ⟨copied, copyMeaning⟩
          subst copied
          step with native_push_exact seen path room as ⟨updated, appended⟩
          have updatedFits : FixedPathColumnFits updated.val := by
            intro value member
            rw [appended] at member
            rcases List.mem_append.mp member with earlier | current
            · exact seenFits value earlier
            · have same : value = path := List.mem_singleton.mp current
              simpa [same] using pathFits
          simp [deniedReadStep, ruleGuardDeniedRead, selected, ← allowance,
            native_deref_contents, guardUnitVerdict, fixedPathColumn, appended,
            List.map_append, updatedFits]

theorem native_guard_denied_read_success (read : NativeDeniedSource)
    (reserved : Slice (NativeVec String)) (seen : NativeVec (NativeVec String))
    (fits : GuardDeniedReadFits read) (reservedFits : FixedPathColumnFits reserved.val)
    (seenFits : FixedPathColumnFits seen.val) (room : seen.val.length < Usize.max) :
    AuthsNativeRecipe.recipe.validate.validate_denied_read read reserved seen ⦃ actual =>
      actual.1 = .Ok () → DeniedReadAdmitted (ruleGuardDeniedRead read) ∧
        ∃ path, fixedValues (ruleGuardDeniedRead read).path = some path ∧
          path ∉ fixedPathColumn seen.val ∧ path ∉ fixedPathColumn reserved.val ∧
          fixedPathColumn actual.2.val = fixedPathColumn seen.val ++ [path] ⦄ := by
  apply spec_mono (native_guard_denied_read_step_exact read reserved seen fits reservedFits seenFits room)
  intro actual meaning accepted
  have modelAccepted : (deniedReadStep (ruleGuardDeniedRead read)
      (fixedPathColumn reserved.val) (fixedPathColumn seen.val)).1 = .ok () := by
    cases result : (deniedReadStep (ruleGuardDeniedRead read)
      (fixedPathColumn reserved.val) (fixedPathColumn seen.val)).1 <;>
      simp_all [guardUnitVerdict]
  obtain ⟨admitted, path, copied, fresh, separate, appended⟩ := (denied_read_step_success _ _ _).mp modelAccepted
  exact ⟨admitted, path, copied, fresh, separate, meaning.2.1.trans appended⟩

end Auths.Product.NativeCompiler.Refinement
