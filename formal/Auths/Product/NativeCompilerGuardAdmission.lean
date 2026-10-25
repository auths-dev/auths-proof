import Auths.Product.RecipeGuardSequence
import Auths.Product.NativeCompilerGuardReservationDomain
import Auths.Product.NativeCompilerGuardPrefixes

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

structure GuardAdmissionFits (guard : NativeGuardSource) : Prop where
  prefixes : ∀ prefix ∈ guard.prefixes.val, TextFits prefix
  probe : ∀ probe, guard.probe = some probe → GuardProbeFits probe
  account : ∀ account, guard.account = some account → GuardAccountFits account
  denied : ∀ reads, guard.denied_reads = some reads → ∀ read ∈ reads.val, GuardDeniedReadFits read

/-- The actual guard suffix after account/probe reservations. It invokes the
unchanged source-reservation and denied-list caller when the option is present. -/
def guardDeniedTail (guard : NativeGuardSource) (source : NativeRecipeSource)
    (reserved : NativeVec (NativeVec String)) :
    Result (core.result.Result Unit AuthsNativeRecipe.recipe.GatewayRecipeError) :=
  match guard.denied_reads with
  | none => ok (.Ok ())
  | some reads => AuthsNativeRecipe.recipe.validate.validate_guard_denied
      (AuthsNativeRecipe.alloc.vec.Vec.deref reads) reserved source

/-- The actual account then denied-read suffix, expressed transparently so
both probe branches can use the same proven source term. -/
def guardAccountTail (guard : NativeGuardSource) (source : NativeRecipeSource)
    (reserved : NativeVec (NativeVec String)) :
    Result (core.result.Result Unit AuthsNativeRecipe.recipe.GatewayRecipeError) := do
  match guard.account with
  | none => guardDeniedTail guard source reserved
  | some account =>
      let checked ← AuthsNativeRecipe.recipe.validate.validate_account_read account
      let flow ← core.result.Result.Insts.CoreOpsTry.branch checked
      match flow with
      | .Continue path =>
          let next ← AuthsNativeRecipe.alloc.vec.Vec.push reserved path
          guardDeniedTail guard source next
      | .Break residual =>
          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
            Unit (core.convert.FromSame AuthsNativeRecipe.recipe.GatewayRecipeError) residual

def guardAllStages (guard : NativeGuardSource) (source : NativeRecipeSource) :
    Result (core.result.Result Unit AuthsNativeRecipe.recipe.GatewayRecipeError) := do
  let prefixes ← AuthsNativeRecipe.recipe.validate.validate_prefixes
    (AuthsNativeRecipe.alloc.vec.Vec.deref guard.prefixes)
  let flow ← core.result.Result.Insts.CoreOpsTry.branch prefixes
  match flow with
  | .Break residual =>
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
        Unit (core.convert.FromSame AuthsNativeRecipe.recipe.GatewayRecipeError) residual
  | .Continue _ =>
      match guard.probe with
      | none => guardAccountTail guard source (AuthsNativeRecipe.alloc.vec.Vec.new (NativeVec String))
      | some probe =>
          let checked ← AuthsNativeRecipe.recipe.validate.validate_probe probe
          let probeFlow ← core.result.Result.Insts.CoreOpsTry.branch checked
          match probeFlow with
          | .Break residual =>
              core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
                Unit (core.convert.FromSame AuthsNativeRecipe.recipe.GatewayRecipeError) residual
          | .Continue path =>
              let reserved ← AuthsNativeRecipe.alloc.vec.Vec.push
                (AuthsNativeRecipe.alloc.vec.Vec.new (NativeVec String)) path
              guardAccountTail guard source reserved

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel RecipeCredentialAdmission
set_option maxHeartbeats 24000000
set_option maxRecDepth 4096

/-- These source-stage terms expand to the actual generated function. There
is no opaque Auths guard, authorization Boolean or replacement execution path. -/
theorem native_guard_uses_original_stages (guard : NativeGuardSource) (source : NativeRecipeSource) :
    AuthsNativeRecipe.recipe.validate.validate_guard guard source = guardAllStages guard source := by
  cases probeAt : guard.probe <;> cases accountAt : guard.account <;>
    cases deniedAt : guard.denied_reads <;>
    simp [AuthsNativeRecipe.recipe.validate.validate_guard, guardAllStages, guardAccountTail,
      guardDeniedTail, probeAt, accountAt, deniedAt, bind_assoc]

private theorem native_guard_denied_tail_exact (guard : NativeGuardSource) (source : NativeRecipeSource)
    (reserved : NativeVec (NativeVec String)) (fits : GuardAdmissionFits guard)
    (sourceFits : GuardSourcePathsFit source) (reservedFits : FixedPathColumnFits reserved.val)
    (count : reserved.val.length ≤ 2) :
    guardDeniedTail guard source reserved ⦃ actual =>
      actual = guardUnitVerdict (guardDeniedTailResult
        (guard.denied_reads.map (fun reads => reads.val.map ruleGuardDeniedRead))
        (fixedPathColumn reserved.val) (ruleGuardSourcePaths source)) ⦄ := by
  unfold guardDeniedTail
  cases deniedAt : guard.denied_reads with
  | none => rfl
  | some reads =>
      apply spec_mono (native_guard_denied_original_source_exact
        (AuthsNativeRecipe.alloc.vec.Vec.deref reads) reserved source (fits.denied reads deniedAt)
        reservedFits sourceFits (by scalar_tac))
      intro actual meaning
      simpa [guardDeniedTailResult, deniedAt, native_deref_contents] using meaning

private theorem native_guard_account_tail_exact (guard : NativeGuardSource) (source : NativeRecipeSource)
    (reserved : NativeVec (NativeVec String)) (fits : GuardAdmissionFits guard)
    (sourceFits : GuardSourcePathsFit source) (reservedFits : FixedPathColumnFits reserved.val)
    (count : reserved.val.length ≤ 1) :
    guardAccountTail guard source reserved ⦃ actual =>
      actual = guardUnitVerdict (guardAccountTailResult
        (guard.account.map ruleGuardAccount)
        (guard.denied_reads.map (fun reads => reads.val.map ruleGuardDeniedRead))
        (fixedPathColumn reserved.val) (ruleGuardSourcePaths source)) ⦄ := by
  unfold guardAccountTail
  cases accountAt : guard.account with
  | none =>
      apply spec_mono (native_guard_denied_tail_exact guard source reserved fits sourceFits reservedFits (by omega))
      intro actual meaning
      simpa [accountAt, guardAccountTailResult] using meaning
  | some account =>
      step with native_guard_account_read_exact account (fits.account account accountAt) as ⟨checked, checkMeaning⟩
      cases checked with
      | Err error =>
          obtain ⟨refused, errorValue⟩ := original_guard_path_error error _ checkMeaning
          simp [core.result.Result.Insts.CoreOpsTry.branch,
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame, core.convert.FromSame.from, guardAccountTailResult,
            accountAt, refused, errorValue, guardUnitVerdict]
      | Ok path =>
          have selected := original_guard_path_ok path _ checkMeaning
          obtain ⟨admitted, original⟩ := (account_read_result_ok _ _).mp selected
          have fixedSelected := (fixed_path_result_ok _ _).mpr ⟨admitted.1, original⟩
          have pathFits := admitted_original_fixed_texts_fit _ path fixedSelected
          simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
          step with native_push_exact reserved path (by scalar_tac) as ⟨updated, appended⟩
          have updatedFits : FixedPathColumnFits updated.val := by
            intro value member
            rw [appended] at member
            rcases List.mem_append.mp member with earlier | current
            · exact reservedFits value earlier
            · have same : value = path := List.mem_singleton.mp current
              simpa [same] using pathFits
          have updatedCount : updated.val.length ≤ 2 := by simp [appended]; omega
          apply spec_mono (native_guard_denied_tail_exact guard source updated fits sourceFits updatedFits updatedCount)
          intro actual meaning
          simpa [guardAccountTailResult, accountAt, selected, fixedPathColumn,
            appended, List.map_append] using meaning

private theorem native_guard_all_stages_exact (guard : NativeGuardSource) (source : NativeRecipeSource)
    (fits : GuardAdmissionFits guard) (sourceFits : GuardSourcePathsFit source) :
    guardAllStages guard source ⦃ actual =>
      actual = guardUnitVerdict (guardResult (ruleGuard guard) (ruleGuardSourcePaths source)) ⦄ := by
  unfold guardAllStages
  step with native_guard_prefixes_admission_exact (AuthsNativeRecipe.alloc.vec.Vec.deref guard.prefixes)
    fits.prefixes as ⟨prefixes, prefixMeaning⟩
  by_cases allowedPrefixes : RecipeAdmissionAtoms.Prefixes (guard.prefixes.val.map textBytes)
  · have prefixesAccepted : prefixes = .Ok () := by
      simpa [allowedPrefixes, native_deref_contents, consumptionVerdict] using prefixMeaning
    simp only [prefixesAccepted, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    cases probeAt : guard.probe with
    | none =>
        apply spec_mono (native_guard_account_tail_exact guard source
          (AuthsNativeRecipe.alloc.vec.Vec.new (NativeVec String)) fits sourceFits
          (by simp [FixedPathColumnFits, native_empty_contents]) (by simp [native_empty_contents]))
        intro actual meaning
        simpa [guardResult, ruleGuard, allowedPrefixes, probeAt, native_empty_contents,
          fixedPathColumn, ruleGuardAccount, ruleGuardDeniedRead, planPath] using meaning
    | some probe =>
        step with native_guard_probe_exact probe (fits.probe probe probeAt) as ⟨checked, checkMeaning⟩
        cases checked with
        | Err error =>
            obtain ⟨refused, errorValue⟩ := original_guard_path_error error _ checkMeaning
            simp [core.result.Result.Insts.CoreOpsTry.branch,
              core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
              core.convert.FromSame, core.convert.FromSame.from, guardResult, ruleGuard,
              allowedPrefixes, probeAt, ruleGuardProbe, planPath, refused, errorValue, guardUnitVerdict]
        | Ok path =>
            have selected := original_guard_path_ok path _ checkMeaning
            obtain ⟨admitted, original⟩ := (probe_result_ok _ _).mp selected
            have fixedSelected := (fixed_path_result_ok _ _).mpr ⟨admitted.1, original⟩
            have pathFits := admitted_original_fixed_texts_fit _ path fixedSelected
            simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
            step with native_push_exact (AuthsNativeRecipe.alloc.vec.Vec.new (NativeVec String)) path
              (by simp [native_empty_contents]; scalar_tac) as ⟨reserved, appended⟩
            have reservedFits : FixedPathColumnFits reserved.val := by
              simpa [FixedPathColumnFits, appended, native_empty_contents] using pathFits
            have reservedCount : reserved.val.length ≤ 1 := by simp [appended, native_empty_contents]
            apply spec_mono (native_guard_account_tail_exact guard source reserved fits sourceFits reservedFits reservedCount)
            intro actual meaning
            simpa [guardResult, ruleGuard, allowedPrefixes, probeAt, ruleGuardProbe, ruleGuardAccount,
              ruleGuardDeniedRead, planPath, selected, fixedPathColumn, appended, native_empty_contents] using meaning
  · have prefixesRefused : prefixes = .Err .InvalidCredentialGuard := by
      simpa [allowedPrefixes, native_deref_contents, consumptionVerdict, consumptionError] using prefixMeaning
    simp [prefixesRefused, core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame, core.convert.FromSame.from, guardResult, ruleGuard,
      allowedPrefixes, guardUnitVerdict]

/-- Complete actual credential guard. Real prefix/probe/account calls earn
their results, returned reservations and bounded native carriers; the actual
source reservation and denied-read loop earn the final decision. The only
input domains describe original String representation, not accepted policy. -/
@[step] theorem native_guard_admission_exact (guard : NativeGuardSource) (source : NativeRecipeSource)
    (fits : GuardAdmissionFits guard) (sourceFits : GuardSourcePathsFit source) :
    AuthsNativeRecipe.recipe.validate.validate_guard guard source ⦃ actual =>
      actual = guardUnitVerdict (validateGuard () (ruleGuard guard) (ruleGuardSourcePaths source)) ⦄ := by
  rw [native_guard_uses_original_stages]
  apply spec_mono (native_guard_all_stages_exact guard source fits sourceFits)
  intro actual meaning
  simpa [guard_result_exact] using meaning

theorem native_guard_success_earns_policy (guard : NativeGuardSource) (source : NativeRecipeSource)
    (fits : GuardAdmissionFits guard) (sourceFits : GuardSourcePathsFit source) :
    AuthsNativeRecipe.recipe.validate.validate_guard guard source ⦃ actual =>
      actual = .Ok () → GuardAdmitted (ruleGuard guard) (ruleGuardSourcePaths source) ⦄ := by
  apply spec_mono (native_guard_admission_exact guard source fits sourceFits)
  intro actual meaning accepted
  by_contra refused
  simp [validateGuard, refused, guardUnitVerdict, accepted] at meaning

theorem native_guard_useful (guard : NativeGuardSource) (source : NativeRecipeSource)
    (fits : GuardAdmissionFits guard) (sourceFits : GuardSourcePathsFit source)
    (admitted : GuardAdmitted (ruleGuard guard) (ruleGuardSourcePaths source)) :
    AuthsNativeRecipe.recipe.validate.validate_guard guard source ⦃ actual => actual = .Ok () ⦄ := by
  apply spec_mono (native_guard_admission_exact guard source fits sourceFits)
  intro actual meaning
  simpa [validateGuard, admitted, guardUnitVerdict] using meaning

end Auths.Product.NativeCompiler.Refinement
