import Auths.Product.RecipeDeniedReadSequence
import Auths.Product.NativeCompilerDeniedReadStep

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel RecipeCredentialAdmission
set_option maxHeartbeats 22000000
set_option maxRecDepth 4096

/-- An already recorded failure is terminal even if there are unread inputs.
No later malformed read can replace that error or add another seen path. -/
@[step] theorem native_denied_read_loop_stops_on_failure (reads : Slice NativeDeniedSource)
    (reserved : Slice (NativeVec String)) (seen : NativeVec (NativeVec String))
    (position : Std.Usize) (error : AuthsNativeRecipe.recipe.GatewayRecipeError) :
    AuthsNativeRecipe.recipe.validate.validate_denied_reads_loop reads reserved seen position (some error)
      ⦃ actual => actual = some error ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.validate_denied_reads_loop
  by_cases inside : position < reads.len <;>
    simp [inside, core.option.Option.is_none]

private theorem native_denied_reads_suffix (reads : Slice NativeDeniedSource)
    (reserved : Slice (NativeVec String)) (seen : NativeVec (NativeVec String)) (position : Std.Usize)
    (within : position.val ≤ reads.val.length)
    (fits : ∀ read ∈ reads.val, GuardDeniedReadFits read)
    (reservedFits : FixedPathColumnFits reserved.val) (seenFits : FixedPathColumnFits seen.val)
    (room : seen.val.length + (reads.val.length - position.val) ≤ Usize.max) :
    AuthsNativeRecipe.recipe.validate.validate_denied_reads_loop reads reserved seen position none ⦃ actual =>
      actual = if deniedReadSequence (fixedPathColumn reserved.val) (fixedPathColumn seen.val)
        ((reads.val.map ruleGuardDeniedRead).drop position.val) then none else some .InvalidCredentialGuard ⦄ := by
  generalize remaining : reads.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing seen position with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.validate_denied_reads_loop
      by_cases inside : position.val < reads.val.length
      · have nativeInside : position < reads.len := by scalar_tac
        simp only [nativeInside, core.option.Option.is_none, ↓reduceIte, bind_tc_ok]
        step with Slice.index_usize_spec reads position inside as ⟨read, readAt⟩
        have readFits := fits read (by rw [readAt]; exact List.getElem_mem inside)
        have suffix : (reads.val.map ruleGuardDeniedRead).drop position.val =
            ruleGuardDeniedRead read :: (reads.val.map ruleGuardDeniedRead).drop (position.val + 1) := by
          simpa [List.drop_map, readAt] using
            congrArg (List.map ruleGuardDeniedRead) (List.drop_eq_getElem_cons inside)
        step with native_guard_denied_read_step_exact read reserved seen readFits reservedFits seenFits (by omega)
          as ⟨checked, stepVerdict, stepState, stepGrowth, nextFits, refusalFrame⟩
        let model := deniedReadStep (ruleGuardDeniedRead read) (fixedPathColumn reserved.val) (fixedPathColumn seen.val)
        cases verdict : model.1 with
        | error error =>
            cases error
            have refused : checked.1 = .Err .InvalidCredentialGuard := by
              simpa [model, verdict, guardUnitVerdict] using stepVerdict
            simp only [refused, bind_tc_ok]
            step as ⟨next, nextValue⟩
            apply spec_mono (native_denied_read_loop_stops_on_failure reads reserved checked.2 next .InvalidCredentialGuard)
            intro actual meaning
            simpa [suffix, deniedReadSequence, ← model, verdict] using meaning
        | ok unit =>
            cases unit
            have accepted : checked.1 = .Ok () := by simpa [model, verdict, guardUnitVerdict] using stepVerdict
            simp only [accepted, bind_tc_ok]
            step as ⟨next, nextValue⟩
            have nextRoom : checked.2.val.length + (reads.val.length - next.val) ≤ Usize.max := by omega
            apply spec_mono (ih _ (by omega) checked.2 next (by omega) nextFits nextRoom rfl)
            intro actual meaning
            simpa [suffix, deniedReadSequence, ← model, verdict, nextValue, stepState] using meaning
      · have nativeEnded : ¬position < reads.len := by scalar_tac
        have ended : (reads.val.map ruleGuardDeniedRead).length ≤ position.val := by simp; omega
        simp [nativeEnded, List.drop_eq_nil_of_le ended, deniedReadSequence]

/-- Complete actual denied-read list validation. Its 1..4 bound earns every
insertion and cursor increment; first failure stops the real loop. Original
read/path/status columns and complete earlier reservations remain represented. -/
@[step] theorem native_guard_denied_reads_exact (reads : Slice NativeDeniedSource)
    (reserved : Slice (NativeVec String)) (fits : ∀ read ∈ reads.val, GuardDeniedReadFits read)
    (reservedFits : FixedPathColumnFits reserved.val) :
    AuthsNativeRecipe.recipe.validate.validate_denied_reads reads reserved ⦃ actual =>
      actual = guardUnitVerdict (deniedReadsResult (reads.val.map ruleGuardDeniedRead) (fixedPathColumn reserved.val)) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.validate_denied_reads
  by_cases empty : reads.val = []
  · simp [core.slice.Slice.is_empty, empty, deniedReadsResult, guardUnitVerdict]
  · have positive : 0 < reads.val.length := List.length_pos.mpr empty
    simp only [core.slice.Slice.is_empty, List.isEmpty_eq_false.mpr empty,
      Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
    by_cases large : 4 < reads.val.length
    · have nativeLarge : reads.len > AuthsNativeRecipe.recipe.validate.MAX_DENIED_READS := by
        simp [AuthsNativeRecipe.recipe.validate.MAX_DENIED_READS]; scalar_tac
      simp [nativeLarge, deniedReadsResult, Nat.not_le.mpr large, guardUnitVerdict]
    · have bounded : reads.val.length ≤ 4 := by omega
      have nativeWithin : ¬reads.len > AuthsNativeRecipe.recipe.validate.MAX_DENIED_READS := by
        simp [AuthsNativeRecipe.recipe.validate.MAX_DENIED_READS]; scalar_tac
      simp only [nativeWithin, ↓reduceIte]
      step with native_denied_reads_suffix reads reserved (AuthsNativeRecipe.alloc.vec.Vec.new (NativeVec String))
        0#usize (by simp) fits reservedFits (by simp [FixedPathColumnFits, native_empty_contents])
        (by simp [native_empty_contents]; scalar_tac) as ⟨failure, failureMeaning⟩
      by_cases allowed : deniedReadSequence (fixedPathColumn reserved.val) [] (reads.val.map ruleGuardDeniedRead) = true
      · have noFailure : failure = none := by simpa [native_empty_contents, fixedPathColumn, allowed] using failureMeaning
        simp [noFailure, deniedReadsResult, positive, bounded, allowed, guardUnitVerdict]
      · have failed : failure = some .InvalidCredentialGuard := by
          simpa [native_empty_contents, fixedPathColumn, allowed] using failureMeaning
        simp [failed, deniedReadsResult, positive, bounded, allowed, guardUnitVerdict]

theorem native_guard_denied_reads_success (reads : Slice NativeDeniedSource)
    (reserved : Slice (NativeVec String)) (fits : ∀ read ∈ reads.val, GuardDeniedReadFits read)
    (reservedFits : FixedPathColumnFits reserved.val) :
    AuthsNativeRecipe.recipe.validate.validate_denied_reads reads reserved ⦃ actual =>
      actual = .Ok () → DeniedReadsAdmitted (reads.val.map ruleGuardDeniedRead) (fixedPathColumn reserved.val) ⦄ := by
  apply spec_mono (native_guard_denied_reads_exact reads reserved fits reservedFits)
  intro actual meaning accepted
  have modelAccepted : deniedReadsResult (reads.val.map ruleGuardDeniedRead) (fixedPathColumn reserved.val) = .ok () := by
    cases result : deniedReadsResult (reads.val.map ruleGuardDeniedRead) (fixedPathColumn reserved.val) <;>
      simp_all [guardUnitVerdict]
  exact (denied_reads_result_admission _ _).mp modelAccepted

theorem native_guard_denied_reads_useful (reads : Slice NativeDeniedSource)
    (reserved : Slice (NativeVec String)) (fits : ∀ read ∈ reads.val, GuardDeniedReadFits read)
    (reservedFits : FixedPathColumnFits reserved.val)
    (admitted : DeniedReadsAdmitted (reads.val.map ruleGuardDeniedRead) (fixedPathColumn reserved.val)) :
    AuthsNativeRecipe.recipe.validate.validate_denied_reads reads reserved ⦃ actual => actual = .Ok () ⦄ := by
  apply spec_mono (native_guard_denied_reads_exact reads reserved fits reservedFits)
  intro actual meaning
  simpa [(denied_reads_result_admission _ _).mpr admitted, guardUnitVerdict] using meaning

end Auths.Product.NativeCompiler.Refinement
