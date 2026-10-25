import Auths.Product.NativeCompilerNamedBody

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

@[step] theorem native_probe_plan_exact (lowering : NativeLowering) (credential : NativeCredentialSource)
    (bounded : CredentialPathsFit credential) :
    AuthsNativeRecipe.recipe.lower.Lowering.probe lowering credential ⦃ actual =>
      nativeRecipeResult (Option.map nativeCredentialPlan) actual =
        RecipePlanModel.optionalCredential planErrors (planReadContext lowering)
          (((originalGuard credential).map planGuard).bind RecipePlanModel.Guard.probe) ⦄ := by
  unfold AuthsNativeRecipe.recipe.lower.Lowering.probe
  step with native_guard_choice_exact credential as ⟨selected, selectedMeaning⟩
  cases guardAt : originalGuard credential with
  | none => simp [selectedMeaning, guardAt, RecipePlanModel.optionalCredential, nativeRecipeResult]
  | some guard =>
      simp only [selectedMeaning, guardAt]
      cases probeAt : guard.probe with
      | none => simp [probeAt, planGuard, RecipePlanModel.optionalCredential, nativeRecipeResult]
      | some probe =>
          simp only [probeAt]
          have pathBounds := (bounded guard guardAt).1 probe probeAt
          step with native_credential_read_exact lowering .Get (AuthsNativeRecipe.alloc.vec.Vec.deref probe.path)
            pathBounds as ⟨compiled, compiledMeaning⟩
          cases compiled with
          | Err error =>
              simp [nativeRecipeResult, RecipePlanModel.optionalCredential, RecipePlanModel.credentialRead,
                planReadContext, planErrors, planGuard, probeAt, plan_path_full_lowering, ← compiledMeaning]
          | Ok plan =>
              step with native_credential_plan_clone_exact plan as ⟨copied, same⟩
              simp [same, nativeRecipeResult, RecipePlanModel.optionalCredential, RecipePlanModel.credentialRead,
                planReadContext, planErrors, planGuard, probeAt, plan_path_full_lowering, ← compiledMeaning,
                kernelWriteMethod]

@[step] theorem native_account_plan_exact (lowering : NativeLowering) (credential : NativeCredentialSource)
    (bounded : CredentialPathsFit credential) :
    AuthsNativeRecipe.recipe.lower.Lowering.account lowering credential ⦃ actual =>
      nativeRecipeResult (Option.map nativeCredentialPlan) actual =
        RecipePlanModel.optionalCredential planErrors (planReadContext lowering)
          (((originalGuard credential).map planGuard).bind RecipePlanModel.Guard.account) ⦄ := by
  unfold AuthsNativeRecipe.recipe.lower.Lowering.account
  step with native_guard_choice_exact credential as ⟨selected, selectedMeaning⟩
  cases guardAt : originalGuard credential with
  | none => simp [selectedMeaning, guardAt, RecipePlanModel.optionalCredential, nativeRecipeResult]
  | some guard =>
      simp only [selectedMeaning, guardAt]
      cases accountAt : guard.account with
      | none => simp [accountAt, planGuard, RecipePlanModel.optionalCredential, nativeRecipeResult]
      | some account =>
          simp only [accountAt]
          have pathBounds := (bounded guard guardAt).2.1 account accountAt
          step with native_credential_read_exact lowering .Get (AuthsNativeRecipe.alloc.vec.Vec.deref account.path)
            pathBounds as ⟨compiled, compiledMeaning⟩
          cases compiled with
          | Err error =>
              simp [nativeRecipeResult, RecipePlanModel.optionalCredential, RecipePlanModel.credentialRead,
                planReadContext, planErrors, planGuard, accountAt, plan_path_full_lowering, ← compiledMeaning]
          | Ok plan =>
              step with native_credential_plan_clone_exact plan as ⟨copied, same⟩
              simp [same, nativeRecipeResult, RecipePlanModel.optionalCredential, RecipePlanModel.credentialRead,
                planReadContext, planErrors, planGuard, accountAt, plan_path_full_lowering, ← compiledMeaning,
                kernelWriteMethod]

private theorem native_denied_plan_suffix (lowering : NativeLowering)
    (iterator : core.slice.iter.Iter NativeDeniedSource) (output : NativeVec NativeCredentialPlan)
    (bounded : ∀ read ∈ iterator.slice.val, NativeDeniedFits read)
    (room : output.val.length + (iterator.slice.val.length - iterator.i) ≤ Usize.max) :
    AuthsNativeRecipe.recipe.lower.Lowering.denied_reads_loop iterator lowering output ⦃ actual =>
      nativeRecipeResult (fun plans => plans.val.map nativeCredentialPlan) actual =
        (RecipePlanModel.deniedReads planErrors (planReadContext lowering)
          ((iterator.slice.val.drop iterator.i).map planDeniedRead)).map
          (fun plans => output.val.map nativeCredentialPlan ++ plans) ⦄ := by
  generalize remaining : iterator.slice.val.length - iterator.i = count
  induction count using Nat.strong_induction_on generalizing iterator output with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.lower.Lowering.denied_reads_loop
      by_cases inside : iterator.i < iterator.slice.val.length
      · simp only [core.slice.iter.IteratorSliceIter.next, dif_pos inside, bind_tc_ok]
        let read := iterator.slice.val[iterator.i]
        let next : core.slice.iter.Iter NativeDeniedSource := { iterator with i := iterator.i + 1 }
        have suffix : iterator.slice.val.drop iterator.i = read :: next.slice.val.drop next.i := by
          simpa only [read, next] using List.drop_eq_getElem_cons inside
        have member : read ∈ iterator.slice.val := List.getElem_mem inside
        step with native_denied_method_choice_exact read (bounded read member).1 as ⟨method, methodMeaning⟩
        step with native_credential_read_exact lowering method (AuthsNativeRecipe.alloc.vec.Vec.deref read.path)
          (bounded read member).2 as ⟨compiled, compiledMeaning⟩
        cases compiled with
        | Err error =>
            simp [suffix, RecipePlanModel.deniedReads, RecipePlanModel.credentialRead,
              planReadContext, planErrors, planDeniedRead, plan_path_full_lowering,
              plan_denied_method, ← methodMeaning, ← compiledMeaning, nativeRecipeResult]
        | Ok plan =>
            step with native_credential_plan_clone_exact plan as ⟨copied, same⟩
            have capacity : output.val.length < Usize.max := by omega
            step with native_push_exact output copied capacity as ⟨grown, grownMeaning⟩
            have nextBounds : ∀ read ∈ next.slice.val, NativeDeniedFits read := by
              simpa only [next] using bounded
            have nextRoom : grown.val.length + (next.slice.val.length - next.i) ≤ Usize.max := by
              simp only [grownMeaning, List.length_append, List.length_singleton, next]
              omega
            apply spec_mono (ih _ (by simp only [next] at *; omega) next grown nextBounds nextRoom rfl)
            intro actual exact
            simpa [suffix, RecipePlanModel.deniedReads, RecipePlanModel.credentialRead,
              planReadContext, planErrors, planDeniedRead, plan_path_full_lowering,
              plan_denied_method, ← methodMeaning, ← compiledMeaning, nativeRecipeResult,
              grownMeaning, same, List.map_append, List.append_assoc] using exact
      · have ended : iterator.slice.val.length ≤ iterator.i := by omega
        simp [core.slice.iter.IteratorSliceIter.next, inside, List.drop_eq_nil_of_le ended,
          RecipePlanModel.deniedReads, nativeRecipeResult]

@[step] theorem native_denied_reads_exact (lowering : NativeLowering) (reads : Slice NativeDeniedSource)
    (bounded : ∀ read ∈ reads.val, NativeDeniedFits read) :
    AuthsNativeRecipe.recipe.lower.Lowering.denied_reads lowering reads ⦃ actual =>
      nativeRecipeResult (fun plans => plans.val.map nativeCredentialPlan) actual =
        RecipePlanModel.deniedReads planErrors (planReadContext lowering) (reads.val.map planDeniedRead) ⦄ := by
  unfold AuthsNativeRecipe.recipe.lower.Lowering.denied_reads
    SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter
  simp only [bind_tc_ok]
  apply spec_mono (native_denied_plan_suffix lowering ⟨reads, 0⟩
    (AuthsNativeRecipe.alloc.vec.Vec.new NativeCredentialPlan) bounded (by simpa using reads.property))
  intro actual exact
  simpa only [List.drop_zero, native_empty_contents, List.map_nil, List.nil_append, Except.map_id] using exact

@[step] theorem native_denied_plan_exact (lowering : NativeLowering) (credential : NativeCredentialSource)
    (bounded : CredentialPathsFit credential) :
    AuthsNativeRecipe.recipe.lower.Lowering.denied lowering credential ⦃ actual =>
      nativeRecipeResult (fun plans => plans.val.map nativeCredentialPlan) actual =
        RecipePlanModel.deniedReads planErrors (planReadContext lowering)
          ((((originalGuard credential).map planGuard).bind RecipePlanModel.Guard.denied).getD []) ⦄ := by
  unfold AuthsNativeRecipe.recipe.lower.Lowering.denied
  step with native_guard_choice_exact credential as ⟨selected, selectedMeaning⟩
  cases guardAt : originalGuard credential with
  | none =>
      simp [selectedMeaning, guardAt, RecipePlanModel.deniedReads, nativeRecipeResult, native_empty_contents]
  | some guard =>
      simp only [selectedMeaning, guardAt]
      cases readsAt : guard.denied_reads with
      | none =>
          simp [readsAt, planGuard, RecipePlanModel.deniedReads, nativeRecipeResult, native_empty_contents]
      | some reads =>
          simp only [readsAt]
          apply spec_mono (native_denied_reads_exact lowering (AuthsNativeRecipe.alloc.vec.Vec.deref reads)
            ((bounded guard guardAt).2.2 reads readsAt))
          intro actual exact
          simpa [planGuard, readsAt] using exact

end Auths.Product.NativeCompiler.Refinement
