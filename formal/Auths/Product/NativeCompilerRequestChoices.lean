import Auths.Product.NativeCompilerReadPlans

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def originalResponseField : NativePathSource → Bool
  | .ResponseField _ _ => true
  | .Fixed _ | .Field _ | .Echo => false

def originalGuard : AuthsNativeRecipe.recipe.source.CredentialSource →
    Option AuthsNativeRecipe.recipe.source.GuardSource
  | .Bearer guard => guard
  | .HeaderApiKey _ guard => guard

def originalIdempotencyHeader (source : NativeRecipeSource) : Bool :=
  match source.write.idempotency with
  | some (.DerivedHeader _) => true
  | some (.OperationIdField _ _) | none => false

def originalDeniedMethod (source : AuthsNativeRecipe.recipe.source.DeniedReadSource) :
    RequestConstruction.Method :=
  if textBytes source.method = [72, 69, 65, 68] then .head else .get

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

private theorem native_response_field_suffix (iterator : core.slice.iter.Iter NativePathSource) :
    AuthsNativeRecipe.recipe.lower.contains_response_field_loop iterator ⦃ actual =>
      actual = (iterator.slice.val.drop iterator.i).any originalResponseField ⦄ := by
  generalize remaining : iterator.slice.val.length - iterator.i = count
  induction count using Nat.strong_induction_on generalizing iterator with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.lower.contains_response_field_loop
      by_cases inside : iterator.i < iterator.slice.val.length
      · simp only [core.slice.iter.IteratorSliceIter.next, dif_pos inside, bind_tc_ok]
        let head := iterator.slice.val[iterator.i]
        let next : core.slice.iter.Iter NativePathSource := { iterator with i := iterator.i + 1 }
        have suffix : iterator.slice.val.drop iterator.i = head :: next.slice.val.drop next.i := by
          simpa only [head, next] using List.drop_eq_getElem_cons inside
        have smaller : next.slice.val.length - next.i < count := by
          simp only [next] at *
          omega
        cases shape : head with
        | Fixed value =>
            apply spec_mono (ih _ smaller next rfl)
            intro actual exact
            simpa only [suffix, List.any_cons, shape, originalResponseField, Bool.false_or] using exact
        | Field name =>
            apply spec_mono (ih _ smaller next rfl)
            intro actual exact
            simpa only [suffix, List.any_cons, shape, originalResponseField, Bool.false_or] using exact
        | ResponseField pointer maximum =>
            simp [suffix, shape, originalResponseField]
        | Echo =>
            apply spec_mono (ih _ smaller next rfl)
            intro actual exact
            simpa only [suffix, List.any_cons, shape, originalResponseField, Bool.false_or] using exact
      · have ended : iterator.slice.val.length ≤ iterator.i := by omega
        simp [core.slice.iter.IteratorSliceIter.next, inside, List.drop_eq_nil_of_le ended]

/-- Every original tag participates; ignored payload strings need no validity
premise because this choice reads only the segment constructor. -/
@[step] theorem native_response_field_choice_exact (path : Slice NativePathSource) :
    AuthsNativeRecipe.recipe.lower.contains_response_field path ⦃ actual =>
      actual = path.val.any originalResponseField ⦄ := by
  unfold AuthsNativeRecipe.recipe.lower.contains_response_field
    SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter
  simp only [bind_tc_ok]
  apply spec_mono (native_response_field_suffix ⟨path, 0⟩)
  intro actual exact
  simpa only [List.drop_zero] using exact

@[step] theorem native_guard_choice_exact (credential : AuthsNativeRecipe.recipe.source.CredentialSource) :
    AuthsNativeRecipe.recipe.source.CredentialSource.guard credential ⦃ actual =>
      actual = originalGuard credential ⦄ := by
  cases credential <;>
    simp [AuthsNativeRecipe.recipe.source.CredentialSource.guard,
      AuthsNativeRecipe.core.option.Option.as_ref, _root_.core.option.Option.as_ref, originalGuard]

@[step] theorem native_idempotency_header_choice_exact (source : NativeRecipeSource) :
    AuthsNativeRecipe.recipe.lower.has_idempotency_header source ⦃ actual =>
      actual = originalIdempotencyHeader source ⦄ := by
  unfold AuthsNativeRecipe.recipe.lower.has_idempotency_header originalIdempotencyHeader
  cases source.write.idempotency with
  | none => rfl
  | some source => cases source <;> rfl

/-- HEAD is selected by full original method bytes. Every other method
retains the compiler's existing GET branch; validation must separately earn
the allowed source-method vocabulary. -/
@[step] theorem native_denied_method_choice_exact (source : AuthsNativeRecipe.recipe.source.DeniedReadSource)
    (fits : TextFits source.method) :
    AuthsNativeRecipe.recipe.lower.denied_read_method source ⦃ actual =>
      kernelWriteMethod actual = originalDeniedMethod source ⦄ := by
  unfold AuthsNativeRecipe.recipe.lower.denied_read_method
  step with borrow_text_exact source.method fits as ⟨method, methodBytes⟩
  step as ⟨literal, literalBytes⟩
  step with native_schema_byte_equality method literal as ⟨head, compared⟩
  have fullComparison : head = decide (textBytes source.method = [72, 69, 65, 68]) := by
    simpa [schemaSliceBytes, methodBytes, literalBytes] using compared
  cases head <;> simp [originalDeniedMethod, kernelWriteMethod, ← fullComparison]

end Auths.Product.NativeCompiler.Refinement
