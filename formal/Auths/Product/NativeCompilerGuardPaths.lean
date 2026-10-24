import Auths.Product.RecipeGuardPaths
import Auths.Product.NativeCompilerPathRules

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

/-- Only Fixed payloads are borrowed by this validator. Other tags refuse
without inspecting their payloads. No admission premise is included. -/
def GuardPathFits : NativePathSource → Prop
  | .Fixed value => TextFits value
  | _ => True

def guardPathBytes (result : core.result.Result (NativeVec String)
    AuthsNativeRecipe.recipe.GatewayRecipeError) :
    core.result.Result (List (List Nat)) AuthsNativeRecipe.recipe.GatewayRecipeError :=
  match result with
  | .Ok values => .Ok (values.val.map textBytes)
  | .Err error => .Err error

def guardPathVerdict (result : Except Unit RecipeCredentialAdmission.FixedPath) :
    core.result.Result (List (List Nat)) AuthsNativeRecipe.recipe.GatewayRecipeError :=
  match result with
  | .ok values => .Ok values
  | .error _ => .Err .InvalidCredentialGuard

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel RecipeCredentialAdmission
set_option maxHeartbeats 18000000
set_option maxRecDepth 4096

private def remainingFixed (path : Slice NativePathSource) (position : Nat) (valid : Bool) :
    FixedPath × Bool :=
  if valid then fixedPrefix ((path.val.map planPathSegment).drop position) else ([], false)

private theorem native_fixed_values_suffix (path : Slice NativePathSource)
    (values : NativeVec String) (position : Std.Usize) (valid : Bool)
    (within : position.val ≤ path.val.length)
    (room : values.val.length + (path.val.length - position.val) ≤ Usize.max) :
    AuthsNativeRecipe.recipe.validate.fixed_values_loop path values position valid ⦃ actual =>
      actual.1.val.map textBytes = values.val.map textBytes ++ (remainingFixed path position.val valid).1 ∧
      actual.2 = (remainingFixed path position.val valid).2 ⦄ := by
  generalize remaining : path.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing values position valid with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.fixed_values_loop
      by_cases inside : position.val < path.val.length
      · have nativeInside : position < path.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        cases valid with
        | false => simp [remainingFixed]
        | true =>
            simp only [Bool.true_eq_true, ↓reduceIte]
            step with Slice.index_usize_spec path position inside as ⟨segment, segmentAt⟩
            have suffix : (path.val.map planPathSegment).drop position.val =
                planPathSegment segment :: (path.val.map planPathSegment).drop (position.val + 1) := by
              simpa [List.drop_map, segmentAt] using
                congrArg (List.map planPathSegment) (List.drop_eq_getElem_cons inside)
            cases shape : segment with
            | Fixed value =>
                simp only [shape, AuthsNativeRecipe.alloc.string.String.Insts.CoreCloneClone.clone, bind_tc_ok]
                step with native_push_exact values value (by omega) as ⟨updated, appended⟩
                step as ⟨next, nextValue⟩
                have nextRoom : updated.val.length + (path.val.length - next.val) ≤ Usize.max := by
                  simp [appended] at *; omega
                apply spec_mono (ih _ (by omega) updated next true (by omega) nextRoom rfl)
                intro actual meaning
                simpa [remainingFixed, suffix, shape, planPathSegment, fixedPrefix, appended,
                  nextValue, List.map_append, List.append_assoc] using meaning
            | Field _ | ResponseField _ _ | Echo =>
                simp only [shape, bind_tc_ok]
                step as ⟨next, nextValue⟩
                apply spec_mono (ih _ (by omega) values next false (by omega) (by omega) rfl)
                intro actual meaning
                simpa [remainingFixed, suffix, shape, planPathSegment, fixedPrefix] using meaning
      · have nativeEnded : ¬position < path.len := by scalar_tac
        have ended : (path.val.map planPathSegment).length ≤ position.val := by simp; omega
        cases valid <;> simp [nativeEnded, remainingFixed, List.drop_eq_nil_of_le ended, fixedPrefix]

/-- Complete actual copying, including a retained all-fixed prefix at the
first non-fixed tag. Storage room comes from the represented original slice. -/
@[step] theorem native_fixed_values_prefix_exact (path : Slice NativePathSource) :
    AuthsNativeRecipe.recipe.validate.fixed_values_loop path (AuthsNativeRecipe.alloc.vec.Vec.new String)
      0#usize true ⦃ actual =>
      actual.1.val.map textBytes = (fixedPrefix (path.val.map planPathSegment)).1 ∧
      actual.2 = (fixedPrefix (path.val.map planPathSegment)).2 ⦄ := by
  apply spec_mono (native_fixed_values_suffix path (AuthsNativeRecipe.alloc.vec.Vec.new String)
    0#usize true (by simp) (by simpa [native_empty_contents] using path.toBase.property))
  intro actual meaning
  simpa [remainingFixed, native_empty_contents] using meaning

/-- This projection checks source tags only. It intentionally accepts the
empty all-fixed path and does not check segment grammar or the 16-slot bound. -/
@[step] theorem native_fixed_values_exact (path : Slice NativePathSource) :
    AuthsNativeRecipe.recipe.validate.fixed_values path ⦃ actual =>
      actual.map (fun values => values.val.map textBytes) = fixedValues (path.val.map planPathSegment) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.fixed_values
  step with native_fixed_values_prefix_exact path as ⟨copied, bytes, flag⟩
  have original := fixed_prefix_values (path.val.map planPathSegment)
  cases valid : copied.2 <;> simp_all

private theorem native_fixed_segments_suffix (path : Slice NativePathSource) (position : Std.Usize)
    (valid : Bool) (within : position.val ≤ path.val.length)
    (fits : ∀ segment ∈ path.val, GuardPathFits segment) :
    AuthsNativeRecipe.recipe.validate.fixed_segments_valid_loop path position valid ⦃ actual =>
      actual = (valid && decide (FixedSegments ((path.val.map planPathSegment).drop position.val))) ⦄ := by
  generalize remaining : path.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position valid with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.fixed_segments_valid_loop
      by_cases inside : position.val < path.val.length
      · have nativeInside : position < path.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        cases valid with
        | false => simp
        | true =>
            simp only [Bool.true_eq_true, ↓reduceIte]
            step with Slice.index_usize_spec path position inside as ⟨segment, segmentAt⟩
            have suffix : (path.val.map planPathSegment).drop position.val =
                planPathSegment segment :: (path.val.map planPathSegment).drop (position.val + 1) := by
              simpa [List.drop_map, segmentAt] using
                congrArg (List.map planPathSegment) (List.drop_eq_getElem_cons inside)
            have headFits := fits segment (by rw [segmentAt]; exact List.getElem_mem inside)
            cases shape : segment with
            | Fixed value =>
                have valueFits : TextFits value := by simpa [GuardPathFits, shape] using headFits
                simp only [shape]
                step with native_deref_view_exact value valueFits as ⟨view, viewMeaning⟩
                subst view
                step with native_recipe_fixed_segment_exact (nativeTextView value valueFits) as ⟨allowed, allowance⟩
                have originalAllowance : allowed = decide (PathCompiler.FixedValid (textBytes value)) := by
                  simpa [native_text_view_bytes] using allowance
                step as ⟨next, nextValue⟩
                apply spec_mono (ih _ (by omega) next allowed (by omega) rfl)
                intro actual meaning
                simpa [suffix, shape, planPathSegment, FixedSegments, nextValue,
                  ← originalAllowance, decide_and] using meaning
            | Field _ | ResponseField _ _ | Echo =>
                simp only [shape, bind_tc_ok]
                step as ⟨next, nextValue⟩
                apply spec_mono (ih _ (by omega) next false (by omega) rfl)
                intro actual meaning
                simpa [suffix, shape, planPathSegment, FixedSegments] using meaning
      · have nativeEnded : ¬position < path.len := by scalar_tac
        have ended : (path.val.map planPathSegment).length ≤ position.val := by simp; omega
        simp [nativeEnded, List.drop_eq_nil_of_le ended, FixedSegments]

@[step] theorem native_fixed_segments_exact (path : Slice NativePathSource)
    (fits : ∀ segment ∈ path.val, GuardPathFits segment) :
    AuthsNativeRecipe.recipe.validate.fixed_segments_valid path ⦃ actual =>
      actual = decide (FixedSegments (path.val.map planPathSegment)) ⦄ := by
  simpa [AuthsNativeRecipe.recipe.validate.fixed_segments_valid] using
    native_fixed_segments_suffix path 0#usize true (by simp) fits

/-- Complete native fixed-path admission. All refusals have the actual guard
error and success returns every original fixed segment in original order. -/
@[step] theorem native_guard_fixed_path_exact (path : Slice NativePathSource)
    (fits : ∀ segment ∈ path.val, GuardPathFits segment) :
    AuthsNativeRecipe.recipe.validate.fixed_path path ⦃ actual =>
      guardPathBytes actual = guardPathVerdict (fixedPathResult (path.val.map planPathSegment)) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.fixed_path
  by_cases empty : path.val = []
  · simp [core.slice.Slice.is_empty, empty, fixedPathResult, guardPathBytes, guardPathVerdict]
  · have positive : 0 < path.val.length := List.length_pos.mpr empty
    simp only [core.slice.Slice.is_empty, List.isEmpty_eq_false.mpr empty,
      Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
    by_cases large : 16 < path.val.length
    · have nativeLarge : path.len > AuthsNativeRecipe.recipe.MAX_PATH_SEGMENTS := by
        simp [AuthsNativeRecipe.recipe.MAX_PATH_SEGMENTS,
          AuthsNativeRecipe.auths_gateway_kernel.path_compiler.MAX_PATH_SEGMENTS]; scalar_tac
      simp [nativeLarge, fixedPathResult, Nat.not_le.mpr large, guardPathBytes, guardPathVerdict]
    · have bounded : path.val.length ≤ 16 := by omega
      have nativeWithin : ¬path.len > AuthsNativeRecipe.recipe.MAX_PATH_SEGMENTS := by
        simp [AuthsNativeRecipe.recipe.MAX_PATH_SEGMENTS,
          AuthsNativeRecipe.auths_gateway_kernel.path_compiler.MAX_PATH_SEGMENTS]; scalar_tac
      simp only [nativeWithin, ↓reduceIte]
      step with native_fixed_segments_exact path fits as ⟨valid, validity⟩
      cases valid with
      | false => simp [fixedPathResult, positive, bounded, ← validity, guardPathBytes, guardPathVerdict]
      | true =>
          simp only [Bool.true_eq_true, ↓reduceIte]
          step with native_fixed_values_exact path as ⟨copied, original⟩
          cases copied <;> simp_all [core.option.Option.ok_or, fixedPathResult,
            guardPathBytes, guardPathVerdict, positive, bounded]

theorem native_guard_fixed_path_success (path : Slice NativePathSource)
    (fits : ∀ segment ∈ path.val, GuardPathFits segment) :
    AuthsNativeRecipe.recipe.validate.fixed_path path ⦃ actual =>
      ∀ copied, actual = .Ok copied → FixedPathAdmitted (path.val.map planPathSegment) ∧
        fixedValues (path.val.map planPathSegment) = some (copied.val.map textBytes) ∧
        0 < copied.val.length ∧ copied.val.length ≤ 16 ⦄ := by
  apply spec_mono (native_guard_fixed_path_exact path fits)
  intro actual meaning copied accepted
  rw [accepted] at meaning
  have result : fixedPathResult (path.val.map planPathSegment) = .ok (copied.val.map textBytes) := by
    cases outcome : fixedPathResult (path.val.map planPathSegment) <;> simp_all [guardPathBytes, guardPathVerdict]
  obtain ⟨admitted, original⟩ := (fixed_path_result_ok _ _).mp result
  have shape := fixed_values_preserve_all_original_segments _ _ original
  refine ⟨admitted, original, ?_, ?_⟩
  · simpa [shape] using admitted.1
  · simpa [shape] using admitted.2.1

end Auths.Product.NativeCompiler.Refinement
