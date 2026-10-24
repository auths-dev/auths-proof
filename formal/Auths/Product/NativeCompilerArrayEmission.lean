import Auths.Product.NativeCompilerTraversalContext

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.EmitterInternal
open Auths.Product.NativeCompiler.StdModel
open Auths.Product.NativeCompiler.Refinement
open TemplateAst
set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

theorem array_item_exact (value : KernelAst) (meaning : TemplateAst.Value)
    (original : AstKernelMeaning value meaning) (depth position : Std.Usize) (output : NativeJsonBuild)
    (depthBound : depth.val ≤ 6) (children : JsonChildren depth.val) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_array_item value depth position output ⦃ actual =>
      nativeJsonEffect actual = arrayItem meaning depth.val position.val (nativeJsonBuild output) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_array_item
  by_cases separator : 0 < position.val
  · have nativeSeparator : position > 0#usize := by scalar_tac
    simp only [nativeSeparator, ↓reduceIte]
    step as ⟨source, sourceMeaning⟩
    step with native_schema_copy_bytes source as ⟨comma, commaMeaning⟩
    step with native_json_push_exact output (.Raw comma) as ⟨separated, separatedMeaning⟩
    rcases separated with ⟨result, current⟩
    cases result with
    | Err error =>
        simp [arrayItem, separator, ← separatedMeaning, nativeJsonEffect, nativeTemplateResult,
          nativeNamedJson, bytes, commaMeaning, sourceMeaning]
    | Ok unit =>
        simp only [bind_tc_ok]
        step as ⟨nextDepth, nextDepthMeaning⟩
        apply spec_mono (children value meaning original none nextDepth current nextDepthMeaning)
        intro actual exact
        simpa [arrayItem, separator, ← separatedMeaning, nativeJsonEffect, nativeTemplateResult,
          nativeNamedJson, bytes, commaMeaning, sourceMeaning, nativeEchoTokens, nextDepthMeaning] using exact
  · have nativeNoSeparator : ¬position > 0#usize := by scalar_tac
    simp only [nativeNoSeparator, ↓reduceIte]
    step as ⟨nextDepth, nextDepthMeaning⟩
    apply spec_mono (children value meaning original none nextDepth output nextDepthMeaning)
    intro actual exact
    simpa [arrayItem, separator, nativeEchoTokens, nextDepthMeaning] using exact

/-- The actual loop emits its closing bracket at termination. The model
fold is therefore followed by that exact final push, including its refusal. -/
theorem array_suffix_exact (items : Slice KernelAst) (meanings : List TemplateAst.Value)
    (original : AstKernelValuesMeaning items.val meanings) (depth : Std.Usize) (output : NativeJsonBuild)
    (position : Std.Usize) (positionBound : position.val ≤ items.val.length)
    (depthBound : depth.val ≤ 6) (children : JsonChildren depth.val) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_array_loop items depth output position ⦃ actual =>
      nativeJsonEffect actual = do
        let folded ← arrayFrom meanings depth.val position.val (nativeJsonBuild output)
        pushJson folded (.raw [93]) ⦄ := by
  have relation := kernel_values_full_relation original
  have lengths : items.val.length = meanings.length := List.Forall₂.length_eq relation
  generalize remaining : items.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing output position with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_array_loop
      by_cases inside : position.val < items.val.length
      · have nativeInside : position < items.len := by scalar_tac
        have modelInside : position.val < meanings.length := by omega
        simp only [nativeInside, ↓reduceIte]
        step with Slice.index_usize_spec items position inside as ⟨child, childAt⟩
        have childMeaning : AstKernelMeaning child meanings[position.val] := by
          have atPosition := original_relation_lookup relation position.val
          simpa [List.getElem?_eq_getElem inside, List.getElem?_eq_getElem modelInside, childAt] using atPosition
        step with array_item_exact child meanings[position.val] childMeaning depth position output depthBound children
          as ⟨itemResult, itemMeaning⟩
        rcases itemResult with ⟨result, current⟩
        cases result with
        | Err error =>
            simp [array_from_step meanings depth.val position.val (nativeJsonBuild output) modelInside,
              ← itemMeaning, nativeJsonEffect, nativeTemplateResult]
        | Ok unit =>
            simp only [bind_tc_ok]
            step as ⟨nextPosition, nextPositionMeaning⟩
            apply spec_mono (ih _ (by omega) current nextPosition (by omega) rfl)
            intro actual exact
            simpa [array_from_step meanings depth.val position.val (nativeJsonBuild output) modelInside,
              ← itemMeaning, nativeJsonEffect, nativeTemplateResult, nextPositionMeaning] using exact
      · have nativeEnded : ¬position < items.len := by scalar_tac
        have modelEnded : meanings.length ≤ position.val := by omega
        simp only [nativeEnded, ↓reduceIte]
        step as ⟨source, sourceMeaning⟩
        step with native_schema_copy_bytes source as ⟨closing, closingMeaning⟩
        apply spec_mono (native_json_push_exact output (.Raw closing))
        intro actual exact
        simpa [array_from_done meanings depth.val position.val (nativeJsonBuild output) modelEnded,
          nativeNamedJson, bytes, closingMeaning, sourceMeaning] using exact

theorem array_exact (items : Slice KernelAst) (meanings : List TemplateAst.Value)
    (original : AstKernelValuesMeaning items.val meanings) (depth : Std.Usize) (output : NativeJsonBuild)
    (depthBound : depth.val ≤ 6) (children : JsonChildren depth.val) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_array items depth output ⦃ actual =>
      nativeJsonEffect actual = jsonArray meanings depth.val (nativeJsonBuild output) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_array
  have lengths : items.val.length = meanings.length := List.Forall₂.length_eq (kernel_values_full_relation original)
  by_cases admitted : 0 < items.val.length ∧ items.val.length ≤ 16
  · have nonempty : items.val.length ≠ 0 := by omega
    have nativeBound : ¬items.len > 16#usize := by scalar_tac
    have modelCount : 0 < meanings.length ∧ meanings.length ≤ 16 := by omega
    simp only [core.slice.Slice.is_empty, bind_tc_ok, Slice.len_val, Slice.length,
      nonempty, decide_false, Bool.false_eq_true, nativeBound, ↓reduceIte]
    step as ⟨source, sourceMeaning⟩
    step with native_schema_copy_bytes source as ⟨opening, openingMeaning⟩
    step with native_json_push_exact output (.Raw opening) as ⟨opened, openedMeaning⟩
    rcases opened with ⟨result, current⟩
    cases result with
    | Err error =>
        simp [jsonArray, modelCount, ← openedMeaning, nativeJsonEffect, nativeTemplateResult,
          nativeNamedJson, bytes, openingMeaning, sourceMeaning]
    | Ok unit =>
        simp only [bind_tc_ok]
        apply spec_mono (array_suffix_exact items meanings original depth current 0#usize (by simp) depthBound children)
        intro actual exact
        simpa [jsonArray, modelCount, ← openedMeaning, nativeJsonEffect, nativeTemplateResult,
          nativeNamedJson, bytes, openingMeaning, sourceMeaning] using exact
  · have modelCount : ¬(0 < meanings.length ∧ meanings.length ≤ 16) := by omega
    by_cases empty : items.val.length = 0
    · have originalEmpty : items.val = [] := List.length_eq_zero_iff.mp empty
      simp [core.slice.Slice.is_empty, originalEmpty, jsonArray, modelCount, nativeJsonEffect,
        nativeTemplateResult, nativeTemplateError]
    · have large : 16 < items.val.length := by omega
      have nativeLarge : items.len > 16#usize := by scalar_tac
      simp [core.slice.Slice.is_empty, empty, nativeLarge, jsonArray, modelCount, nativeJsonEffect,
        nativeTemplateResult, nativeTemplateError]

end Auths.Product.NativeCompiler.EmitterInternal
