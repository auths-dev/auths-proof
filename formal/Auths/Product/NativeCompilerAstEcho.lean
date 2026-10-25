import Auths.Product.NativeCompilerMemberTargets
import Auths.Product.TemplateAstTraversal

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def nativeEchoTokens (echo : Option (Slice (NativeVec Std.U8))) : Option (List (List Nat)) :=
  echo.map nativeTokens
def nativeOptionalTarget (target : Option NativeTarget) : Option TemplateMembers.Target := target.map nativeTarget

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open TemplateAst
set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

@[step] theorem native_ast_target_exact (keys : Slice NativeKey) (echo : Option (Slice (NativeVec Std.U8))) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_target keys echo ⦃ actual =>
      nativeTemplateResult nativeOptionalTarget actual = objectTarget (nativeKeyColumn keys) (nativeEchoTokens echo) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_target
  cases echo with
  | none => rfl
  | some tokens =>
      step with native_json_echo_target_exact keys tokens as ⟨target, targetMeaning⟩
      cases target with
      | Err error =>
          step with native_member_error_exact error as ⟨mapped, mappedMeaning⟩
          simp [objectTarget, nativeEchoTokens, nativeTemplateResult, nativeOptionalTarget,
            ← targetMeaning, nativeMemberResult, mappedMeaning]
      | Ok target =>
          simp [objectTarget, nativeEchoTokens, nativeTemplateResult, nativeOptionalTarget,
            ← targetMeaning, nativeMemberResult]

@[step] theorem native_ast_insertion_exact (target : Option NativeTarget)
    (echo : Option (Slice (NativeVec Std.U8))) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_insertion target echo ⦃ actual =>
      nativeTemplateResult (Option.map schemaSliceBytes) actual =
        objectInsertion (nativeOptionalTarget target) (nativeEchoTokens echo) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_insertion
  cases target with
  | none => cases echo <;> rfl
  | some target =>
      cases target with
      | Descend index => cases echo <;> rfl
      | Insert =>
          cases echo with
          | none => rfl
          | some tokens =>
              cases original : tokens.val with
              | nil => simp [core.slice.Slice.is_empty, original, nativeTemplateResult,
                  nativeTemplateError, objectInsertion, nativeOptionalTarget, nativeTarget,
                  nativeEchoTokens, nativeTokens]
              | cons first rest =>
                  have positive : 0 < tokens.val.length := by simp [original]
                  simp only [core.slice.Slice.is_empty, original, List.isEmpty_cons,
                    Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
                  step with Slice.index_usize_spec tokens 0#usize positive as ⟨selected, selectedAt⟩
                  have same : selected = first := by simpa only [original] using selectedAt
                  simp [AuthsNativeRecipe.alloc.vec.Vec.as_slice, nativeTemplateResult,
                    objectInsertion, nativeOptionalTarget, nativeTarget, nativeEchoTokens,
                    nativeTokens, original, same, schemaSliceBytes, bytes, native_deref_contents]

@[step] theorem native_ast_child_echo_exact (target : Option NativeTarget)
    (echo : Option (Slice (NativeVec Std.U8))) (index : Std.Usize) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_child_echo target echo index ⦃ actual =>
      nativeTemplateResult nativeEchoTokens actual =
        objectChildEcho (nativeOptionalTarget target) (nativeEchoTokens echo) index.val ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_child_echo
  cases target with
  | none => cases echo <;> rfl
  | some target =>
      cases target with
      | Insert => cases echo <;> rfl
      | Descend selected =>
          cases echo with
          | none => rfl
          | some tokens =>
              by_cases same : selected = index
              · subst selected
                by_cases empty : tokens.val.length = 0
                · have original : tokens.val = [] := List.length_eq_zero_iff.mp empty
                  simp [core.slice.Slice.get, core.slice.index.SliceIndexRangeFromUsizeSlice,
                    core.slice.index.SliceIndexRangeFromUsizeSlice.get, original,
                    nativeTemplateResult, nativeTemplateError, nativeEchoTokens,
                    nativeOptionalTarget, nativeTarget, nativeTokens, objectChildEcho]
                · have positive : 0 < tokens.val.length := by omega
                  have nativeBound : (1#usize).val ≤ tokens.length := by simpa using positive
                  simp [core.slice.Slice.get, core.slice.index.SliceIndexRangeFromUsizeSlice,
                    core.slice.index.SliceIndexRangeFromUsizeSlice.get, nativeBound,
                    nativeTemplateResult, nativeEchoTokens, nativeOptionalTarget, nativeTarget,
                    nativeTokens, objectChildEcho, List.drop_map, positive]
              · have different : selected.val ≠ index.val := by
                  intro equal
                  exact same (UScalar.eq_of_val_eq equal)
                simp [same, different, nativeTemplateResult, nativeEchoTokens,
                  nativeOptionalTarget, nativeTarget, objectChildEcho]

end Auths.Product.NativeCompiler.Refinement
