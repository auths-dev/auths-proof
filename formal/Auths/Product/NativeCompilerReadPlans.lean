import Auths.Product.NativeCompilerPaths
import Auths.Product.NativeCompilerPlanClones
import Auths.Product.NativeCompilerReadModel

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

abbrev NativeLowering := AuthsNativeRecipe.recipe.lower.Lowering
abbrev NativeGatewayError := AuthsNativeRecipe.recipe.GatewayRecipeError
abbrev NativeActionRead := AuthsNativeRecipe.auths_gateway_kernel.construct.ActionReadPlan

def nativeRecipeResult {T V : Type} (view : T → V) :
    core.result.Result T NativeGatewayError → Except NativeGatewayError V
  | .Ok output => .ok (view output)
  | .Err error => .error error

def nativeHeader (input : NativeHeader) : RequestConstruction.Header :=
  ⟨bytes input.name, bytes input.value⟩

def nativeScopePlan (input : NativeScopePlan) : RequestConstruction.ScopePlan :=
  ⟨bytes input.name, input.field.val⟩

def nativeHeaders (input : NativeHeaderPlan) : RequestConstruction.HeaderPlan :=
  ⟨input.versions.val.map nativeHeader, input.account_scope.map nativeScopePlan⟩

def nativeActionRead (input : NativeActionRead) : RequestConstruction.ReadPlan :=
  ⟨bytes input.origin, input.path.val.map nativeSegment, nativeHeaders input.headers⟩

def nativeCredentialPlan (input : NativeCredentialPlan) : RequestConstruction.CredentialPlan :=
  ⟨kernelWriteMethod input.method, bytes input.origin, input.path.val.map bytes,
    input.versions.val.map nativeHeader⟩

def loweringNames (input : NativeLowering) : List (List Nat) := input.field_names.val.map bytes

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

@[step] theorem native_action_path_exact (lowering : NativeLowering) (path : Slice NativePathSource)
    (bounded : ∀ segment ∈ path.val, NativePathFits segment) :
    AuthsNativeRecipe.recipe.lower.Lowering.path lowering path ⦃ actual =>
      nativeRecipeResult (fun built => built.val.map nativeSegment) actual =
        (PathCompiler.lowerPath (loweringNames lowering) (path.val.map originalPathSegment)).mapError
          (fun _ => .InvalidSource) ⦄ := by
  unfold AuthsNativeRecipe.recipe.lower.Lowering.path
  step with native_path_input_exact path bounded as ⟨converted, convertedMeaning⟩
  step with native_lower_path_exact (AuthsNativeRecipe.alloc.vec.Vec.deref lowering.field_names)
    (AuthsNativeRecipe.alloc.vec.Vec.deref converted) as ⟨compiled, compiledMeaning⟩
  cases compiled <;>
    simp [AuthsNativeRecipe.core.result.Result.map_err, _root_.core.result.Result.map_err,
      AuthsNativeRecipe.recipe.lower.Lowering.path.closure.Insts.CoreOpsFunctionFnOnceTupleConstructErrorGatewayRecipeError,
      AuthsNativeRecipe.recipe.lower.Lowering.path.closure.Insts.CoreOpsFunctionFnOnceTupleConstructErrorGatewayRecipeError.call_once,
      nativeRecipeResult, ← compiledMeaning, nativeConstructResult, loweringNames,
      nativeNameColumn, nativePath, native_deref_contents, convertedMeaning]

@[step] theorem native_action_read_exact (lowering : NativeLowering) (path : Slice NativePathSource)
    (bounded : ∀ segment ∈ path.val, NativePathFits segment) :
    AuthsNativeRecipe.recipe.lower.Lowering.action_read lowering path ⦃ actual =>
      nativeRecipeResult nativeActionRead actual =
        ReadModel.action NativeGatewayError.InvalidSource (bytes lowering.origin) (nativeHeaders lowering.headers)
          (loweringNames lowering) (path.val.map originalPathSegment) ⦄ := by
  unfold AuthsNativeRecipe.recipe.lower.Lowering.action_read
  step with native_vector_clone_exact core.clone.CloneU8 lowering.origin (by intro byte _; rfl)
    as ⟨origin, originMeaning⟩
  step with native_action_path_exact lowering path bounded as ⟨compiled, compiledMeaning⟩
  cases compiled with
  | Err error =>
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, nativeRecipeResult, ReadModel.action, ← compiledMeaning]
  | Ok compiled =>
      simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      step with native_header_plan_clone_exact lowering.headers as ⟨headers, headersMeaning⟩
      simp [nativeRecipeResult, nativeActionRead, ReadModel.action, ← compiledMeaning,
        originMeaning, headersMeaning]

@[step] theorem native_credential_read_exact (lowering : NativeLowering)
    (method : AuthsNativeRecipe.auths_gateway_kernel.construct.RequestMethod)
    (path : Slice NativePathSource)
    (bounded : ∀ segment ∈ path.val, NativePathFits segment) :
    AuthsNativeRecipe.recipe.lower.Lowering.credential_read lowering method path ⦃ actual =>
      nativeRecipeResult nativeCredentialPlan actual =
        ReadModel.credential NativeGatewayError.InvalidSource (kernelWriteMethod method)
          (bytes lowering.origin) (lowering.headers.versions.val.map nativeHeader)
          (path.val.map originalPathSegment) ⦄ := by
  unfold AuthsNativeRecipe.recipe.lower.Lowering.credential_read
  step with native_path_input_exact path bounded as ⟨converted, convertedMeaning⟩
  step with native_lower_fixed_path_exact (AuthsNativeRecipe.alloc.vec.Vec.deref converted)
    as ⟨compiled, compiledMeaning⟩
  cases compiled with
  | Err error =>
      simp [AuthsNativeRecipe.core.result.Result.map_err, _root_.core.result.Result.map_err,
        AuthsNativeRecipe.recipe.lower.Lowering.credential_read.closure.Insts.CoreOpsFunctionFnOnceTupleConstructErrorGatewayRecipeError,
        AuthsNativeRecipe.recipe.lower.Lowering.credential_read.closure.Insts.CoreOpsFunctionFnOnceTupleConstructErrorGatewayRecipeError.call_once,
        core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, nativeRecipeResult, ReadModel.credential, ← compiledMeaning,
        nativeConstructResult, nativePath, native_deref_contents, convertedMeaning]
  | Ok compiled =>
      simp only [AuthsNativeRecipe.core.result.Result.map_err, _root_.core.result.Result.map_err,
        core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      step with native_vector_clone_exact core.clone.CloneU8 lowering.origin (by intro byte _; rfl)
        as ⟨origin, originMeaning⟩
      step with native_vector_clone_exact AuthsNativeRecipe.auths_gateway_kernel.construct.Header.Insts.CoreCloneClone
        lowering.headers.versions (by intro header _; exact native_header_clone_result header)
        as ⟨versions, versionsMeaning⟩
      simp [nativeRecipeResult, nativeCredentialPlan, ReadModel.credential, ← compiledMeaning,
        nativeConstructResult, nativePath, native_deref_contents, convertedMeaning,
        originMeaning, versionsMeaning]

theorem native_action_read_retains_original_columns (lowering : NativeLowering) (path : Slice NativePathSource)
    (bounded : ∀ segment ∈ path.val, NativePathFits segment) :
    AuthsNativeRecipe.recipe.lower.Lowering.action_read lowering path ⦃ actual =>
      ∀ plan, actual = .Ok plan →
        bytes plan.origin = bytes lowering.origin ∧ nativeHeaders plan.headers = nativeHeaders lowering.headers ∧
        List.Forall₂ (PathCompiler.SegmentMeaning (loweringNames lowering))
          (path.val.map originalPathSegment) (plan.path.val.map nativeSegment) ⦄ := by
  apply spec_mono (native_action_read_exact lowering path bounded)
  intro actual exact plan accepted
  rw [accepted] at exact
  have meaning := ReadModel.action_success_columns NativeGatewayError.InvalidSource
    (bytes lowering.origin) (nativeHeaders lowering.headers) (loweringNames lowering)
    (path.val.map originalPathSegment) (nativeActionRead plan)
    (by simpa only [nativeRecipeResult] using exact.symm)
  exact meaning

theorem native_credential_read_retains_fixed_columns (lowering : NativeLowering)
    (method : AuthsNativeRecipe.auths_gateway_kernel.construct.RequestMethod)
    (path : Slice NativePathSource)
    (bounded : ∀ segment ∈ path.val, NativePathFits segment) :
    AuthsNativeRecipe.recipe.lower.Lowering.credential_read lowering method path ⦃ actual =>
      ∀ plan, actual = .Ok plan →
        kernelWriteMethod plan.method = kernelWriteMethod method ∧ bytes plan.origin = bytes lowering.origin ∧
        plan.versions.val.map nativeHeader = lowering.headers.versions.val.map nativeHeader ∧
        PathCompiler.lowerFixedPath (path.val.map originalPathSegment) = .ok (plan.path.val.map bytes) ⦄ := by
  apply spec_mono (native_credential_read_exact lowering method path bounded)
  intro actual exact plan accepted
  rw [accepted] at exact
  have meaning := ReadModel.credential_success_columns NativeGatewayError.InvalidSource
    (kernelWriteMethod method) (bytes lowering.origin) (lowering.headers.versions.val.map nativeHeader)
    (path.val.map originalPathSegment) (nativeCredentialPlan plan)
    (by simpa only [nativeRecipeResult] using exact.symm)
  exact meaning

end Auths.Product.NativeCompiler.Refinement
