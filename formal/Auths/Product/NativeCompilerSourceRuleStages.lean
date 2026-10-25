import Auths.Product.RecipeRuleStages
import Auths.Product.NativeCompilerWriteAdmission
import Auths.Product.NativeCompilerResponseGroup
import Auths.Product.NativeCompilerFactGroup
import Auths.Product.NativeCompilerHeaderGuardGroup

open Aeneas Aeneas.Std Result

namespace Auths.Product.NativeCompiler

structure SourceRulesFit (source : NativeRecipeSource) : Prop where
  write : WriteGroupFits source
  response : ResponseGroupFits source
  facts : FactGroupFits source
  headers : HeaderGuardGroupFits source
  scope : ∀ scope, source.account_scope = some scope → TextFits scope.header ∧ TextFits scope.field
  bounds : ∀ bounds, source.bounds = some bounds → BoundFieldsFit bounds

/-- Transparent source suffixes call the unchanged translated functions.
The explicit original field map is the map read by the final native use scan;
it is not a caller-selected reduced table or another validation callback. -/
def nativeSourceBoundTail (input : AuthsNativeRecipe.recipe.validate.Rules) (source : NativeRecipeSource)
    (fields : NativeRuleMap) : Result (core.result.Result Unit AuthsNativeRecipe.recipe.GatewayRecipeError) := do
  let (checked, next) ← AuthsNativeRecipe.recipe.validate.validate_bound_rules input source
  let flow ← core.result.Result.Insts.CoreOpsTry.branch checked
  match flow with
  | .Break residual =>
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
        Unit (core.convert.FromSame AuthsNativeRecipe.recipe.GatewayRecipeError) residual
  | .Continue _ =>
      let used ← AuthsNativeRecipe.recipe.validate.all_fields_consumed fields next.consumed.all
      if used then ok (.Ok ()) else ok (.Err .UnsafeTemplate)

def nativeSourceHeaderTail (input : AuthsNativeRecipe.recipe.validate.Rules) (source : NativeRecipeSource)
    (fields : NativeRuleMap) : Result (core.result.Result Unit AuthsNativeRecipe.recipe.GatewayRecipeError) := do
  let checked ← AuthsNativeRecipe.recipe.validate.validate_header_guard_rules source
  let flow ← core.result.Result.Insts.CoreOpsTry.branch checked
  match flow with
  | .Break residual =>
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
        Unit (core.convert.FromSame AuthsNativeRecipe.recipe.GatewayRecipeError) residual
  | .Continue _ => nativeSourceBoundTail input source fields

def nativeSourceFactTail (input : AuthsNativeRecipe.recipe.validate.Rules) (source : NativeRecipeSource)
    (fields : NativeRuleMap) : Result (core.result.Result Unit AuthsNativeRecipe.recipe.GatewayRecipeError) := do
  let (checked, next) ← AuthsNativeRecipe.recipe.validate.validate_fact_rules input source
  let flow ← core.result.Result.Insts.CoreOpsTry.branch checked
  match flow with
  | .Break residual =>
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
        Unit (core.convert.FromSame AuthsNativeRecipe.recipe.GatewayRecipeError) residual
  | .Continue _ => nativeSourceHeaderTail next source fields

def nativeSourceResponseTail (input : AuthsNativeRecipe.recipe.validate.Rules) (source : NativeRecipeSource)
    (fields : NativeRuleMap) : Result (core.result.Result Unit AuthsNativeRecipe.recipe.GatewayRecipeError) := do
  let (checked, next) ← AuthsNativeRecipe.recipe.validate.validate_response_rules input source
  let flow ← core.result.Result.Insts.CoreOpsTry.branch checked
  match flow with
  | .Break residual =>
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
        Unit (core.convert.FromSame AuthsNativeRecipe.recipe.GatewayRecipeError) residual
  | .Continue _ => nativeSourceFactTail next source fields

def nativeSourceAllStages (source : NativeRecipeSource) (fields : NativeRuleMap) :
    Result (core.result.Result Unit AuthsNativeRecipe.recipe.GatewayRecipeError) := do
  let consumed ← AuthsNativeRecipe.recipe.validate.Consumption.Insts.CoreDefaultDefault.default
  let (checked, next) ← AuthsNativeRecipe.recipe.validate.validate_write_rules ⟨fields, consumed⟩ source
  let flow ← core.result.Result.Insts.CoreOpsTry.branch checked
  match flow with
  | .Break residual =>
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
        Unit (core.convert.FromSame AuthsNativeRecipe.recipe.GatewayRecipeError) residual
  | .Continue _ => nativeSourceResponseTail next source fields

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement

theorem native_source_rules_use_original_stages (source : NativeRecipeSource) (fields : NativeRuleMap) :
    AuthsNativeRecipe.recipe.validate.validate_source_rules source fields = nativeSourceAllStages source fields := by
  simp [AuthsNativeRecipe.recipe.validate.validate_source_rules, nativeSourceAllStages,
    nativeSourceResponseTail, nativeSourceFactTail, nativeSourceHeaderTail, nativeSourceBoundTail, bind_assoc]

end Auths.Product.NativeCompiler.Refinement
