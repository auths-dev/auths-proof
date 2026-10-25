import Auths.Product.NativeCompilerBodyFields
import Auths.Product.NativeCompilerAstMeaning
import Auths.Product.RecipeBodyCounters

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

abbrev NativeNodeResult := core.result.Result Unit AuthsNativeRecipe.recipe.GatewayRecipeError ×
  AuthsNativeRecipe.recipe.validate.Rules × Std.Usize

def NodeMeaning (before : AuthsNativeRecipe.recipe.validate.Rules)
    (expected : RecipeRuleAdmission.NodeOutcome) (actual : NativeNodeResult) : Prop :=
  ClaimMeaning before expected.1 (actual.1, actual.2.1) ∧
    actual.2.2.val = expected.2 ∧ RuleStateDomain actual.2.1 ∧
    actual.2.1.consumed.binds = before.consumed.binds

def BodyMeaning (before : AuthsNativeRecipe.recipe.validate.Rules)
    (expected : RecipeConsumption.Outcome)
    (actual : core.result.Result Unit AuthsNativeRecipe.recipe.GatewayRecipeError ×
      AuthsNativeRecipe.recipe.validate.Rules) : Prop :=
  ClaimMeaning before expected actual ∧ RuleStateDomain actual.2 ∧
    actual.2.consumed.binds = before.consumed.binds

/-- This is the actual charge/map-error expression in value_expr. It names
the selected native closure and kernel; no node-admission decision is supplied
by a foreign model or an expected compiler result. -/
def nativeBodyCharge (nodes depth : Std.Usize) :
    Result (core.result.Result Std.Usize AuthsNativeRecipe.recipe.GatewayRecipeError) := do
  let charged ← AuthsNativeRecipe.auths_gateway_kernel.template_ast.charge_node nodes depth
  AuthsNativeRecipe.core.result.Result.map_err
    AuthsNativeRecipe.recipe.validate.Rules.value_expr.closure.Insts.CoreOpsFunctionFnOnceTupleTemplateErrorGatewayRecipeError
    charged ()

def bodyChargeOutcome : core.result.Result Std.Usize AuthsNativeRecipe.recipe.GatewayRecipeError →
    Except AuthsNativeRecipe.recipe.GatewayRecipeError Nat
  | .Ok value => .ok value.val
  | .Err error => .error error

theorem body_source_values_count {inputs : List SourceAst} {models : List TemplateAst.Value}
    (meaning : AstSourceValuesMeaning inputs models) : inputs.length = models.length := by
  induction meaning <;> simp_all

theorem body_source_members_count {inputs : List (String × SourceAst)}
    {models : List (List Nat × TemplateAst.Value)} (meaning : AstSourceMembersMeaning inputs models) :
    inputs.length = models.length := by
  induction meaning <;> simp_all

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 12000000
set_option maxRecDepth 4096

/-- The selected source constant is computed by its actual checked shift and
subtraction. It is not replaced by an opaque handwritten Auths constant. -/
@[step] theorem native_safe_integer_constant_exact :
    AuthsNativeRecipe.recipe.validate.MAX_SAFE_INTEGER ⦃ actual => actual.val = 9007199254740991 ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.MAX_SAFE_INTEGER
  decide

@[step] theorem native_body_unsigned_abs_exact (value : Std.I64) :
    AuthsNativeRecipe.core.num.I64.unsigned_abs value ⦃ actual => actual.val = value.val.natAbs ⦄ := by
  simp [AuthsNativeRecipe.core.num.I64.unsigned_abs, spec_ok]

@[step] theorem native_recipe_field_name_exact (name : Str) :
    AuthsNativeRecipe.recipe.valid_field_name name ⦃ actual =>
      actual = OperationIdentity.validToken (schemaSliceBytes name) 64 ⦄ := by
  unfold AuthsNativeRecipe.recipe.valid_field_name
    AuthsNativeRecipe.core.str.Str.as_bytes _root_.core.str.Str.as_bytes
  simp only [bind_tc_ok]
  exact native_schema_token_exact name 64#usize

@[step] theorem native_body_charge_exact (nodes depth : Std.Usize) :
    nativeBodyCharge nodes depth ⦃ actual =>
      bodyChargeOutcome actual = (TemplateAst.chargeNode nodes.val depth.val).mapError
        (fun _ => AuthsNativeRecipe.recipe.GatewayRecipeError.UnsafeTemplate) ⦄ := by
  unfold nativeBodyCharge
  step with native_node_charge_exact nodes depth as ⟨charged, meaning⟩
  cases charged <;>
    simp [AuthsNativeRecipe.core.result.Result.map_err, _root_.core.result.Result.map_err,
      AuthsNativeRecipe.recipe.validate.Rules.value_expr.closure.Insts.CoreOpsFunctionFnOnceTupleTemplateErrorGatewayRecipeError,
      AuthsNativeRecipe.recipe.validate.Rules.value_expr.closure.Insts.CoreOpsFunctionFnOnceTupleTemplateErrorGatewayRecipeError.call_once,
      bodyChargeOutcome, ← meaning, nativeTemplateResult, Except.mapError]

theorem node_meaning_preserves_counter (before : AuthsNativeRecipe.recipe.validate.Rules)
    (fuel : Nat) (expression : TemplateAst.Value) (depth nodes : Std.Usize) (actual : NativeNodeResult)
    (meaning : NodeMeaning before (RecipeRuleAdmission.value fuel expression depth.val nodes.val
      (consumptionState before.consumed) (nativeRuleMapMeaning before.fields)) actual) :
    nodes.val ≤ actual.2.2.val ∧ actual.2.2.val ≤ max 64 nodes.val := by
  rw [meaning.2.1]
  exact RecipeRuleAdmission.value_counter_frame _ _ _ _ _ _

end Auths.Product.NativeCompiler.Refinement
