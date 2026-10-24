import Auths.Product.NativeCompilerPlanInputs
import Auths.Product.NativeCompilerAst

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

private theorem native_named_body_error_map (meaning : TemplateAst.Body) (declared : Option NativeEcho)
    (compiled : core.result.Result NativeNamedTemplate NativeTemplateError)
    (exact : nativeTemplateResult nativeTemplate compiled = TemplateAst.compileBody meaning (declared.map nativeEchoMeaning)) :
    AuthsNativeRecipe.core.result.Result.map_err
      AuthsNativeRecipe.recipe.lower.Lowering.named_body.closure.Insts.CoreOpsFunctionFnOnceTupleTemplateErrorGatewayRecipeError
      compiled () ⦃ actual => nativeRecipeResult nativeTemplate actual =
        (TemplateAst.compileBody meaning (declared.map nativeEchoMeaning)).mapError
          (RecipePlanModel.templateError planErrors) ⦄ := by
  cases compiled with
  | Ok output =>
      simp [AuthsNativeRecipe.core.result.Result.map_err, core.result.Result.map_err,
        ← exact, nativeTemplateResult, nativeRecipeResult]
  | Err error =>
      cases error <;> simp [AuthsNativeRecipe.core.result.Result.map_err, core.result.Result.map_err,
        AuthsNativeRecipe.recipe.lower.Lowering.named_body.closure.Insts.CoreOpsFunctionFnOnceTupleTemplateErrorGatewayRecipeError,
        AuthsNativeRecipe.recipe.lower.Lowering.named_body.closure.Insts.CoreOpsFunctionFnOnceTupleTemplateErrorGatewayRecipeError.call_once,
        ← exact, nativeTemplateResult, nativeTemplateError, nativeRecipeResult,
        RecipePlanModel.templateError, planErrors]

/-- The actual original typed-source adapter feeds the actual body compiler.
The complete original-meaning relation and string representability contain
neither accepted grammar nor a desired emitted template. -/
@[step] theorem native_named_body_exact (body : SourceBody) (meaning : TemplateAst.Body)
    (original : BodySourceMeaning body meaning) (bounded : BodyBounds body)
    (echo : Option NativeEchoSource) (echoBounds : ∀ source, echo = some source → NativeEchoFits source) :
    AuthsNativeRecipe.recipe.lower.Lowering.named_body body echo ⦃ actual =>
      nativeRecipeResult nativeTemplate actual = RecipePlanModel.namedBody planErrors meaning (echo.map planEchoSource) ⦄ := by
  unfold AuthsNativeRecipe.recipe.lower.Lowering.named_body
  step with native_body_has_original_meaning body bounded as ⟨copied, copiedMeaning, sourceMeaning, kernelMeaning⟩
  have same : copiedMeaning = meaning := body_source_meaning_unique sourceMeaning original
  subst copiedMeaning
  cases echo with
  | none =>
      simp only [AuthsNativeRecipe.core.option.Option.as_ref, core.option.Option.as_ref, bind_tc_ok]
      step with native_compile_body_exact copied meaning kernelMeaning none as ⟨compiled, compiledMeaning⟩
      apply spec_mono (native_named_body_error_map meaning none compiled compiledMeaning)
      intro actual exact
      simpa [RecipePlanModel.namedBody] using exact
  | some source =>
      step with native_echo_input_exact source (echoBounds source rfl) as ⟨declared, declaredMeaning⟩
      cases declared with
      | Err error =>
          simp [core.result.Result.Insts.CoreOpsTry.branch,
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame, nativeRecipeResult, RecipePlanModel.namedBody,
            plan_original_echo, ← declaredMeaning, nativeEchoResult]
      | Ok declared =>
          simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
            AuthsNativeRecipe.core.option.Option.as_ref, core.option.Option.as_ref]
          step with native_compile_body_exact copied meaning kernelMeaning (some declared) as ⟨compiled, compiledMeaning⟩
          apply spec_mono (native_named_body_error_map meaning (some declared) compiled compiledMeaning)
          intro actual exact
          simpa [RecipePlanModel.namedBody, plan_original_echo, ← declaredMeaning, nativeEchoResult] using exact

@[step] theorem native_named_write_body_exact (source : NativeRecipeSource) (meaning : TemplateAst.Body)
    (original : BodySourceMeaning source.write.body meaning) (bounded : BodyBounds source.write.body)
    (echoBounds : ∀ echo, source.echo = some echo → NativeEchoFits echo.write) :
    AuthsNativeRecipe.recipe.lower.named_write_body source ⦃ actual =>
      nativeRecipeResult nativeTemplate actual = RecipePlanModel.namedBody planErrors meaning
        ((planSource source meaning).echo) ⦄ := by
  unfold AuthsNativeRecipe.recipe.lower.named_write_body
  cases placement : source.echo with
  | none =>
      apply spec_mono (native_named_body_exact source.write.body meaning original bounded none (by simp))
      intro actual exact
      simpa [planSource, placement] using exact
  | some echo =>
      apply spec_mono (native_named_body_exact source.write.body meaning original bounded (some echo.write)
        (by intro other same; cases same; exact echoBounds echo placement))
      intro actual exact
      simpa [planSource, placement] using exact

end Auths.Product.NativeCompiler.Refinement
