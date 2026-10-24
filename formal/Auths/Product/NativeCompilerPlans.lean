import Auths.Product.NativeCompilerCheckedColumns

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 16000000
set_option maxRecDepth 4096

private theorem native_template_named_body (body : NativeNamedTemplate) :
    nativeNamedTemplate body = TemplateAst.namedBody (nativeTemplate body) := by cases body <;> rfl

/-- Complete actual lowering of every represented source record in the byte
representation domain. Body meaning retains original syntax and no admitted
source, lock, selected plan or successful helper is assumed. The private Rust
record's constructor must separately earn admission and its provenance. -/
@[step] theorem native_plans_exact (checked : NativeCheckedSource) (meaning : TemplateAst.Body)
    (original : BodySourceMeaning checked.source.write.body meaning) (bounded : PlanInputFits checked) :
    AuthsNativeRecipe.recipe.lower.plans checked ⦃ actual =>
      nativeRecipeResult nativePlans actual = RecipePlanModel.compile planErrors
        (nativeFieldsMeaning checked.field_specs) (textBytes checked.parsed_host)
        (planSource checked.source meaning) ⦄ := by
  unfold AuthsNativeRecipe.recipe.lower.plans
  step with native_checked_source_column checked as ⟨source, sourceMeaning⟩
  subst source
  step with native_checked_host_column checked bounded.host as ⟨parsedHost, hostMeaning⟩
  step with native_checked_field_column checked as ⟨fieldSlice, fieldSliceMeaning⟩
  step with native_field_column_copy fieldSlice as ⟨fieldSchemas, fieldSchemasMeaning⟩
  have schemas : nativeFieldColumn (AuthsNativeRecipe.alloc.vec.Vec.deref fieldSchemas) =
      nativeFieldsMeaning checked.field_specs := by
    simp [nativeFieldColumn, nativeFieldsMeaning, fieldSchemasMeaning, fieldSliceMeaning]
  step with native_named_write_body_exact checked.source meaning original bounded.body bounded.echo
    as ⟨named, namedMeaning⟩
  cases named with
  | Err error => simp [RecipePlanModel.compile, ← namedMeaning, nativeRecipeResult]
  | Ok body =>
      step with native_named_template_clone_exact body as ⟨bodyCopy, bodyCopyMeaning⟩
      step with native_path_input_exact (AuthsNativeRecipe.alloc.vec.Vec.deref checked.source.write.path)
        bounded.writePath as ⟨path, pathMeaning⟩
      step with native_header_input_exact checked.source bounded.headers as ⟨headers, versionsMeaning, scopeMeaning⟩
      rcases headers with ⟨versions, scope⟩
      step with native_write_method_exact checked.source.write.method as ⟨method, methodMeaning⟩
      step with borrow_text_exact checked.source.origin bounded.origin as ⟨origin, originMeaning⟩
      step with native_str_byte_column parsedHost as ⟨host, hostAt⟩
      step with native_optional_slice_column versions as ⟨versionSlices, versionSlicesMeaning⟩
      step with native_optional_reference_column scope as ⟨scopeRef, scopeRefMeaning⟩
      step with native_idempotency_header_choice_exact checked.source as ⟨idempotency, idempotencyMeaning⟩
      step with native_template_source_exact bodyCopy as ⟨namedSource, namedSourceMeaning⟩
      let request : NativeWriteSource := {
        method
        origin
        parsed_host := host
        path := AuthsNativeRecipe.alloc.vec.Vec.deref path
        versions := versionSlices
        scope := scopeRef
        idempotency_header := idempotency
        body := namedSource
      }
      have requestMeaning : nativeWriteSource request = RecipePlanModel.writeSource
          (planSource checked.source meaning) (textBytes checked.parsed_host) (nativeTemplate body) := by
        cases body <;> simp_all [request, nativeWriteSource, RecipePlanModel.writeSource,
          planSource, nativePath, loweredPathSegment, nativeVersions, loweredHeaders,
          schemaSliceBytes, nativeNameColumn, plan_path_full_lowering, native_template_named_body,
          nativeNamedTemplate, nativeTemplate, TemplateAst.namedBody, nativeJsonSource, nativeFormSource,
          plan_idempotency_choice, RecipePlanModel.hasIdempotencyHeader]
      step with native_compile_write_exact (AuthsNativeRecipe.alloc.vec.Vec.deref fieldSchemas) request
        as ⟨compiled, compiledMeaning⟩
      rw [schemas, requestMeaning] at compiledMeaning
      cases compiled with
      | Err error =>
          cases error <;> simp_all [RecipePlanModel.compile, ← namedMeaning, ← compiledMeaning,
            nativeRecipeResult, nativeCompileResult, nativeCompileError, nativeHeaderError,
            RecipePlanModel.writeError, planErrors]
          rename_i headerError
          cases headerError <;> simp_all [RecipePlanModel.compile, ← namedMeaning, ← compiledMeaning,
            nativeRecipeResult, nativeCompileResult, nativeCompileError, nativeHeaderError,
            RecipePlanModel.writeError, planErrors]
      | Ok compiled =>
          step with native_write_plan_clone_exact compiled.plan as ⟨write, writeMeaning⟩
          step with native_vector_clone_exact (AuthsNativeRecipe.core.clone.CloneallocvecVec core.clone.CloneU8)
            compiled.field_names (by
              intro name member
              exact native_vector_clone_result core.clone.CloneU8 name (by intro byte member; rfl))
            as ⟨names, namesMeaning⟩
          step with native_vector_clone_exact core.clone.CloneU8 write.origin (by intro byte member; rfl)
            as ⟨readOrigin, readOriginMeaning⟩
          step with native_header_plan_clone_exact write.headers as ⟨readHeaders, readHeadersMeaning⟩
          let lowering : NativeLowering := ⟨names, readOrigin, readHeaders⟩
          have readContextMeaning : planReadContext lowering = RecipePlanModel.readContext (nativeCompiledWrite compiled) := by
            simp [lowering, planReadContext, RecipePlanModel.readContext, nativeCompiledWrite,
              nativeWritePlan, loweringNames, namesMeaning, readOriginMeaning, readHeadersMeaning, writeMeaning]
          have probeSpec := native_probe_plan_exact lowering checked.source.credential bounded.credential
          have accountSpec := native_account_plan_exact lowering checked.source.credential bounded.credential
          have deniedSpec := native_denied_plan_exact lowering checked.source.credential bounded.credential
          cases observationAt : checked.source.observation <;>
            cases preEntryAt : checked.source.pre_entry <;>
            cases relativeAt : checked.source.relative_ceiling
          all_goals
            simp only [observationAt, preEntryAt, relativeAt]
            repeat' first
              | step with native_response_field_choice_exact
              | step with native_action_read_exact lowering _ (by
                  first
                  | simpa only [native_deref_contents] using bounded.observation _ (by assumption)
                  | simpa only [native_deref_contents] using bounded.preEntry _ (by assumption)
                  | simpa only [native_deref_contents] using bounded.relativeCeiling _ (by assumption))
              | step with probeSpec
              | step with accountSpec
              | step with deniedSpec
              | split
            all_goals
              simp_all [RecipePlanModel.compile, RecipePlanModel.remainingPlans,
                RecipePlanModel.optionalAction, RecipePlanModel.actionRead, RecipePlanModel.optionalCredential,
                RecipePlanModel.credentialRead, planSource, planReadContext, readContextMeaning,
                RecipePlanModel.readContext, planPath, plan_path_full_lowering, List.any_map,
                Function.comp_def, plan_response_choice, plan_original_guard, planGuard,
                nativeRecipeResult, nativePlans, nativeCompiledWrite, nativeWritePlan, nativeFieldsMeaning,
                nativeFieldColumn, fieldSchemasMeaning, fieldSliceMeaning, writeMeaning, nativeCompileResult,
                core.result.Result.Insts.CoreOpsTry.branch,
                core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                core.convert.FromSame, planErrors, lowering]

end Auths.Product.NativeCompiler.Refinement
