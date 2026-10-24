import Auths.Product.RecipeRulePlanPaths
import Auths.Product.NativeCompilerCompileAdmission

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

theorem original_guard_has_plan_path_view (guard : NativeGuardSource) :
    RecipeRuleAdmission.guardPlanView (ruleGuard guard) = planGuard guard := by
  simp [RecipeRuleAdmission.guardPlanView, ruleGuard, planGuard, planDeniedRead,
    planPath, List.map_map, Function.comp_def]

theorem original_source_has_plan_path_links (source : NativeConstructorSource) (body : TemplateAst.Body) :
    RecipeRuleAdmission.PlanPathLinks (ruleSource source body) (planSource source body) := by
  constructor
  · simp [planSource, ruleSource, planPath, List.map_map, Function.comp_def, rule_segment_has_original_plan_meaning]
  · simp [planSource, ruleSource, ruleObservation, planPath, List.map_map, Function.comp_def,
      rule_segment_has_original_plan_meaning]
  · simp [planSource, ruleSource, rulePreEntry, planPath, List.map_map, Function.comp_def,
      rule_segment_has_original_plan_meaning]
  · simp [planSource, ruleSource, ruleRelativeCeiling, planPath, List.map_map, Function.comp_def,
      rule_segment_has_original_plan_meaning]
  · rfl
  · simp [planSource, ruleSource, ruleScope, originalScope]
  · simp [planSource, ruleSource, plan_original_guard, original_guard_has_plan_path_view,
      Option.map_map, Function.comp_def]

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

set_option maxHeartbeats 24000000
set_option maxRecDepth 4096

/-- Actual constructor success earns original-schema write/read path and
header admission for the same complete lowering view. All group successes,
map associations, field layout and guard policy are earned from that caller.
No selected plan, actual lowering success or expected index is a premise. -/
theorem native_constructor_success_earns_lowering_paths (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (schema : ProfileSchema.Value) (schemaBounds : JsonBounds lock.command_schema)
    (schemaMeaning : JsonMeaning lock.command_schema schema) (body : TemplateAst.Body)
    (bodyMeaning : BodySourceMeaning source.write.body body) (fits : ConstructorSourceFits source)
    (checked : NativeConstructorRecord)
    (completed : AuthsNativeRecipe.recipe.validate.validate_source source lock canonical = ok (.Ok checked)) :
    checked.source = source ∧
      PathCompiler.PathAdmissible (FieldProjection.names (nativeFieldsMeaning checked.field_specs))
        ((planSource source body).path.map RecipePlanModel.pathSegment) ∧
      HeaderCompiler.HeaderAdmissible (FieldProjection.names (nativeFieldsMeaning checked.field_specs))
        (planSource source body).versions (planSource source body).scope ∧
      RecipePlanModel.ReadPathsAdmissible (FieldProjection.names (nativeFieldsMeaning checked.field_specs)) (planSource source body) := by
  have trace := native_constructor_success_earns_original_trace source lock canonical checked completed
  obtain ⟨original, fields, meaning, _, rules⟩ := native_constructor_success_earns_complete_rules source lock canonical checked
    schemaBounds schema schemaMeaning body bodyMeaning fits.rules completed
  have layout := (ProfileSchema.root_meaning_earns_complete_valid_layout schema (nativeFieldsMeaning checked.field_specs) original).2.1
  exact ⟨trace.originalSource, RecipeRuleAdmission.complete_rules_earn_plan_path_admission
    (nativeFieldsMeaning checked.field_specs) (nativeRuleMapMeaning fields) layout meaning
    (ruleSource source body) (planSource source body) (original_source_has_plan_path_links source body) rules⟩

/-- Useful actual whole-plan lowering from independent typed write/read
admission. The AST-to-named-body prefix remains explicit; no expected complete
plan, successful native write/read helper or returned native value is supplied.
General source admission must still earn the remaining body/echo obligation. -/
theorem native_plans_useful_from_write_read_admission (checked : NativeCheckedSource) (body : TemplateAst.Body)
    (original : BodySourceMeaning checked.source.write.body body) (bounded : PlanInputFits checked)
    (named : TemplateAst.NamedTemplate)
    (bodyAt : RecipePlanModel.namedBody planErrors body (planSource checked.source body).echo = .ok named)
    (writeAdmitted : RequestCompiler.Admissible (nativeFieldsMeaning checked.field_specs)
      (RecipePlanModel.writeSource (planSource checked.source body) (textBytes checked.parsed_host) named))
    (readsAdmitted : RecipePlanModel.ReadPathsAdmissible (FieldProjection.names (nativeFieldsMeaning checked.field_specs))
      (planSource checked.source body)) :
    AuthsNativeRecipe.recipe.lower.plans checked ⦃ actual =>
      ∃ output, actual = .Ok output ∧ nativeFieldsMeaning output.field_schemas = nativeFieldsMeaning checked.field_specs ⦄ := by
  obtain ⟨expected, compiled, fields⟩ := RecipePlanModel.write_and_read_admission_is_useful planErrors
    (nativeFieldsMeaning checked.field_specs) (textBytes checked.parsed_host) (planSource checked.source body)
    named bodyAt writeAdmitted readsAdmitted
  apply spec_mono (native_plans_exact checked body original bounded)
  intro actual exact
  cases actual with
  | Err error => simp [compiled, nativeRecipeResult] at exact
  | Ok output =>
      have same : nativePlans output = expected := by simpa [compiled, nativeRecipeResult] using exact
      exact ⟨output, rfl, (congrArg RecipePlanModel.Plans.fields same).trans fields⟩

/-- Constructor admission earns every remaining write condition once original
body lowering admission is supplied. The parsed origin, closed write-method
enum, complete original field layout, paths and headers are conclusions of
the actual constructor and source data, not separate acceptance premises. -/
theorem native_constructor_success_earns_write_admissibility (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (schema : ProfileSchema.Value) (schemaBounds : JsonBounds lock.command_schema)
    (schemaMeaning : JsonMeaning lock.command_schema schema) (body : TemplateAst.Body)
    (bodyMeaning : BodySourceMeaning source.write.body body) (fits : ConstructorSourceFits source)
    (checked : NativeConstructorRecord)
    (completed : AuthsNativeRecipe.recipe.validate.validate_source source lock canonical = ok (.Ok checked))
    (named : TemplateAst.NamedTemplate)
    (bodyAdmitted : RequestCompiler.BodyAdmissible (FieldProjection.names (nativeFieldsMeaning checked.field_specs))
      (TemplateAst.namedBody named)) :
    RequestCompiler.Admissible (nativeFieldsMeaning checked.field_specs)
        (RecipePlanModel.writeSource (planSource source body) (textBytes checked.parsed_host) named) ∧
      RecipePlanModel.ReadPathsAdmissible (FieldProjection.names (nativeFieldsMeaning checked.field_specs))
        (planSource source body) := by
  obtain ⟨_, path, headers, reads⟩ := native_constructor_success_earns_lowering_paths source lock canonical schema
    schemaBounds schemaMeaning body bodyMeaning fits checked completed
  have original := native_constructor_success_earns_original_fields source lock canonical checked schemaBounds schema schemaMeaning completed
  have layout := (ProfileSchema.root_meaning_earns_complete_valid_layout schema (nativeFieldsMeaning checked.field_specs) original).2.1
  obtain ⟨parsed, _, origin⟩ := native_constructor_success_earns_origin source lock canonical fits.origin checked completed
  obtain ⟨frame, positive, bounded⟩ := RecipeOriginAdmission.parsed_origin_retains_exact_host _ _ _ origin
  refine ⟨⟨layout, ⟨positive, bounded, frame⟩, ?_, headers, path, bodyAdmitted⟩, reads⟩
  cases source.write.method <;> rfl

/-- Actual constructor success plus the original AST/body obligations yields
useful actual whole-plan lowering. No successful native lowering/write/read,
expected complete plan, read-domain flag or chosen schema map is supplied.
The remaining body/echo premises must still be earned from source admission. -/
theorem native_constructor_success_yields_useful_plans (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (schema : ProfileSchema.Value) (schemaBounds : JsonBounds lock.command_schema)
    (schemaMeaning : JsonMeaning lock.command_schema schema) (body : TemplateAst.Body)
    (bodyMeaning : BodySourceMeaning source.write.body body) (fits : ConstructorSourceFits source)
    (checked : NativeConstructorRecord)
    (completed : AuthsNativeRecipe.recipe.validate.validate_source source lock canonical = ok (.Ok checked))
    (named : TemplateAst.NamedTemplate)
    (bodyAt : RecipePlanModel.namedBody planErrors body (planSource source body).echo = .ok named)
    (bodyAdmitted : RequestCompiler.BodyAdmissible (FieldProjection.names (nativeFieldsMeaning checked.field_specs))
      (TemplateAst.namedBody named)) :
    AuthsNativeRecipe.recipe.lower.plans checked ⦃ actual =>
      ∃ output, actual = .Ok output ∧ nativeFieldsMeaning output.field_schemas = nativeFieldsMeaning checked.field_specs ⦄ := by
  have trace := native_constructor_success_earns_original_trace source lock canonical checked completed
  have domain := native_constructor_success_earns_plan_input_domain source lock canonical schema schemaBounds schemaMeaning
    body bodyMeaning fits checked completed
  obtain ⟨write, reads⟩ := native_constructor_success_earns_write_admissibility source lock canonical schema schemaBounds schemaMeaning
    body bodyMeaning fits checked completed named bodyAdmitted
  exact native_plans_useful_from_write_read_admission checked body
    (by simpa only [trace.originalSource] using bodyMeaning) domain named
    (by simpa only [trace.originalSource] using bodyAt)
    (by simpa only [trace.originalSource] using write)
    (by simpa only [trace.originalSource] using reads)

end Auths.Product.NativeCompiler.Refinement
