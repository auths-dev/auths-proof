import Auths.Product.RecipeBodyEchoAdmission
import Auths.Product.NativeCompilerUsefulReadPlans

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

set_option maxHeartbeats 30000000
set_option maxRecDepth 4096

/-- Actual constructor success earns original body references, shared nodes
and useful named-body compilation, including the actual declared echo. The
original AST's map order is explicit representation input; the public parser/
BTreeMap boundary must earn it. It is not a trusted Auths admission flag. -/
theorem native_constructor_success_earns_named_body (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (schema : ProfileSchema.Value) (schemaBounds : JsonBounds lock.command_schema)
    (schemaMeaning : JsonMeaning lock.command_schema schema) (body : TemplateAst.Body)
    (bodyMeaning : BodySourceMeaning source.write.body body) (fits : ConstructorSourceFits source)
    (order : RecipeRuleAdmission.BodyMemberOrder body) (checked : NativeConstructorRecord)
    (completed : AuthsNativeRecipe.recipe.validate.validate_source source lock canonical = ok (.Ok checked)) :
    RecipeRuleAdmission.BodyFieldsWithin (FieldProjection.names (nativeFieldsMeaning checked.field_specs)) body ∧
      TemplateAst.bodyNodes body ≤ 64 ∧ ∃ named,
        RecipePlanModel.namedBody planErrors body (planSource source body).echo = .ok named ∧ TemplateAst.TemplateDomain named := by
  obtain ⟨original, fields, meaning, _, rules⟩ := native_constructor_success_earns_complete_rules source lock canonical checked
    schemaBounds schema schemaMeaning body bodyMeaning fits.rules completed
  have layout := (ProfileSchema.root_meaning_earns_complete_valid_layout schema (nativeFieldsMeaning checked.field_specs) original).2.1
  have domain := RecipeRuleAdmission.complete_rules_earn_named_body planErrors (nativeFieldsMeaning checked.field_specs)
    (nativeRuleMapMeaning fields) layout meaning (ruleSource source body) order rules
  simpa [ruleSource, planSource, Option.map_map, Function.comp_def] using domain

/-- The actual named_write_body helper is useful from original constructor
admission and original-map representation, without a successful native body
compiler or caller-selected emitted template as a premise. The outer compiler
must still earn named-piece field/index lowering and the public byte boundary. -/
theorem native_constructor_success_yields_useful_named_body (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (schema : ProfileSchema.Value) (schemaBounds : JsonBounds lock.command_schema)
    (schemaMeaning : JsonMeaning lock.command_schema schema) (body : TemplateAst.Body)
    (bodyMeaning : BodySourceMeaning source.write.body body) (fits : ConstructorSourceFits source)
    (order : RecipeRuleAdmission.BodyMemberOrder body) (checked : NativeConstructorRecord)
    (completed : AuthsNativeRecipe.recipe.validate.validate_source source lock canonical = ok (.Ok checked)) :
    AuthsNativeRecipe.recipe.lower.named_write_body source ⦃ actual =>
      ∃ output, actual = .Ok output ∧ TemplateAst.TemplateDomain (nativeTemplate output) ∧
        RecipeRuleAdmission.BodyFieldsWithin (FieldProjection.names (nativeFieldsMeaning checked.field_specs)) body ⦄ := by
  obtain ⟨names, _, expected, compiled, resources⟩ := native_constructor_success_earns_named_body source lock canonical schema
    schemaBounds schemaMeaning body bodyMeaning fits order checked completed
  apply spec_mono (native_named_write_body_exact source body bodyMeaning fits.rules.write.2.1
    (fun echo present => (fits.rules.response.echo echo present).2))
  intro actual exact
  cases actual with
  | Err error => simp [compiled, nativeRecipeResult] at exact
  | Ok output =>
      have same : nativeTemplate output = expected := by simpa [compiled, nativeRecipeResult] using exact
      exact ⟨output, rfl, by simpa only [same] using resources, names⟩

end Auths.Product.NativeCompiler.Refinement
