import Auths.Product.RecipeBodyPlanAdmission
import Auths.Product.NativeCompilerBodySourceAdmission

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

set_option maxHeartbeats 30000000
set_option maxRecDepth 4096

theorem native_constructor_success_earns_typed_body (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (schema : ProfileSchema.Value) (schemaBounds : JsonBounds lock.command_schema)
    (schemaMeaning : JsonMeaning lock.command_schema schema) (body : TemplateAst.Body)
    (bodyMeaning : BodySourceMeaning source.write.body body) (fits : ConstructorSourceFits source)
    (order : RecipeRuleAdmission.BodyMemberOrder body) (checked : NativeConstructorRecord)
    (completed : AuthsNativeRecipe.recipe.validate.validate_source source lock canonical = ok (.Ok checked)) :
    ∃ named, RecipePlanModel.namedBody planErrors body (planSource source body).echo = .ok named ∧
      RequestCompiler.BodyAdmissible (FieldProjection.names (nativeFieldsMeaning checked.field_specs)) (TemplateAst.namedBody named) := by
  obtain ⟨sourceFields, _, named, compiled, resources⟩ := native_constructor_success_earns_named_body source lock canonical schema
    schemaBounds schemaMeaning body bodyMeaning fits order checked completed
  have original := native_constructor_success_earns_original_fields source lock canonical checked schemaBounds schema schemaMeaning completed
  have layout := (ProfileSchema.root_meaning_earns_complete_valid_layout schema (nativeFieldsMeaning checked.field_specs) original).2.1
  have emittedFields := TemplateAst.named_body_preserves_original_fields planErrors
    (FieldProjection.names (nativeFieldsMeaning checked.field_specs)) body (planSource source body).echo named sourceFields compiled
  exact ⟨named, compiled, TemplateAst.template_fields_resources_earn_body_lowering
    (nativeFieldsMeaning checked.field_specs) layout named resources emittedFields⟩

/-- Actual constructor admission earns useful whole-plan lowering, including
body/echo/resources, exact field/index admission, paths, headers, original
origin and the closed write method. No body/plan success or selected template
is a caller premise. Original map order remains a representation boundary. -/
theorem native_constructor_success_yields_complete_plans (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (schema : ProfileSchema.Value) (schemaBounds : JsonBounds lock.command_schema)
    (schemaMeaning : JsonMeaning lock.command_schema schema) (body : TemplateAst.Body)
    (bodyMeaning : BodySourceMeaning source.write.body body) (fits : ConstructorSourceFits source)
    (order : RecipeRuleAdmission.BodyMemberOrder body) (checked : NativeConstructorRecord)
    (completed : AuthsNativeRecipe.recipe.validate.validate_source source lock canonical = ok (.Ok checked)) :
    AuthsNativeRecipe.recipe.lower.plans checked ⦃ actual => ∃ plans, actual = .Ok plans ∧
      nativeFieldsMeaning plans.field_schemas = nativeFieldsMeaning checked.field_specs ⦄ := by
  obtain ⟨named, compiled, admitted⟩ := native_constructor_success_earns_typed_body source lock canonical schema schemaBounds schemaMeaning
    body bodyMeaning fits order checked completed
  exact native_constructor_success_yields_useful_plans source lock canonical schema schemaBounds schemaMeaning body bodyMeaning fits
    checked completed named compiled admitted

/-- Total original constructor relation strengthened by constructive actual
whole-plan success for every admitted record. Native child success is earned
inside the proof from the same actual constructor execution, never supplied. -/
@[step] theorem native_constructor_admission_with_complete_plans (hash : List Nat → List Nat)
    (library : NativeSha256LibraryContract hash) (source : NativeConstructorSource) (lock : NativeProfileLock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) (schema : ProfileSchema.Value)
    (schemaBounds : JsonBounds lock.command_schema) (schemaMeaning : JsonMeaning lock.command_schema schema)
    (body : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body body)
    (fits : ConstructorSourceFits source) (lockFits : NativeProfileLockFits lock)
    (order : RecipeRuleAdmission.BodyMemberOrder body) (schemaRoom : NativeCanonicalFits 0 canonical.schema) :
    AuthsNativeRecipe.recipe.validate.validate_source source lock canonical ⦃ actual =>
      constructorOutcome actual = RecipeConstructorAdmission.validate constructorErrors hash
        (originalConstructorSource source body) (originalConstructorLock lock canonical schema)
        (constructorParsedOrigin source fits) ∧ ConstructorFrame source canonical actual ∧
        ∀ checked, actual = .Ok checked → ∃ plans,
          AuthsNativeRecipe.recipe.lower.plans checked = ok (.Ok plans) ∧
          nativeFieldsMeaning plans.field_schemas = nativeFieldsMeaning checked.field_specs ⦄ := by
  have total := native_constructor_admission_exact hash library source lock canonical schema schemaBounds schemaMeaning
    body bodyMeaning fits lockFits schemaRoom
  cases run : AuthsNativeRecipe.recipe.validate.validate_source source lock canonical with
  | fail error => simp [run] at total
  | div => simp [run] at total
  | ok actual =>
      have facts : constructorOutcome actual = RecipeConstructorAdmission.validate constructorErrors hash
          (originalConstructorSource source body) (originalConstructorLock lock canonical schema)
          (constructorParsedOrigin source fits) ∧ ConstructorFrame source canonical actual := by simpa [run] using total
      simp only [run, spec_ok]
      refine ⟨facts.1, facts.2, ?_⟩
      intro checked accepted
      have completed : AuthsNativeRecipe.recipe.validate.validate_source source lock canonical = ok (.Ok checked) := by
        simpa only [accepted] using run
      have useful := native_constructor_success_yields_complete_plans source lock canonical schema schemaBounds schemaMeaning
        body bodyMeaning fits order checked completed
      cases loweredAt : AuthsNativeRecipe.recipe.lower.plans checked with
      | fail error => simp [loweredAt] at useful
      | div => simp [loweredAt] at useful
      | ok result =>
          have built : ∃ plans, result = .Ok plans ∧ nativeFieldsMeaning plans.field_schemas = nativeFieldsMeaning checked.field_specs := by
            simpa [loweredAt] using useful
          obtain ⟨plans, same, fields⟩ := built
          exact ⟨plans, by simpa only [same] using loweredAt, fields⟩

/-- Independent complete source admission and successful original canonical
source bytes yield useful actual complete compilation. Every actual body,
write, read, whole-plan and compiler result is a conclusion. The exact digest,
namespace, source and complete field/schema pairs are retained. Named hash/URL
context, public parser/map-order/serialization provenance and resource/physical
adequacy remain explicit outer qualification obligations. -/
theorem native_compile_useful_from_source_admission (hash : List Nat → List Nat)
    (library : NativeSha256LibraryContract hash) (source : NativeConstructorSource) (lock : NativeProfileLock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) (schema : ProfileSchema.Value)
    (schemaBounds : JsonBounds lock.command_schema) (schemaMeaning : JsonMeaning lock.command_schema schema)
    (body : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body body)
    (fits : ConstructorSourceFits source) (lockFits : NativeProfileLockFits lock)
    (order : RecipeRuleAdmission.BodyMemberOrder body) (schemaRoom : NativeCanonicalFits 0 canonical.schema)
    (sourceRoom : NativeCanonicalFits 32 canonical.source) (admitted : RecipeConstructorAdmission.Value)
    (sourceAt : RecipeConstructorAdmission.validate constructorErrors hash (originalConstructorSource source body)
      (originalConstructorLock lock canonical schema) (constructorParsedOrigin source fits) = .ok admitted)
    (canonicalBytes : NativeVec Std.U8) (canonicalAt : canonical.source = .Ok canonicalBytes) :
    AuthsNativeRecipe.recipe.compile_decoded source lock canonical ⦃ actual => ∃ output,
      actual = .Ok output ∧ output.source = source ∧ textBytes output.«namespace» = admitted.namespaceBytes ∧
      nativeDigestArrayBytes output.digest = hash (RecipeBinding.digestPreimage (bytes canonicalBytes)) ∧
      RecipeConstructorAdmission.fieldPairs (nativeFieldsMeaning output.plans.field_schemas) = admitted.fields ⦄ := by
  unfold AuthsNativeRecipe.recipe.compile_decoded
  step with native_constructor_admission_with_complete_plans hash library source lock canonical schema schemaBounds schemaMeaning
    body bodyMeaning fits lockFits order schemaRoom as ⟨admission, semantic, frame, completePlans⟩
  cases admission with
  | Err error => simp [constructorOutcome, sourceAt] at semantic
  | Ok checked =>
      have same : constructorValue checked = admitted := by simpa [constructorOutcome, sourceAt] using semantic
      have originalCanonical := (frame checked rfl).2
      have checkedCanonical : checked.canonical_source = .Ok canonicalBytes := originalCanonical.trans canonicalAt
      have checkedRoom : NativeCanonicalFits 32 checked.canonical_source := by simpa only [originalCanonical] using sourceRoom
      simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      step with native_checked_recipe_digest_exact hash library checked checkedRoom as ⟨digested, digestMeaning⟩
      have digestModel : nativeDigestOutcome digested = .ok (hash (RecipeBinding.digestPreimage (bytes canonicalBytes))) := by
        simpa [RecipeLockAdmission.recipeDigest, nativeCanonicalOutcome, checkedCanonical] using digestMeaning
      cases digested with
      | Err error => simp [nativeDigestOutcome] at digestModel
      | Ok digest =>
          have digestAt : nativeDigestArrayBytes digest = hash (RecipeBinding.digestPreimage (bytes canonicalBytes)) := by
            simpa [nativeDigestOutcome] using digestModel
          obtain ⟨plans, plansAt, fields⟩ := completePlans checked rfl
          simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok, plansAt,
            AuthsNativeRecipe.recipe.validate.ValidatedSource.into_namespace, spec_ok]
          refine ⟨⟨source, checked.«namespace», digest, plans⟩, rfl, rfl, ?_, digestAt, ?_⟩
          · exact congrArg RecipeConstructorAdmission.Value.namespaceBytes same
          · rw [fields]
            exact congrArg RecipeConstructorAdmission.Value.fields same

end Auths.Product.NativeCompiler.Refinement
