import Auths.Product.NativeCompilerConstructorMeaning
import Auths.Product.NativeCompilerRuleFieldDomain
import Auths.Product.NativeCompilerSourceRulesAdmission

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

set_option maxHeartbeats 20000000
set_option maxRecDepth 4096

/-- Constructor success earns both original schema semantics and the actual
map domain. The trace supplies parse/build outcomes as conclusions; the
independent full original layout earns count, names and map associations. -/
theorem native_constructor_success_earns_rule_field_domain (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (checked : NativeConstructorRecord) (bounded : JsonBounds lock.command_schema)
    (schema : ProfileSchema.Value) (schemaMeaning : JsonMeaning lock.command_schema schema)
    (completed : AuthsNativeRecipe.recipe.validate.validate_source source lock canonical = ok (.Ok checked)) :
    ProfileSchema.RootMeaning schema (nativeFieldsMeaning checked.field_specs) ∧
      ∃ fields : NativeRuleMap,
        AuthsNativeRecipe.recipe.profile.rule_fields (AuthsNativeRecipe.alloc.vec.Vec.deref checked.field_specs) = ok (.Ok fields) ∧
        Rules.Meaning (nativeFieldsMeaning checked.field_specs) (nativeRuleMapMeaning fields) ∧
        fields.entries.val.length ≤ 32 ∧ (∀ entry ∈ fields.entries.val, TextFits entry.1) ∧
        AuthsNativeRecipe.recipe.validate.validate_source_rules source fields = ok (.Ok ()) := by
  have trace := native_constructor_success_earns_original_trace source lock canonical checked completed
  have original := native_constructor_success_earns_original_fields source lock canonical checked bounded schema schemaMeaning completed
  have layout := (ProfileSchema.root_meaning_earns_complete_valid_layout schema (nativeFieldsMeaning checked.field_specs) original).2.1
  obtain ⟨fields, built, rules⟩ := trace.ruleFields
  have copied := native_rule_fields_success_has_original_meaning (AuthsNativeRecipe.alloc.vec.Vec.deref checked.field_specs)
  rw [built] at copied
  have meaning : Rules.Meaning (nativeFieldsMeaning checked.field_specs) (nativeRuleMapMeaning fields) := by
    simpa [spec_ok, nativeFieldColumn, nativeFieldsMeaning, native_deref_contents] using copied
  have count := original_rule_map_count _ fields layout meaning
  have names := original_rule_fields_earn_name_bounds _ fields layout meaning
  exact ⟨original, fields, built, meaning, count, fun entry member => (names entry member).2, rules⟩

/-- Complete constructor success earns the whole independent original-source
rule verdict. The initial ledger is the real default ledger in the source-rule
root; original field count/names are earned here, never supplied by the caller. -/
theorem native_constructor_success_earns_complete_rules (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (checked : NativeConstructorRecord) (bounded : JsonBounds lock.command_schema)
    (schema : ProfileSchema.Value) (schemaMeaning : JsonMeaning lock.command_schema schema)
    (body : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body body)
    (fits : SourceRulesFit source)
    (completed : AuthsNativeRecipe.recipe.validate.validate_source source lock canonical = ok (.Ok checked)) :
    ProfileSchema.RootMeaning schema (nativeFieldsMeaning checked.field_specs) ∧
      ∃ fields : NativeRuleMap,
        Rules.Meaning (nativeFieldsMeaning checked.field_specs) (nativeRuleMapMeaning fields) ∧
        fields.entries.val.length ≤ 32 ∧
        (RecipeRuleAdmission.validate (nativeRuleMapMeaning fields) (ruleSource source body)).1 = .ok () := by
  obtain ⟨original, fields, built, mapMeaning, count, names, validated⟩ :=
    native_constructor_success_earns_rule_field_domain source lock canonical checked bounded schema schemaMeaning completed
  have semantic := native_source_rules_success source fields body bodyMeaning fits count names
  rw [validated] at semantic
  refine ⟨original, fields, mapMeaning, count, ?_⟩
  simpa [spec_ok] using semantic

/-- The actual compile caller carries the same original source, parsed fields,
complete grouped admission and staged plans. No child validation, chosen rule
map or successful lowering is a premise. This is a success consequence; total
constructor/compile usefulness and all-refusal composition remain separate. -/
theorem native_compile_success_earns_complete_rules (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (bounded : JsonBounds lock.command_schema) (schema : ProfileSchema.Value)
    (schemaMeaning : JsonMeaning lock.command_schema schema) (body : TemplateAst.Body)
    (bodyMeaning : BodySourceMeaning source.write.body body) (fits : SourceRulesFit source)
    (output : AuthsNativeRecipe.recipe.CompiledRecipe)
    (completed : AuthsNativeRecipe.recipe.compile_decoded source lock canonical = ok (.Ok output)) :
    output.source = source ∧ ∃ checked : NativeConstructorRecord,
      AuthsNativeRecipe.recipe.validate.validate_source source lock canonical = ok (.Ok checked) ∧
      ProfileSchema.RootMeaning schema (nativeFieldsMeaning checked.field_specs) ∧
      (∃ fields : NativeRuleMap,
        Rules.Meaning (nativeFieldsMeaning checked.field_specs) (nativeRuleMapMeaning fields) ∧
        fields.entries.val.length ≤ 32 ∧
        (RecipeRuleAdmission.validate (nativeRuleMapMeaning fields) (ruleSource source body)).1 = .ok ()) ∧
      output.«namespace» = checked.«namespace» ∧
      AuthsNativeRecipe.recipe.lower.plans checked = ok (.Ok output.plans) := by
  obtain ⟨checked, admitted, digest, plans, original, namespaceValue⟩ :=
    native_compile_success_keeps_all_stage_results source lock canonical output completed
  obtain ⟨schemaOriginal, rules⟩ := native_constructor_success_earns_complete_rules source lock canonical checked
    bounded schema schemaMeaning body bodyMeaning fits admitted
  exact ⟨original, checked, admitted, schemaOriginal, rules, namespaceValue, plans⟩

end Auths.Product.NativeCompiler.Refinement
