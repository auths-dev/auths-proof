import Auths.Product.NativeSerdeNumericSerialization
import Auths.Product.NativeCompilerConstructorRules

/-!
Connect actual native constructor/decoded-compiler success to complete
same-source numeric serialization. Complete original decoded meanings earn
all representation domains; the real constructor earns schema and rule
admission. Neither numeric admission nor a chosen body/serialization/schema
view is supplied. These are success consequences under the named native
primitive boundaries, not byte-entry, Serialize/JCS adequacy or non-vacuity.
-/
namespace Auths.Product.NativeSerde
open RecipeSerdeGrammar NativeCompiler
open Aeneas Aeneas.Std Result

def OriginalNumericSerialization (source : NativeRecord .recipe) (lock : NativeRecord .lock)
    (serialized schema : RecipeSerde.Json) : Prop :=
  RecipeSerde.SourceEncoding source serialized ∧ FullJsonValue.Unique serialized ∧
    FullJsonNumericSafety.SafeNumbers serialized ∧ FullJsonMeaning lock.command_schema schema ∧
    FullJsonValue.Unique schema ∧ FullJsonNumericSafety.SafeNumbers schema

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

theorem successful_native_constructor_earns_numeric_serialization (rawSource rawLock : RawJson)
    (source : NativeRecord .recipe) (lock : NativeRecord .lock)
    (sourceOriginal : SourceMeaning rawSource source) (lockOriginal : LockMeaning rawLock lock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) (checked : NativeConstructorRecord)
    (completed : AuthsNativeRecipe.recipe.validate.validate_source source lock canonical = ok (.Ok checked)) :
    ∃ serialized schema, OriginalNumericSerialization source lock serialized schema := by
  have sourceBounds := native_decode_earns_carrier_bounds sourceOriginal.2
  have fits := source_rules_fits_from_carrier source sourceBounds
  have lockBounds := (decoded_lock_earns_compiler_domain rawLock lock lockOriginal).2
  obtain ⟨schema, schemaOriginal, schemaUnique⟩ := decoded_lock_earns_unique_full_schema rawLock lock lockOriginal
  have schemaMeaning := full_json_earns_schema_view schemaOriginal
  obtain ⟨copied, body, copiedAt, bodyOriginal, kernelOriginal⟩ :=
    NativeCompiler.Refinement.native_body_earns_original_meaning source.write.body
      (source_body_bounds_from_carrier source sourceBounds)
  obtain ⟨schemaAdmitted, fields, fieldMeaning, count, rulesAdmitted⟩ :=
    NativeCompiler.Refinement.native_constructor_success_earns_complete_rules source lock canonical checked lockBounds
      (FullJsonValue.schemaView schema) schemaMeaning body bodyOriginal fits completed
  obtain ⟨serialized, encoded, sourceUnique⟩ := decoded_source_earns_unique_full_serialization rawSource source sourceOriginal
  have sourceSafe := RecipeSerde.admitted_source_serialization_has_safe_numbers
    (nativeRuleMapMeaning fields) source body bodyOriginal rulesAdmitted serialized encoded
  have schemaSafe := FullJsonNumericSafety.schema_safety_keeps_full_original schema
    (ProfileSchemaNumericSafety.root_meaning_has_safe_numbers (FullJsonValue.schemaView schema)
      (nativeFieldsMeaning checked.field_specs) schemaAdmitted)
  exact ⟨serialized, schema, encoded, sourceUnique, sourceSafe, schemaOriginal, schemaUnique, schemaSafe⟩

/-- Actual whole decoded compilation success earns both complete safe trees
and the exact retained source. No child success, independently accepted rules,
safe-number flags or canonical byte provenance are supplied. The canonical
input's origin and actual Serialize/canonicalizer behavior remain outer work. -/
theorem successful_native_compile_earns_numeric_serialization (rawSource rawLock : RawJson)
    (source : NativeRecord .recipe) (lock : NativeRecord .lock)
    (sourceOriginal : SourceMeaning rawSource source) (lockOriginal : LockMeaning rawLock lock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) (output : AuthsNativeRecipe.recipe.CompiledRecipe)
    (completed : AuthsNativeRecipe.recipe.compile_decoded source lock canonical = ok (.Ok output)) :
    output.source = source ∧ ∃ serialized schema, OriginalNumericSerialization output.source lock serialized schema := by
  obtain ⟨checked, admitted, digest, plans, original, namespaceValue⟩ :=
    NativeCompiler.Refinement.native_compile_success_keeps_all_stage_results source lock canonical output completed
  refine ⟨original, ?_⟩
  rw [original]
  exact successful_native_constructor_earns_numeric_serialization rawSource rawLock source lock
    sourceOriginal lockOriginal canonical checked admitted

end Auths.Product.NativeSerde
