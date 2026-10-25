import Auths.Product.NativeCompilerConstructorTrace
import Auths.Product.NativeCompilerSchemaRoot

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def originalSourceBinding (source : NativeConstructorSource) : RecipeBinding.Binding :=
  ⟨textBytes source.service, textBytes source.tool, textBytes source.profile_schema_digest⟩

structure NativeSourceBindingFits (source : NativeConstructorSource) : Prop where
  service : TextFits source.service
  tool : TextFits source.tool
  schemaDigest : TextFits source.profile_schema_digest

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open RecipeBinding

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

set_option maxHeartbeats 12000000
set_option maxRecDepth 4096

@[step] theorem native_constructor_source_tag_exact (source : NativeConstructorSource)
    (fits : TextFits source.schema) :
    constructorSourceTag source ⦃ actual => actual = decide (textBytes source.schema = sourceSchema) ⦄ := by
  unfold constructorSourceTag
  step with borrow_text_exact source.schema fits as ⟨schema, schemaMeaning⟩
  apply spec_mono (native_source_schema_exact schema)
  intro actual meaning
  simpa [schemaSliceBytes, schemaMeaning] using meaning

@[step] theorem native_constructor_profile_binding_exact (source : NativeConstructorSource)
    (lock : NativeProfileLock) (sourceFits : NativeSourceBindingFits source)
    (lockFits : NativeProfileLockFits lock) :
    constructorProfileBinding source lock ⦃ actual =>
      actual = decide (SourceMatches (originalSourceBinding source) (originalLockMetadata lock).binding) ⦄ := by
  unfold constructorProfileBinding
  step with borrow_text_exact source.service sourceFits.service as ⟨service, serviceMeaning⟩
  step with borrow_text_exact source.tool sourceFits.tool as ⟨tool, toolMeaning⟩
  step with borrow_text_exact source.profile_schema_digest sourceFits.schemaDigest as ⟨digest, digestMeaning⟩
  step with borrow_text_exact lock.service lockFits.service as ⟨lockService, lockServiceMeaning⟩
  step with borrow_text_exact lock.tool lockFits.tool as ⟨lockTool, lockToolMeaning⟩
  step with borrow_text_exact lock.schema_digest lockFits.schemaDigest as ⟨lockDigest, lockDigestMeaning⟩
  apply spec_mono (native_source_profile_binding_exact
    ⟨service, tool, digest⟩ ⟨lockService, lockTool, lockDigest⟩)
  intro actual meaning
  simpa [nativeProfileBinding, originalSourceBinding, originalLockMetadata, schemaSliceBytes,
    serviceMeaning, toolMeaning, digestMeaning, lockServiceMeaning, lockToolMeaning, lockDigestMeaning] using meaning

/-- A successful native constructor earns the supported source schema and exact
original service/tool/schema-digest binding; neither is inferred from a private
record or an input approval. The domains are string representability only. -/
theorem native_constructor_success_earns_source_binding (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (checked : NativeConstructorRecord) (tagFits : TextFits source.schema)
    (sourceFits : NativeSourceBindingFits source) (lockFits : NativeProfileLockFits lock)
    (completed : AuthsNativeRecipe.recipe.validate.validate_source source lock canonical = ok (.Ok checked)) :
    textBytes source.schema = sourceSchema ∧
      SourceMatches (originalSourceBinding source) (originalLockMetadata lock).binding := by
  have trace := native_constructor_success_earns_original_trace source lock canonical checked completed
  have tag := native_constructor_source_tag_exact source tagFits
  rw [trace.sourceTag] at tag
  have binding := native_constructor_profile_binding_exact source lock sourceFits lockFits
  rw [trace.profileBound] at binding
  exact ⟨by simpa [spec_ok] using tag, by simpa [spec_ok] using binding⟩

/-- Metadata and the schema hash comparison are earned by the complete native
compile call. The schema outcome still needs its original JSON serialization
relation, and the vetted hash API contract stays explicit. -/
theorem native_compile_success_earns_lock_binding (hash : List Nat → List Nat)
    (library : NativeSha256LibraryContract hash) (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (fits : NativeProfileLockFits lock) (hashRoom : NativeCanonicalFits 0 canonical.schema)
    (output : AuthsNativeRecipe.recipe.CompiledRecipe)
    (completed : AuthsNativeRecipe.recipe.compile_decoded source lock canonical = ok (.Ok output)) :
    MetadataValid (originalLockMetadata lock) ∧ ∃ original, canonical.schema = .Ok original ∧
      SchemaDigestMatches (textBytes lock.schema_digest) (hash (bytes original)) := by
  obtain ⟨checked, trace, digest, plans, original, namespaceValue⟩ :=
    native_compile_success_earns_constructor_trace source lock canonical output completed
  have meaning := native_lock_acceptance_earns_digest hash library lock canonical.schema fits hashRoom
  rw [trace.lockChecked] at meaning
  simpa [spec_ok] using meaning

/-- Complete original decoded schema meaning is retained through the actual
constructor field result. Every field name/schema pair is represented; an
accepted native field column is not supplied as a premise. -/
theorem native_constructor_success_earns_original_fields (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (checked : NativeConstructorRecord) (bounded : JsonBounds lock.command_schema)
    (original : ProfileSchema.Value) (originalMeaning : JsonMeaning lock.command_schema original)
    (completed : AuthsNativeRecipe.recipe.validate.validate_source source lock canonical = ok (.Ok checked)) :
    ProfileSchema.RootMeaning original (nativeFieldsMeaning checked.field_specs) := by
  have trace := native_constructor_success_earns_original_trace source lock canonical checked completed
  have fields : AuthsNativeRecipe.recipe.profile.parse_root lock.command_schema = ok (.Ok checked.field_specs) := by
    simpa [AuthsNativeRecipe.recipe.parse_root_fields] using trace.fieldsChecked
  have meaning := native_profile_root_has_exact_semantics lock.command_schema bounded original originalMeaning
  rw [fields] at meaning
  simpa [spec_ok] using meaning

/-- A complete successful compilation carries an independently meaningful full
original field layout in the same checked record used by digest and lowering.
This does not yet establish all rule/guard semantics or plan-input bounds. -/
theorem native_compile_success_earns_original_fields (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (bounded : JsonBounds lock.command_schema) (original : ProfileSchema.Value)
    (originalMeaning : JsonMeaning lock.command_schema original)
    (output : AuthsNativeRecipe.recipe.CompiledRecipe)
    (completed : AuthsNativeRecipe.recipe.compile_decoded source lock canonical = ok (.Ok output)) :
    ∃ checked : NativeConstructorRecord, NativeConstructorTrace source lock canonical checked ∧
      ProfileSchema.RootMeaning original (nativeFieldsMeaning checked.field_specs) ∧
      AuthsNativeRecipe.recipe.lower.plans checked = ok (.Ok output.plans) ∧
      output.source = source ∧ output.«namespace» = checked.«namespace» := by
  obtain ⟨checked, admitted, digest, plans, originalSource, namespaceValue⟩ :=
    native_compile_success_keeps_all_stage_results source lock canonical output completed
  exact ⟨checked, native_constructor_success_earns_original_trace source lock canonical checked admitted,
    native_constructor_success_earns_original_fields source lock canonical checked bounded original originalMeaning admitted,
    plans, originalSource, namespaceValue⟩

end Auths.Product.NativeCompiler.Refinement
