import Auths.Product.NativeSerdeCompilerFits
import Auths.Product.RecipeSerdeSource
import Auths.Product.RecipeSerdeSourceUniqueness
import Auths.Product.FullJsonSchemaView
import Auths.Product.NativeCompilerAst
import Auths.Product.NativeCompilerCompileAdmission
import Auths.Product.NativeSerdeMapOrder
import Auths.Product.NativeCompilerParsedSourceUsefulness

/-!
Consume complete original decoded meaning at the existing decoded compiler
boundary. Representation domains and semantic views are earned, not separate
premises. Actual byte parsing/derive correctness, canonical provenance, library
adequacy and physical costs remain named outer obligations.
-/
namespace Auths.Product.NativeSerde
open RecipeSerdeGrammar NativeCompiler
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

theorem source_probe_bounds_from_carrier (input : NativeRecord .recipe)
    (bounded : CarrierBounds (.record .recipe) input) : RecipeSerde.ProbeBounded input.credential := by
  intro probe present
  have choice : RecipeSerde.originalProbe input.credential =
      (originalGuard input.credential).bind (fun guard => guard.probe) := by
    cases input.credential <;> rfl
  cases guarded : originalGuard input.credential with
  | none => simp [choice, guarded] at present
  | some guard =>
      have probeAt : guard.probe = some probe := by simpa [choice, guarded] using present
      have credential := bounded_record_field bounded (.internal .credential) input.credential (by simp [recordSlots])
      have guardBounds := credential_guard_bounds_from_carrier input.credential credential guard guarded
      have option := bounded_record_field guardBounds (.option (.record .probe)) guard.probe (by simp [recordSlots])
      have probeBounds := bounded_option_present option probe probeAt
      exact bounded_json_fits (bounded_record_field probeBounds .json probe.equals (by simp [recordSlots]))

/-- Complete typed serialization data exists for the same decoded source.
This specifies the full tree before canonical sorting/numeric formatting;
it does not prove the actual Serialize derive or canonicalizer call. -/
theorem decoded_source_earns_full_serialization (raw : RawJson) (input : NativeRecord .recipe)
    (original : SourceMeaning raw input) : ∃ serialized, RecipeSerde.SourceEncoding input serialized := by
  have bounded := native_decode_earns_carrier_bounds original.2
  exact RecipeSerde.source_encoding_exists input (source_body_bounds_from_carrier input bounded)
    (source_probe_bounds_from_carrier input bounded)

/-- Full original decoded provenance constructs a complete serialization and
earns recursive uniqueness together. No serialized value or uniqueness result
is supplied. Actual Serialize/canonicalizer adequacy is still an outer gate. -/
theorem decoded_source_earns_unique_full_serialization (raw : RawJson) (input : NativeRecord .recipe)
    (original : SourceMeaning raw input) :
    ∃ serialized, RecipeSerde.SourceEncoding input serialized ∧ FullJsonValue.Unique serialized := by
  obtain ⟨serialized, encoded⟩ := decoded_source_earns_full_serialization raw input original
  exact ⟨serialized, encoded,
    RecipeSerde.decoded_source_serialization_has_unique_objects raw input original serialized encoded⟩

/-- The original command schema, rather than a fictitious whole-lock serde
input, has a full recursively unique value. Booleans, nulls, float bits and
all annotations remain in this value before canonical numeric formatting. -/
theorem decoded_lock_earns_unique_full_schema (raw : RawJson) (input : NativeRecord .lock)
    (original : LockMeaning raw input) :
    ∃ schema, FullJsonMeaning input.command_schema schema ∧ FullJsonValue.Unique schema := by
  have bounded := (decoded_lock_earns_compiler_domain raw input original).2
  obtain ⟨schema, meaning⟩ := full_json_meaning_exists input.command_schema bounded
  exact ⟨schema, meaning, RecipeSerde.decoded_lock_schema_has_unique_objects raw input original schema meaning⟩

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

/-- Total actual decoded compilation, deriving all source/lock/schema/body
representation premises and original semantic views from full native meaning.
No source admission, successful native child, expected plan, schema view or
body model is supplied by the caller. Canonical bytes remain explicit inputs;
this is not a theorem for the selected public byte-entry root. -/
theorem native_compile_with_decoded_meaning (hash : List Nat → List Nat)
    (library : NativeSha256LibraryContract hash) (rawSource rawLock : RawJson)
    (source : NativeRecord .recipe) (lock : NativeRecord .lock)
    (sourceMeaning : SourceMeaning rawSource source) (lockMeaning : LockMeaning rawLock lock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (schemaRoom : NativeCanonicalFits 0 canonical.schema) (sourceRoom : NativeCanonicalFits 32 canonical.source) :
    ∃ fullSchema body, FullJsonMeaning lock.command_schema fullSchema ∧
      BodySourceMeaning source.write.body body ∧
      AuthsNativeRecipe.recipe.compile_decoded source lock canonical ⦃ actual =>
        compilerOutcome actual = decodedCompilerModel hash source lock canonical
          (FullJsonValue.schemaView fullSchema) body
          (decoded_source_earns_constructor_domain rawSource source sourceMeaning) ∧
        CompilerFrame source actual ⦄ := by
  have fits := decoded_source_earns_constructor_domain rawSource source sourceMeaning
  obtain ⟨lockFits, schemaBounds⟩ := decoded_lock_earns_compiler_domain rawLock lock lockMeaning
  obtain ⟨fullSchema, fullMeaning⟩ := full_json_meaning_exists lock.command_schema schemaBounds
  have schemaMeaning := full_json_earns_schema_view fullMeaning
  have bodyBounds := source_body_bounds_from_carrier source (native_decode_earns_carrier_bounds sourceMeaning.2)
  obtain ⟨copied, body, copiedAt, bodyMeaning, kernelMeaning⟩ :=
    NativeCompiler.Refinement.native_body_earns_original_meaning source.write.body bodyBounds
  refine ⟨fullSchema, body, fullMeaning, bodyMeaning, ?_⟩
  exact NativeCompiler.Refinement.native_compile_decoded_admission_exact hash library source lock canonical
    (FullJsonValue.schemaView fullSchema) schemaBounds schemaMeaning body bodyMeaning fits lockFits schemaRoom sourceRoom

/-- The same complete native meaning also earns useful compilation whenever
the independent source model admits and source canonicalization succeeds.
The caller supplies no body/schema model, map order, representation domain,
native helper success or expected lowered plan. Canonical provenance and real
library/compiler non-vacuity remain separate outer obligations. -/
theorem native_compile_useful_with_decoded_meaning (hash : List Nat → List Nat)
    (library : NativeSha256LibraryContract hash) (rawSource rawLock : RawJson)
    (source : NativeRecord .recipe) (lock : NativeRecord .lock)
    (sourceMeaning : SourceMeaning rawSource source) (lockMeaning : LockMeaning rawLock lock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (schemaRoom : NativeCanonicalFits 0 canonical.schema) (sourceRoom : NativeCanonicalFits 32 canonical.source) :
    ∃ fullSchema body, FullJsonMeaning lock.command_schema fullSchema ∧
      BodySourceMeaning source.write.body body ∧
      ∀ admitted canonicalBytes,
        RecipeConstructorAdmission.validate constructorErrors hash (originalConstructorSource source body)
          (originalConstructorLock lock canonical (FullJsonValue.schemaView fullSchema))
          (constructorParsedOrigin source (decoded_source_earns_constructor_domain rawSource source sourceMeaning)) = .ok admitted →
        canonical.source = .Ok canonicalBytes →
        AuthsNativeRecipe.recipe.compile_decoded source lock canonical ⦃ actual => ∃ output,
          actual = .Ok output ∧ output.source = source ∧ textBytes output.«namespace» = admitted.namespaceBytes ∧
          nativeDigestArrayBytes output.digest = hash (RecipeBinding.digestPreimage (bytes canonicalBytes)) ∧
          RecipeConstructorAdmission.fieldPairs (nativeFieldsMeaning output.plans.field_schemas) = admitted.fields ⦄ := by
  have fits := decoded_source_earns_constructor_domain rawSource source sourceMeaning
  obtain ⟨lockFits, schemaBounds⟩ := decoded_lock_earns_compiler_domain rawLock lock lockMeaning
  obtain ⟨fullSchema, fullMeaning⟩ := full_json_meaning_exists lock.command_schema schemaBounds
  have schemaMeaning := full_json_earns_schema_view fullMeaning
  have bodyBounds := source_body_bounds_from_carrier source (native_decode_earns_carrier_bounds sourceMeaning.2)
  obtain ⟨copied, body, copiedAt, bodyMeaning, kernelMeaning⟩ :=
    NativeCompiler.Refinement.native_body_earns_original_meaning source.write.body bodyBounds
  refine ⟨fullSchema, body, fullMeaning, bodyMeaning, ?_⟩
  intro admitted canonicalBytes sourceAt canonicalAt
  exact NativeCompiler.Refinement.native_compile_useful_with_original_map_order hash library source lock canonical
    (FullJsonValue.schemaView fullSchema) schemaBounds schemaMeaning body bodyMeaning fits lockFits
    (decoded_source_earns_body_order rawSource source sourceMeaning) schemaRoom sourceRoom admitted sourceAt canonicalBytes canonicalAt

end Auths.Product.NativeSerde
