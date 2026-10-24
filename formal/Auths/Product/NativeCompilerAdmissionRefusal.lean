import Auths.Product.NativeCompilerConstructorMeaning

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open RecipeBinding

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

set_option maxHeartbeats 12000000
set_option maxRecDepth 4096

/-- Invalid original metadata is refused before canonical bytes or any hash API
is consumed. No crypto-library contract or canonicalization-success/bound
premise is needed for this branch. -/
@[step] theorem native_lock_metadata_refusal (lock : NativeProfileLock)
    (canonical : NativeCanonicalBytes) (fits : NativeProfileLockFits lock)
    (invalid : ¬MetadataValid (originalLockMetadata lock)) :
    AuthsNativeRecipe.recipe.validate_lock lock canonical ⦃ actual =>
      actual = .Err NativeRecipeError.InvalidProfileLock ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate_lock
  step with borrow_text_exact lock.schema fits.schema as ⟨schema, schemaMeaning⟩
  step with borrow_text_exact lock.profile fits.profile as ⟨profile, profileMeaning⟩
  step with borrow_text_exact lock.service fits.service as ⟨service, serviceMeaning⟩
  step with borrow_text_exact lock.tool fits.tool as ⟨tool, toolMeaning⟩
  step with borrow_text_exact lock.schema_digest fits.schemaDigest as ⟨declared, declaredMeaning⟩
  let metadata : NativeLockMetadata := {
    schema
    generator_format := lock.generator_format
    version := lock.version
    profile
    binding := ⟨service, tool, declared⟩
  }
  have originalMetadata : nativeLockMetadata metadata = originalLockMetadata lock := by
    simp [metadata, nativeLockMetadata, nativeProfileBinding, originalLockMetadata,
      schemaSliceBytes, schemaMeaning, profileMeaning, serviceMeaning, toolMeaning, declaredMeaning]
  step with native_lock_metadata_exact metadata as ⟨valid, metadataMeaning⟩
  have refused : valid = false := by simpa [originalMetadata, invalid] using metadataMeaning
  simp [refused]

/-- The complete admission constructor refuses an invalid lock, preserving the
source-tag-before-lock error order. Later rules, parsing and hashing cannot turn
that refusal into a checked record. -/
@[step] theorem native_constructor_invalid_lock_refusal (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (sourceFits : TextFits source.schema) (lockFits : NativeProfileLockFits lock)
    (invalid : ¬MetadataValid (originalLockMetadata lock)) :
    AuthsNativeRecipe.recipe.validate.validate_source source lock canonical ⦃ actual =>
      actual = .Err NativeRecipeError.InvalidSource ∨ actual = .Err NativeRecipeError.InvalidProfileLock ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.validate_source
  step with borrow_text_exact source.schema sourceFits as ⟨schema, schemaMeaning⟩
  step with native_source_schema_exact schema as ⟨supported, supportedMeaning⟩
  cases supported with
  | false => simp
  | true =>
      simp only [Bool.true_eq_true, ↓reduceIte]
      step with native_lock_metadata_refusal lock canonical.schema lockFits invalid as ⟨result, refused⟩
      simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from]

/-- This refusal is for the actual complete shipping compile caller, including
its digest/lowering tail. It is not a predicate over an assumed checked record. -/
@[step] theorem native_compile_invalid_lock_refusal (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (sourceFits : TextFits source.schema) (lockFits : NativeProfileLockFits lock)
    (invalid : ¬MetadataValid (originalLockMetadata lock)) :
    AuthsNativeRecipe.recipe.compile_decoded source lock canonical ⦃ actual =>
      actual = .Err NativeRecipeError.InvalidSource ∨ actual = .Err NativeRecipeError.InvalidProfileLock ⦄ := by
  unfold AuthsNativeRecipe.recipe.compile_decoded
  step with native_constructor_invalid_lock_refusal source lock canonical sourceFits lockFits invalid
    as ⟨result, refused⟩
  rcases refused with refused | refused <;>
    simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame, core.convert.FromSame.from]

end Auths.Product.NativeCompiler.Refinement
