import Auths.Product.NativeCompilerSha256Contract
import Auths.Product.NativeCompilerDigestHex
import Auths.Product.RecipeLockAdmission

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

abbrev NativeProfileLock := AuthsNativeRecipe.recipe.ProfileLockFile
abbrev NativeCanonicalBytes := core.result.Result (NativeVec Std.U8) Unit
abbrev NativeRecipeError := AuthsNativeRecipe.recipe.GatewayRecipeError

def compilerLockErrors : RecipeLockAdmission.Errors NativeRecipeError :=
  ⟨.InvalidSource, .InvalidProfileLock⟩

def originalLockMetadata (lock : NativeProfileLock) : RecipeBinding.Metadata :=
  ⟨textBytes lock.schema, lock.generator_format.val, lock.version.val,
    textBytes lock.profile, ⟨textBytes lock.service, textBytes lock.tool, textBytes lock.schema_digest⟩⟩

structure NativeProfileLockFits (lock : NativeProfileLock) : Prop where
  schema : TextFits lock.schema
  profile : TextFits lock.profile
  service : TextFits lock.service
  tool : TextFits lock.tool
  schemaDigest : TextFits lock.schema_digest

/-- A representability/hash-framing bound, without any canonicalization or
admission premise. The public parser/serializer boundary must earn this from
its original byte limits, including serialization growth and physical costs. -/
def NativeCanonicalFits (overhead : Nat) (canonical : NativeCanonicalBytes) : Prop :=
  ∀ original, canonical = .Ok original → overhead + original.val.length ≤ sha256InputLimit

def nativeCanonicalOutcome : NativeCanonicalBytes → RecipeLockAdmission.CanonicalOutcome
  | .Err () => .error ()
  | .Ok original => .ok (bytes original)

def nativeLockOutcome : core.result.Result Unit NativeRecipeError → Except NativeRecipeError Unit
  | .Err error => .error error
  | .Ok () => .ok ()

def nativeDigestOutcome : core.result.Result (Array Std.U8 32#usize) NativeRecipeError →
    Except NativeRecipeError (List Nat)
  | .Err error => .error error
  | .Ok digest => .ok (nativeDigestArrayBytes digest)

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open RecipeBinding

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]

set_option maxHeartbeats 12000000
set_option maxRecDepth 4096

@[step] theorem native_canonical_byte_view (original : NativeVec Std.U8) :
    AuthsNativeRecipe.alloc.vec.Vec.as_slice Global original ⦃ view =>
      schemaSliceBytes view = bytes original ∧ view.val = original.val ⦄ := by
  simp [AuthsNativeRecipe.alloc.vec.Vec.as_slice, schemaSliceBytes, bytes,
    native_deref_contents, spec_ok]

/-- Every original metadata field is read from this same lock, and the actual
hash/comparison receives the complete supplied canonical outcome. No digest
match, accepted metadata or serialization success is a premise. -/
@[step] theorem native_validate_lock_exact (hash : List Nat → List Nat)
    (library : NativeSha256LibraryContract hash) (lock : NativeProfileLock)
    (canonical : NativeCanonicalBytes) (fits : NativeProfileLockFits lock)
    (hashRoom : NativeCanonicalFits 0 canonical) :
    AuthsNativeRecipe.recipe.validate_lock lock canonical ⦃ actual =>
      nativeLockOutcome actual = RecipeLockAdmission.validateLock compilerLockErrors hash
        (originalLockMetadata lock) (nativeCanonicalOutcome canonical) ⦄ := by
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
  by_cases metadataValid : MetadataValid (originalLockMetadata lock)
  · have validTrue : valid = true := by simpa [originalMetadata, metadataValid] using metadataMeaning
    simp only [validTrue, Bool.true_eq_true, ↓reduceIte]
    cases canonical with
    | Err reason =>
        cases reason
        simp [nativeLockOutcome, RecipeLockAdmission.validateLock, nativeCanonicalOutcome,
          compilerLockErrors, metadataValid]
    | Ok original =>
        simp only []
        step with native_canonical_byte_view original as ⟨schemaBytes, originalBytes, originalView⟩
        have bounded : schemaBytes.val.length ≤ sha256InputLimit := by
          have bound := hashRoom original rfl
          simpa [originalView] using bound
        step with native_sha256_once_exact hash library schemaBytes bounded as ⟨digest, digestMeaning⟩
        step with native_sha256_into_array_exact digest as ⟨array, arrayMeaning⟩
        step with native_schema_digest_matches_exact declared array as ⟨matches, matchMeaning⟩
        have actualDigest : nativeDigestArrayBytes array = hash (bytes original) := by
          calc
            nativeDigestArrayBytes array = nativeSha256OutputBytes digest := arrayMeaning
            _ = hash (schemaSliceBytes schemaBytes) := digestMeaning
            _ = hash (bytes original) := congrArg hash originalBytes
        have matchMeaning : matches = decide (SchemaDigestMatches (textBytes lock.schema_digest)
            (hash (bytes original))) := by
          simpa [schemaSliceBytes, declaredMeaning, actualDigest] using matchMeaning
        by_cases same : SchemaDigestMatches (textBytes lock.schema_digest) (hash (bytes original))
        · have matched : matches = true := by simpa [same] using matchMeaning
          simp [matched, nativeLockOutcome, RecipeLockAdmission.validateLock, nativeCanonicalOutcome,
            compilerLockErrors, metadataValid, originalLockMetadata, same]
        · have mismatch : matches = false := by simpa [same] using matchMeaning
          simp [mismatch, nativeLockOutcome, RecipeLockAdmission.validateLock, nativeCanonicalOutcome,
            compilerLockErrors, metadataValid, originalLockMetadata, same]
  · have validFalse : valid = false := by simpa [originalMetadata, metadataValid] using metadataMeaning
    simp [validFalse, nativeLockOutcome, RecipeLockAdmission.validateLock, nativeCanonicalOutcome,
      compilerLockErrors, metadataValid]

/-- The actual checked digest hashes the literal recipe domain and the full
retained canonical outcome. This holds for every represented checked record;
being such a record is not an assumption that its source was admitted. -/
@[step] theorem native_checked_recipe_digest_exact (hash : List Nat → List Nat)
    (library : NativeSha256LibraryContract hash)
    (checked : AuthsNativeRecipe.recipe.validate.ValidatedSource)
    (hashRoom : NativeCanonicalFits 32 checked.canonical_source) :
    AuthsNativeRecipe.recipe.validate.ValidatedSource.digest checked ⦃ actual =>
      nativeDigestOutcome actual = RecipeLockAdmission.recipeDigest compilerLockErrors hash
        (nativeCanonicalOutcome checked.canonical_source) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.ValidatedSource.digest
  cases originalOutcome : checked.canonical_source with
  | Err reason =>
      cases reason
      simp [nativeDigestOutcome, RecipeLockAdmission.recipeDigest, nativeCanonicalOutcome,
        compilerLockErrors, originalOutcome]
  | Ok original =>
      simp only [originalOutcome]
      step with native_canonical_byte_view original as ⟨sourceBytes, sourceMeaning, sourceView⟩
      step with native_recipe_digest_input_exact sourceBytes as ⟨input, domainMeaning, originalInput⟩
      have domainSize : input.domain.val.length = 32 := by
        simpa [schemaSliceBytes, compiledRecipeDomain] using congrArg List.length domainMeaning
      have room : input.domain.val.length + input.canonical_source.val.length ≤ sha256InputLimit := by
        have originalRoom := hashRoom original (by simp [originalOutcome])
        simpa [domainSize, originalInput, sourceView] using originalRoom
      step with library.initializes as ⟨initial, initialMeaning⟩
      step with library.absorbs initial [] input.domain initialMeaning
        (by simp; omega) as ⟨afterDomain, domainState⟩
      have domainState : library.stateMeaning afterDomain (schemaSliceBytes input.domain) := by
        simpa [schemaSliceBytes] using domainState
      step with library.absorbs afterDomain (schemaSliceBytes input.domain) input.canonical_source domainState
        (by simpa [schemaSliceBytes] using room) as ⟨afterSource, sourceState⟩
      step with library.finalizes afterSource
        (schemaSliceBytes input.domain ++ schemaSliceBytes input.canonical_source) sourceState
        (by simpa [schemaSliceBytes] using room) as ⟨digest, digestMeaning⟩
      step with native_sha256_into_array_exact digest as ⟨array, arrayMeaning⟩
      have actualDigest : nativeDigestArrayBytes array =
          hash (compiledRecipeDomain ++ bytes original) := by
        have originalPreimage : schemaSliceBytes input.domain ++ schemaSliceBytes input.canonical_source =
            compiledRecipeDomain ++ bytes original := by
          rw [domainMeaning, originalInput, sourceMeaning]
        calc
          nativeDigestArrayBytes array = nativeSha256OutputBytes digest := arrayMeaning
          _ = hash (schemaSliceBytes input.domain ++ schemaSliceBytes input.canonical_source) := digestMeaning
          _ = hash (compiledRecipeDomain ++ bytes original) := congrArg hash originalPreimage
      simp [nativeDigestOutcome, RecipeLockAdmission.recipeDigest, nativeCanonicalOutcome,
        compilerLockErrors, originalOutcome, digestPreimage, actualDigest]

/-- Acceptance earns the declared digest comparison against these original
schema bytes; it cannot assume that comparison in a caller premise. -/
theorem native_lock_acceptance_earns_digest (hash : List Nat → List Nat)
    (library : NativeSha256LibraryContract hash) (lock : NativeProfileLock)
    (canonical : NativeCanonicalBytes) (fits : NativeProfileLockFits lock)
    (hashRoom : NativeCanonicalFits 0 canonical) :
    AuthsNativeRecipe.recipe.validate_lock lock canonical ⦃ actual =>
      actual = .Ok () → MetadataValid (originalLockMetadata lock) ∧
        ∃ original, canonical = .Ok original ∧
          SchemaDigestMatches (textBytes lock.schema_digest) (hash (bytes original)) ⦄ := by
  apply spec_mono (native_validate_lock_exact hash library lock canonical fits hashRoom)
  intro actual meaning accepted
  have admitted : RecipeLockAdmission.validateLock compilerLockErrors hash
      (originalLockMetadata lock) (nativeCanonicalOutcome canonical) = .ok () := by
    simpa [accepted, nativeLockOutcome] using meaning.symm
  obtain ⟨metadata, modelBytes, canonicalMeaning, digestMeaning⟩ :=
    (RecipeLockAdmission.lock_success_earns_original_digest compilerLockErrors hash
      (originalLockMetadata lock) (nativeCanonicalOutcome canonical)).mp admitted
  refine ⟨metadata, ?_⟩
  cases canonical with
  | Err reason => cases reason; simp [nativeCanonicalOutcome] at canonicalMeaning
  | Ok original =>
      have same : modelBytes = bytes original := by
        simpa [nativeCanonicalOutcome] using canonicalMeaning.symm
      exact ⟨original, rfl, by simpa [originalLockMetadata, same] using digestMeaning⟩

end Auths.Product.NativeCompiler.Refinement
