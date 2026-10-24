import Auths.Product.RecipeBinding
import Auths.Product.DerivedTokensRefinement
import Auths.Product.Refinement.ByteIdentity

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway
open Auths.Product.Refinement.ByteIdentity
open Auths.Product.DerivedTokens

namespace Auths.Product.RecipeBinding.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

/-! Source bodies target the shipping byte helpers. Actual generation and ABI
inspection, followed by elaboration/repairs, are deferred with the rest of this
coding batch. No native serde/canonicalizer/SHA or whole compiler theorem is
asserted here. -/

def bindingOf (binding : recipe_binding.ProfileBinding) : Binding :=
  ⟨sliceBytes binding.service, sliceBytes binding.tool, sliceBytes binding.schema_digest⟩

def metadataOf (lock : recipe_binding.LockMetadata) : Metadata :=
  ⟨sliceBytes lock.schema, lock.generator_format.val, lock.version.val,
    sliceBytes lock.profile, bindingOf lock.binding⟩

def inputOf (input : recipe_binding.RecipeDigestInput) : DigestInput :=
  ⟨sliceBytes input.domain, sliceBytes input.canonical_source⟩

private theorem exact_bytes (left right : Slice Std.U8) :
    construct.field_name_equal left right ⦃ actual =>
      actual = decide (sliceBytes left = sliceBytes right) ⦄ := by
  simpa only [sliceBytes, byteList_inj] using field_name_equal_exact left right

@[step] theorem lower_hex_byte_exact (byte : Std.U8) :
    recipe_binding.lower_hex_byte byte ⦃ actual => actual = decide (HexDigit byte.val) ⦄ := by
  simp [recipe_binding.lower_hex_byte, HexDigit, UScalar.le_equiv,
    Bool.and_eq_true, Bool.or_eq_true, decide_and, decide_or]

@[step] theorem lower_hex_scan_exact (bytes : Slice Std.U8) :
    recipe_binding.lower_hex_digest_loop bytes 0#usize ⦃ actual =>
      actual = decide (∀ byte ∈ sliceBytes bytes, HexDigit byte) ⦄ := by
  unfold recipe_binding.lower_hex_digest_loop
  apply loop.spec_decr_nat
    (measure := fun index => bytes.val.length - index.val)
    (inv := fun index => index.val ≤ bytes.val.length ∧
      ∀ byte ∈ bytes.val.take index.val, HexDigit byte.val)
  · intro index invariant
    unfold recipe_binding.lower_hex_digest_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < bytes.val.length := by simpa using within
      step as ⟨byte, byteAt⟩
      step with lower_hex_byte_exact as ⟨allowed, meaning⟩
      cases allowed
      · have invalid : ¬HexDigit byte.val := by simpa using meaning.symm
        have member : byte.val ∈ sliceBytes bytes := List.mem_map.mpr
          ⟨byte, List.mem_iff_getElem?.mpr ⟨index.val, by simpa [byteAt] using List.getElem?_eq_getElem inside⟩, rfl⟩
        have refused : ¬∀ current ∈ sliceBytes bytes, HexDigit current := fun all => invalid (all _ member)
        simp [refused]
      · have valid : HexDigit byte.val := by simpa using meaning.symm
        simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
        step as ⟨next, nextValue⟩
        refine ⟨by omega, ?_, by omega⟩
        rw [nextValue, List.take_succ_eq_append_getElem inside]
        intro current member
        simp only [List.mem_append, List.mem_singleton] at member
        rcases member with earlier | current
        · exact invariant.2 _ earlier
        · simpa [current, byteAt] using valid
    · simp only [spec_ok]
      have atEnd : bytes.val.length ≤ index.val := by simpa using within
      have valid : ∀ byte ∈ sliceBytes bytes, HexDigit byte := by
        intro byte member
        obtain ⟨current, member, same⟩ := List.mem_map.mp member
        simpa [same] using invariant.2 current (by simpa [List.take_of_length_le atEnd] using member)
      simp [valid]
  · exact ⟨by simp, by simp⟩

@[step] theorem lower_hex_digest_exact (bytes : Slice Std.U8) :
    recipe_binding.lower_hex_digest bytes ⦃ actual =>
      actual = decide (LowerHexDigest (sliceBytes bytes)) ⦄ := by
  unfold recipe_binding.lower_hex_digest
  by_cases size : bytes.val.length = 64
  · have nativeSize : bytes.len = 64#usize := by scalar_tac
    simp only [nativeSize, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
    apply spec_mono (lower_hex_scan_exact bytes)
    intro actual meaning
    simpa [LowerHexDigest, sliceBytes, byteList, size] using meaning
  · have nativeSize : bytes.len ≠ 64#usize := by scalar_tac
    simp [nativeSize, LowerHexDigest, sliceBytes, byteList, size]

@[step] theorem source_schema_supported_exact (schema : Slice Std.U8) :
    recipe_binding.source_schema_supported schema ⦃ actual =>
      actual = decide (sliceBytes schema = sourceSchema) ⦄ := by
  unfold recipe_binding.source_schema_supported
  step with exact_bytes as ⟨actual, meaning⟩
  simpa [recipe_binding.SOURCE_SCHEMA_BYTES, recipe_binding.SOURCE_SCHEMA,
    sourceSchema, sliceBytes, byteList] using meaning

@[step] theorem source_matches_profile_exact (source lock : recipe_binding.ProfileBinding) :
    recipe_binding.source_matches_profile source lock ⦃ actual =>
      actual = decide (SourceMatches (bindingOf source) (bindingOf lock)) ⦄ := by
  unfold recipe_binding.source_matches_profile
  step with exact_bytes as ⟨service, serviceMeaning⟩
  cases service
  · simp_all [SourceMatches, bindingOf]
  · step with exact_bytes as ⟨tool, toolMeaning⟩
    cases tool
    · simp_all [SourceMatches, bindingOf]
    · step with exact_bytes as ⟨actual, digestMeaning⟩
      simp_all [SourceMatches, bindingOf]

@[step] theorem lock_metadata_valid_exact (lock : recipe_binding.LockMetadata) :
    recipe_binding.lock_metadata_valid lock ⦃ actual =>
      actual = decide (MetadataValid (metadataOf lock)) ⦄ := by
  unfold recipe_binding.lock_metadata_valid
  step with exact_bytes as ⟨schema, schemaMeaning⟩
  cases schema
  · simp_all [MetadataValid, metadataOf, bindingOf, recipe_binding.LOCK_SCHEMA_BYTES,
      recipe_binding.LOCK_SCHEMA, lockSchema, sliceBytes, byteList]
  · simp only [Bool.true_eq_true, ↓reduceIte]
    split_ifs <;>
      try { simp_all [MetadataValid, metadataOf, bindingOf, UScalar.eq_equiv,
        core.slice.Slice.is_empty, sliceBytes, byteList, recipe_binding.LOCK_SCHEMA_BYTES,
        recipe_binding.LOCK_SCHEMA, lockSchema] }
    step with lower_hex_digest_exact as ⟨actual, meaning⟩
    simp_all [MetadataValid, metadataOf, bindingOf, UScalar.eq_equiv,
      core.slice.Slice.is_empty, sliceBytes, byteList, recipe_binding.LOCK_SCHEMA_BYTES,
      recipe_binding.LOCK_SCHEMA, lockSchema]

@[step] theorem schema_digest_matches_exact (declared : Slice Std.U8) (digest : Array Std.U8 32#usize) :
    recipe_binding.schema_digest_matches declared digest ⦃ actual =>
      actual = decide (SchemaDigestMatches (sliceBytes declared)
        (DerivedTokens.Refinement.digestBytes digest)) ⦄ := by
  unfold recipe_binding.schema_digest_matches
  step with DerivedTokens.Refinement.append_digest_hex_exact as ⟨encoded, encodedMeaning⟩
  step with exact_bytes as ⟨actual, meaning⟩
  simpa [SchemaDigestMatches, alloc.vec.Vec.deref, sliceBytes, vecBytes,
    encodedMeaning] using meaning

@[step] theorem recipe_digest_input_exact (canonicalSource : Slice Std.U8) :
    recipe_binding.recipe_digest_input canonicalSource ⦃ actual =>
      inputOf actual = recipeInput (sliceBytes canonicalSource) ∧
        actual.canonical_source = canonicalSource ⦄ := by
  simp [recipe_binding.recipe_digest_input, recipe_binding.COMPILED_RECIPE_DOMAIN,
    inputOf, recipeInput, compiledRecipeDomain, sliceBytes, byteList, spec_ok]

theorem source_matched_profile_has_exact_components (source lock : recipe_binding.ProfileBinding) :
    recipe_binding.source_matches_profile source lock ⦃ actual =>
      actual = true ↔ bindingOf source = bindingOf lock ⦄ := by
  apply spec_mono (source_matches_profile_exact source lock)
  intro actual meaning
  simpa [meaning] using source_matches_iff_equal (bindingOf source) (bindingOf lock)

theorem source_digest_comparison_earns_metadata_spelling
    (declared : Slice Std.U8) (digest : Array Std.U8 32#usize) :
    recipe_binding.schema_digest_matches declared digest ⦃ actual =>
      actual = true → LowerHexDigest (sliceBytes declared) ⦄ := by
  apply spec_mono (schema_digest_matches_exact declared digest)
  intro actual meaning accepted
  have matches : SchemaDigestMatches (sliceBytes declared) (DerivedTokens.Refinement.digestBytes digest) := by
    simpa [accepted] using meaning.symm
  exact actual_digest_spelling_is_admitted _ _ (DerivedTokens.Refinement.digest_size digest)
    (DerivedTokens.Refinement.digest_byte_bounds digest) matches

theorem source_digest_input_retains_exact_preimage (canonicalSource : Slice Std.U8) :
    recipe_binding.recipe_digest_input canonicalSource ⦃ actual =>
      sliceBytes actual.domain ++ sliceBytes actual.canonical_source =
        digestPreimage (sliceBytes canonicalSource) ∧ actual.canonical_source = canonicalSource ⦄ := by
  apply spec_mono (recipe_digest_input_exact canonicalSource)
  intro actual meaning
  have chunks := congrArg (fun input : DigestInput => input.domain ++ input.canonicalSource) meaning.1
  exact ⟨by simpa [inputOf, recipe_input_has_exact_preimage] using chunks, meaning.2⟩

end Auths.Product.RecipeBinding.Refinement
