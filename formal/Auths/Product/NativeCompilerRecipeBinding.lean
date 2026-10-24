import Auths.Product.NativeCompilerBytes
import Auths.Product.RecipeBinding

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

abbrev NativeLockMetadata := AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.LockMetadata
abbrev NativeProfileBinding := AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.ProfileBinding

def nativeProfileBinding (binding : NativeProfileBinding) : RecipeBinding.Binding :=
  ⟨schemaSliceBytes binding.service, schemaSliceBytes binding.tool, schemaSliceBytes binding.schema_digest⟩

def nativeLockMetadata (lock : NativeLockMetadata) : RecipeBinding.Metadata :=
  ⟨schemaSliceBytes lock.schema, lock.generator_format.val, lock.version.val,
    schemaSliceBytes lock.profile, nativeProfileBinding lock.binding⟩

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open RecipeBinding DerivedTokens

set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

@[step] theorem native_lower_hex_byte_exact (byte : Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.lower_hex_byte byte ⦃ actual =>
      actual = decide (HexDigit byte.val) ⦄ := by
  by_cases digitMin : 48 ≤ byte.val <;>
    by_cases digitMax : byte.val ≤ 57 <;>
    by_cases letterMin : 97 ≤ byte.val <;>
    by_cases letterMax : byte.val ≤ 102 <;>
    simp_all [AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.lower_hex_byte,
      HexDigit, UScalar.le_equiv, UScalar.lt_equiv, spec_ok] <;> omega

private theorem native_lower_hex_suffix (input : Slice Std.U8) (position : Std.Usize)
    (bound : position.val ≤ input.val.length) :
    AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.lower_hex_digest_loop input position ⦃ actual =>
      actual = decide (∀ byte ∈ input.val.drop position.val, HexDigit byte.val) ⦄ := by
  generalize remaining : input.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.lower_hex_digest_loop
      split <;> rename_i within
      · have inside : position.val < input.val.length := by simpa using within
        step with Slice.index_usize_spec input position inside as ⟨byte, byteAt⟩
        step with native_lower_hex_byte_exact byte as ⟨good, goodMeaning⟩
        by_cases valid : HexDigit byte.val
        · have accepted : good = true := by simpa [valid] using goodMeaning
          simp only [accepted, Bool.true_eq_true, ↓reduceIte]
          step as ⟨next, nextValue⟩
          have nextBound : next.val ≤ input.val.length := by omega
          have smaller : input.val.length - next.val < count := by omega
          apply spec_mono (ih _ smaller next nextBound rfl)
          intro actual meaning
          have suffix : input.val.drop position.val = byte :: input.val.drop next.val := by
            simpa only [byteAt, nextValue] using List.drop_eq_getElem_cons inside
          simpa only [suffix, List.mem_cons, forall_eq_or_imp, valid, true_and] using meaning
        · have refused : good = false := by simpa [valid] using goodMeaning
          have next : input.val.drop position.val = byte :: input.val.drop (position.val + 1) := by
            simpa only [byteAt] using List.drop_eq_getElem_cons inside
          simp [refused, next, valid]
      · have ended : input.val.length ≤ position.val := by simpa using within
        simp [List.drop_eq_nil_of_le ended]

@[step] theorem native_lower_hex_digest_exact (input : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.lower_hex_digest input ⦃ actual =>
      actual = decide (LowerHexDigest (schemaSliceBytes input)) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.lower_hex_digest
  by_cases size : input.val.length = 64
  · have nativeSize : input.len = 64#usize := by scalar_tac
    simp only [nativeSize, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
    apply spec_mono (native_lower_hex_suffix input 0#usize (by simp))
    intro actual meaning
    simpa [LowerHexDigest, schemaSliceBytes, size, List.mem_map] using meaning
  · have wrong : input.len ≠ 64#usize := by scalar_tac
    simp [wrong, LowerHexDigest, schemaSliceBytes, size]

@[step] theorem native_source_schema_exact (schema : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.source_schema_supported schema ⦃ actual =>
      actual = decide (schemaSliceBytes schema = sourceSchema) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.source_schema_supported
  simp only [AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.SOURCE_SCHEMA_BYTES,
    AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.SOURCE_SCHEMA,
    core.str.Str.as_bytes, bind_tc_ok]
  apply spec_mono (native_schema_byte_equality schema _)
  intro actual meaning
  simpa [schemaSliceBytes, sourceSchema] using meaning

@[step] theorem native_source_profile_binding_exact (source lock : NativeProfileBinding) :
    AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.source_matches_profile source lock ⦃ actual =>
      actual = decide (SourceMatches (nativeProfileBinding source) (nativeProfileBinding lock)) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.source_matches_profile
  step with native_schema_byte_equality source.service lock.service as ⟨service, serviceMeaning⟩
  by_cases sameService : schemaSliceBytes source.service = schemaSliceBytes lock.service
  · have serviceTrue : service = true := by simpa [sameService] using serviceMeaning
    simp only [serviceTrue, Bool.true_eq_true, ↓reduceIte]
    step with native_schema_byte_equality source.tool lock.tool as ⟨tool, toolMeaning⟩
    by_cases sameTool : schemaSliceBytes source.tool = schemaSliceBytes lock.tool
    · have toolTrue : tool = true := by simpa [sameTool] using toolMeaning
      simp only [toolTrue, Bool.true_eq_true, ↓reduceIte]
      apply spec_mono (native_schema_byte_equality source.schema_digest lock.schema_digest)
      intro actual digestMeaning
      simpa [SourceMatches, nativeProfileBinding, sameService, sameTool] using digestMeaning
    · have toolFalse : tool = false := by simpa [sameTool] using toolMeaning
      simp [toolFalse, SourceMatches, nativeProfileBinding, sameService, sameTool]
  · have serviceFalse : service = false := by simpa [sameService] using serviceMeaning
    simp [serviceFalse, SourceMatches, nativeProfileBinding, sameService]

@[step] theorem native_lock_metadata_exact (lock : NativeLockMetadata) :
    AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.lock_metadata_valid lock ⦃ actual =>
      actual = decide (MetadataValid (nativeLockMetadata lock)) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.lock_metadata_valid
  simp only [AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.LOCK_SCHEMA_BYTES,
    AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.LOCK_SCHEMA,
    core.str.Str.as_bytes, bind_tc_ok]
  step with native_schema_byte_equality lock.schema _ as ⟨schema, schemaMeaning⟩
  by_cases schemaValid : schemaSliceBytes lock.schema = lockSchema
  · have schemaTrue : schema = true := by simpa [schemaSliceBytes, lockSchema, schemaValid] using schemaMeaning
    simp only [schemaTrue, Bool.true_eq_true, ↓reduceIte]
    by_cases format : lock.generator_format.val = 2
    · have nativeFormat : lock.generator_format = 2#u8 := by scalar_tac
      simp only [nativeFormat, ↓reduceIte]
      by_cases version : lock.version.val = 0
      · have nativeVersion : lock.version = 0#u16 := by scalar_tac
        simp [nativeVersion, MetadataValid, nativeLockMetadata, version]
      · have nativeVersion : lock.version ≠ 0#u16 := by scalar_tac
        simp only [nativeVersion, ne_eq, not_false_eq_true, ↓reduceIte]
        step as ⟨profileEmpty, profileMeaning⟩
        by_cases profile : lock.profile.val = []
        · simp_all [MetadataValid, nativeLockMetadata, nativeProfileBinding,
            core.slice.Slice.is_empty, schemaSliceBytes]
        · have profileFalse : profileEmpty = false := by
            simpa [List.length_eq_zero_iff, profile] using profileMeaning
          simp only [profileFalse, Bool.false_eq_true, ↓reduceIte]
          step as ⟨serviceEmpty, serviceMeaning⟩
          by_cases service : lock.binding.service.val = []
          · simp_all [MetadataValid, nativeLockMetadata, nativeProfileBinding,
              core.slice.Slice.is_empty, schemaSliceBytes]
          · have serviceFalse : serviceEmpty = false := by
              simpa [List.length_eq_zero_iff, service] using serviceMeaning
            simp only [serviceFalse, Bool.false_eq_true, ↓reduceIte]
            step as ⟨toolEmpty, toolMeaning⟩
            by_cases tool : lock.binding.tool.val = []
            · simp_all [MetadataValid, nativeLockMetadata, nativeProfileBinding,
                core.slice.Slice.is_empty, schemaSliceBytes]
            · have toolFalse : toolEmpty = false := by
                simpa [List.length_eq_zero_iff, tool] using toolMeaning
              simp only [toolFalse, Bool.false_eq_true, ↓reduceIte]
              apply spec_mono (native_lower_hex_digest_exact lock.binding.schema_digest)
              intro actual digestMeaning
              simpa [MetadataValid, nativeLockMetadata, nativeProfileBinding, schemaValid,
                format, version, profile, service, tool, schemaSliceBytes] using digestMeaning
    · have nativeFormat : lock.generator_format ≠ 2#u8 := by scalar_tac
      simp [nativeFormat, MetadataValid, nativeLockMetadata, format]
  · have schemaFalse : schema = false := by simpa [schemaSliceBytes, lockSchema, schemaValid] using schemaMeaning
    simp [schemaFalse, MetadataValid, nativeLockMetadata, schemaValid]

@[step] theorem native_recipe_digest_input_exact (original : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.recipe_digest_input original ⦃ actual =>
      schemaSliceBytes actual.domain = compiledRecipeDomain ∧ actual.canonical_source = original ⦄ := by
  simp [AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.recipe_digest_input,
    AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.COMPILED_RECIPE_DOMAIN,
    schemaSliceBytes, compiledRecipeDomain, spec_ok]

end Auths.Product.NativeCompiler.Refinement
