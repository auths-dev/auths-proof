import Auths.Product.NativeCompilerByteSlices
import Auths.Product.NativeCompilerOrigin

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

/-- Transparent normal form of the source's final byte checks. The actual
origin-domain theorem must match this expression; it is not an opaque Auths
validator or supplied successful predicate. -/
def nativeDomainChecks (policy : Slice Std.U8) : Result Bool := do
  let localhost ← AuthsNativeRecipe.auths_gateway_kernel.construct.field_name_equal policy (toStr "localhost")
  if localhost then ok false
  else do
    let localhostSuffix ← AuthsNativeRecipe.core.slice.Slice.ends_with core.cmp.PartialEqU8 policy (toStr ".localhost")
    if localhostSuffix then ok false
    else do
      let local ← AuthsNativeRecipe.auths_gateway_kernel.construct.field_name_equal policy (toStr "local")
      if local then ok false
      else do
        let localSuffix ← AuthsNativeRecipe.core.slice.Slice.ends_with core.cmp.PartialEqU8 policy (toStr ".local")
        if localSuffix then ok false
        else do
          let internalSuffix ← AuthsNativeRecipe.core.slice.Slice.ends_with core.cmp.PartialEqU8 policy (toStr ".internal")
          if internalSuffix then ok false
          else core.slice.Slice.contains core.cmp.PartialEqU8 policy 46#u8

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open RecipeOriginAdmission

set_option maxHeartbeats 10000000
set_option maxRecDepth 4096

@[step] theorem native_domain_checks_exact (policy : Slice Std.U8) :
    nativeDomainChecks policy ⦃ actual => actual = decide (DomainChecks (schemaSliceBytes policy)) ⦄ := by
  unfold nativeDomainChecks
  repeat' first
    | step with native_schema_byte_equality
    | step with native_byte_suffix_exact
    | step with native_byte_contains_exact
    | split
  all_goals simp_all [DomainChecks, localhost, local, internalSuffix, schemaSliceBytes]

/-- The source's exact case-sensitive hostname policy: at most 253 bytes,
remove one terminal root dot, reject the named local suffixes, and require a
remaining dot. This alone proves no DNS resolution or public IP property. -/
@[step] theorem native_origin_domain_exact (input : Str) :
    AuthsNativeRecipe.recipe.origin_domain_allowed input ⦃ actual =>
      actual = decide (DomainPolicy (schemaSliceBytes input)) ⦄ := by
  unfold AuthsNativeRecipe.recipe.origin_domain_allowed
  step with native_str_size_exact input as ⟨size, sizeMeaning⟩
  by_cases large : 253 < input.val.length
  · have nativeLarge : size > 253#usize := by scalar_tac
    simp [nativeLarge, DomainPolicy, schemaSliceBytes, Nat.not_le.mpr large]
  · have bounded : input.val.length ≤ 253 := by omega
    have nativeBound : ¬size > 253#usize := by scalar_tac
    simp only [nativeBound, ↓reduceIte,
      AuthsNativeRecipe.core.str.Str.as_bytes, _root_.core.str.Str.as_bytes, bind_tc_ok]
    have finish (endValue : Std.Usize) (within : endValue.val ≤ input.val.length)
        (policyMeaning : (input.val.take endValue.val).map (·.val) = policyName (schemaSliceBytes input)) :
        (do
          let policy ← core.slice.index.Slice.index
            (core.slice.index.SliceIndexRangeToUsizeSlice Std.U8) input { «end» := endValue }
          nativeDomainChecks policy) ⦃ actual => actual = decide (DomainPolicy (schemaSliceBytes input)) ⦄ := by
      step with core.slice.index.SliceIndexRangeToUsizeSlice.index.step_spec
        { «end» := endValue } input (by scalar_tac) as ⟨policy, policyValue, policyLength⟩
      apply spec_mono (native_domain_checks_exact policy)
      intro actual meaning
      have original : schemaSliceBytes policy = policyName (schemaSliceBytes input) := by
        simpa [schemaSliceBytes, policyValue, List.slice] using policyMeaning
      simpa [DomainPolicy, schemaSliceBytes, bounded, original] using meaning
    by_cases nonempty : 0 < input.val.length
    · have nativeNonempty : input.len > 0#usize := by scalar_tac
      simp only [nativeNonempty, ↓reduceIte]
      step as ⟨lastIndex, indexMeaning⟩
      have index : lastIndex.val = input.val.length - 1 := by scalar_tac
      have inside : lastIndex.val < input.val.length := by omega
      step with Slice.index_usize_spec input lastIndex inside as ⟨last, lastMeaning⟩
      have originalLast : (schemaSliceBytes input).getLast? = some last.val := by
        rw [List.getLast?_eq_getElem?]
        simp only [schemaSliceBytes, List.length_map, List.getElem?_map]
        rw [← index]
        simp [inside, lastMeaning]
      by_cases dot : last.val = 46
      · have nativeDot : last = 46#u8 := by scalar_tac
        simp only [nativeDot, ↓reduceIte, bind_tc_ok]
        apply finish lastIndex (by omega)
        simp [policyName, originalLast, dot, schemaSliceBytes, index, List.take_map]
      · have nativeDot : last ≠ 46#u8 := by scalar_tac
        simp only [nativeDot, ↓reduceIte, bind_tc_ok]
        apply finish input.len (by simp)
        simp [policyName, originalLast, dot]
    · have empty : input.val = [] := List.eq_nil_of_length_eq_zero (by omega)
      have nativeEmpty : ¬input.len > 0#usize := by scalar_tac
      simp only [nativeEmpty, ↓reduceIte, bind_tc_ok]
      apply finish input.len (by simp)
      simp [empty, schemaSliceBytes, policyName]

end Auths.Product.NativeCompiler.Refinement
