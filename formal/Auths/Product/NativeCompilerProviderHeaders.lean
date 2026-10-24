import Auths.Product.NativeCompilerHeaders
import Auths.Product.NativeCompilerConsumption

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel HeaderCompiler
set_option maxHeartbeats 16000000
set_option maxRecDepth 4096

private theorem native_provider_rows_loop (iterator : AuthsNativeRecipe.alloc.collections.btree.map.Iter String String)
    (fits : ∀ pair ∈ iterator.val, TextFits pair.1 ∧ TextFits pair.2) :
    AuthsNativeRecipe.recipe.validate.provider_versions_valid_loop iterator ⦃ actual =>
      actual = decide (∀ pair ∈ iterator.val, VersionValid (textBytes pair.1) (textBytes pair.2)) ⦄ := by
  generalize remaining : iterator.val.length = count
  induction count using Nat.strong_induction_on generalizing iterator with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.provider_versions_valid_loop
      step with next_pair_exact iterator as ⟨next, nextMeaning⟩
      cases original : iterator.val with
      | nil =>
          have ended : next.1 = none := (by simpa [original] using nextMeaning).1
          simp [ended, original]
      | cons pair rest =>
          obtain ⟨headAt, tailAt⟩ : next.1 = some pair ∧ next.2.val = rest := by simpa [original] using nextMeaning
          simp only [headAt]
          have pairFits := fits pair (by simp [original])
          step with borrow_text_exact pair.1 pairFits.1 as ⟨name, nameMeaning⟩
          step with borrow_text_exact pair.2 pairFits.2 as ⟨value, valueMeaning⟩
          step with native_version_header_exact name value as ⟨valid, validity⟩
          have originalValidity : valid = decide (VersionValid (textBytes pair.1) (textBytes pair.2)) := by
            simpa [nameMeaning, valueMeaning] using validity
          cases valid with
          | false => simp [original, ← originalValidity]
          | true =>
              simp only [Bool.true_eq_true, ↓reduceIte]
              apply spec_mono (ih _ (by simp [original, tailAt] at *; omega) next.2
                (fun member present => fits member (by simp [original, tailAt] at present ⊢; exact Or.inr present)) rfl)
              intro actual meaning
              simpa [original, tailAt, ← originalValidity] using meaning

@[step] theorem native_provider_rows_exact (headers : NativeHeaders)
    (fits : ∀ pair ∈ headers.entries.val, TextFits pair.1 ∧ TextFits pair.2) :
    AuthsNativeRecipe.recipe.validate.provider_versions_valid headers ⦃ actual =>
      actual = decide (∀ row ∈ originalHeaders headers, VersionValid row.1 row.2) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.provider_versions_valid
    AuthsNativeRecipe.SharedABTreeMap.Insts.CoreIterTraitsCollectIntoIteratorPairSharedAKSharedAVIter.into_iter
  simp only [bind_tc_ok]
  apply spec_mono (native_provider_rows_loop headers.entries fits)
  intro actual meaning
  simpa [originalHeaders, List.forall_mem_map] using meaning

private theorem native_provider_copy_loop (iterator : AuthsNativeRecipe.alloc.collections.btree.map.Iter String String)
    (output : NativeVec NativeNamedHeader)
    (fits : ∀ pair ∈ iterator.val, TextFits pair.1 ∧ TextFits pair.2)
    (room : output.val.length + iterator.val.length ≤ Usize.max) :
    AuthsNativeRecipe.recipe.validate.provider_version_entries_loop iterator output ⦃ actual =>
      loweredHeaders actual = loweredHeaders output ++ iterator.val.map (fun pair => (textBytes pair.1, textBytes pair.2)) ⦄ := by
  generalize remaining : iterator.val.length = count
  induction count using Nat.strong_induction_on generalizing iterator output with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.provider_version_entries_loop
      step with next_pair_exact iterator as ⟨next, nextMeaning⟩
      cases original : iterator.val with
      | nil =>
          have ended : next.1 = none := (by simpa [original] using nextMeaning).1
          simp [ended, original]
      | cons pair rest =>
          obtain ⟨headAt, tailAt⟩ : next.1 = some pair ∧ next.2.val = rest := by simpa [original] using nextMeaning
          simp only [headAt]
          have pairFits := fits pair (by simp [original])
          step with borrow_text_exact pair.1 pairFits.1 as ⟨name, nameMeaning⟩
          step with copy_u8_exact name as ⟨copiedName, copiedNameMeaning⟩
          step with borrow_text_exact pair.2 pairFits.2 as ⟨value, valueMeaning⟩
          step with copy_u8_exact value as ⟨copiedValue, copiedValueMeaning⟩
          let row : NativeNamedHeader := ⟨copiedName, copiedValue⟩
          step with native_push_exact output row (by simp [original] at room; omega) as ⟨updated, appended⟩
          have nextRoom : updated.val.length + next.2.val.length ≤ Usize.max := by
            simp [appended, original, tailAt] at *; omega
          apply spec_mono (ih _ (by simp [original, tailAt] at *; omega) next.2 updated
            (fun member present => fits member (by simp [original, tailAt] at present ⊢; exact Or.inr present)) nextRoom rfl)
          intro actual meaning
          simpa [loweredHeaders, appended, original, tailAt, row,
            copiedNameMeaning, copiedValueMeaning, nameMeaning, valueMeaning,
            List.append_assoc] using meaning

@[step] theorem native_provider_entries_exact (headers : NativeHeaders)
    (fits : ∀ pair ∈ headers.entries.val, TextFits pair.1 ∧ TextFits pair.2) :
    AuthsNativeRecipe.recipe.validate.provider_version_entries headers ⦃ actual =>
      loweredHeaders actual = originalHeaders headers ∧ actual.val.length = headers.entries.val.length ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.provider_version_entries
    AuthsNativeRecipe.SharedABTreeMap.Insts.CoreIterTraitsCollectIntoIteratorPairSharedAKSharedAVIter.into_iter
  simp only [bind_tc_ok]
  apply spec_mono (native_provider_copy_loop headers.entries (AuthsNativeRecipe.alloc.vec.Vec.new NativeNamedHeader)
    fits (by simpa [native_empty_contents] using headers.entries.toBase.property))
  intro actual meaning
  have copied : loweredHeaders actual = originalHeaders headers := by
    simpa [loweredHeaders, originalHeaders, native_empty_contents] using meaning
  exact ⟨copied, by simpa [loweredHeaders, originalHeaders] using congrArg List.length copied⟩

/-- Complete source provider-header acceptance/refusal. Every copied row is
the original name/value pair, and the real kernel validator earns distinctness
and the closed version catalog after the source's own row checks. -/
@[step] theorem native_provider_headers_admission_exact (headers : NativeHeaders)
    (fits : ∀ pair ∈ headers.entries.val, TextFits pair.1 ∧ TextFits pair.2) :
    AuthsNativeRecipe.recipe.validate.validate_provider_headers headers ⦃ actual =>
      actual = consumptionVerdict (if VersionsValid (originalHeaders headers) then .ok () else .error .invalidProviderHeader) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.validate_provider_headers
  simp only [AuthsNativeRecipe.alloc.collections.btree.map.BTreeMap.is_empty, bind_tc_ok]
  by_cases empty : headers.entries.val = []
  · simp [empty, originalHeaders, VersionsValid, consumptionVerdict, consumptionError]
  · simp only [List.isEmpty_eq_false.mpr empty, Bool.false_eq_true, ↓reduceIte]
    step as ⟨size, sizeMeaning⟩
    by_cases large : 2 < headers.entries.val.length
    · have nativeLarge : size > AuthsNativeRecipe.recipe.validate.MAX_PROVIDER_HEADERS := by
        simp [AuthsNativeRecipe.recipe.validate.MAX_PROVIDER_HEADERS,
          AuthsNativeRecipe.auths_gateway_kernel.header_compiler.MAX_PROVIDER_HEADERS]; scalar_tac
      have invalid : ¬VersionsValid (originalHeaders headers) := by
        simp only [VersionsValid, originalHeaders, List.length_map]
        omega
      simp [nativeLarge, invalid, consumptionVerdict, consumptionError]
    · have nativeWithin : ¬size > AuthsNativeRecipe.recipe.validate.MAX_PROVIDER_HEADERS := by
        simp [AuthsNativeRecipe.recipe.validate.MAX_PROVIDER_HEADERS,
          AuthsNativeRecipe.auths_gateway_kernel.header_compiler.MAX_PROVIDER_HEADERS]; scalar_tac
      simp only [nativeWithin, ↓reduceIte]
      step with native_provider_rows_exact headers fits as ⟨valid, validity⟩
      cases valid with
      | false =>
          have invalid : ¬VersionsValid (originalHeaders headers) := by
            intro admitted
            have rows := admitted.2.2.2
            simp [rows] at validity
          simp [invalid, consumptionVerdict, consumptionError]
      | true =>
          simp only [Bool.true_eq_true, ↓reduceIte]
          step with native_provider_entries_exact headers fits as ⟨copied, original, count⟩
          step with native_versions_valid_exact (AuthsNativeRecipe.alloc.vec.Vec.deref copied) as ⟨accepted, acceptance⟩
          have originalAcceptance : accepted = decide (VersionsValid (originalHeaders headers)) := by
            simpa [nativeVersions, loweredHeaders, original] using acceptance
          cases accepted <;> simp [← originalAcceptance, consumptionVerdict, consumptionError]

theorem native_provider_headers_success_safe (headers : NativeHeaders)
    (fits : ∀ pair ∈ headers.entries.val, TextFits pair.1 ∧ TextFits pair.2) :
    AuthsNativeRecipe.recipe.validate.validate_provider_headers headers ⦃ actual =>
      actual = .Ok () → headers.entries.val.length ≤ 2 ∧
        ∀ row ∈ originalHeaders headers, row.1.length ≤ 20 ∧ row.2.length ≤ 64 ∧
          row.1 ≠ stripeAccountName ∧
          ∀ byte ∈ row.2, byte < 128 ∧ byte ≠ 0 ∧ byte ≠ 10 ∧ byte ≠ 13 ⦄ := by
  apply spec_mono (native_provider_headers_admission_exact headers fits)
  intro actual meaning success
  have valid : VersionsValid (originalHeaders headers) := by
    by_contra invalid
    simp [invalid, consumptionVerdict, consumptionError, success] at meaning
  refine ⟨by simpa [originalHeaders] using valid.2.1, ?_⟩
  intro row present
  have rowValid := valid.2.2.2 row present
  have bounds := valid_version_bounds _ _ rowValid
  exact ⟨bounds.1, bounds.2, version_name_excludes_account_scope _ _ rowValid,
    version_bytes_are_safe _ _ rowValid⟩

end Auths.Product.NativeCompiler.Refinement
