import Auths.Product.NativeCompilerPaths

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open HeaderCompiler
set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

@[step] theorem native_header_index_exact (name : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.header_index name ⦃ actual =>
      actual.map UScalar.val = headerIndex (schemaSliceBytes name) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.header_compiler.header_index
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.STRIPE_VERSION_BYTES
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.GITHUB_VERSION_BYTES
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.STRIPE_ACCOUNT_BYTES
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.STRIPE_VERSION
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.GITHUB_VERSION
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.STRIPE_ACCOUNT
    AuthsNativeRecipe.core.str.Str.as_bytes _root_.core.str.Str.as_bytes
  simp only [bind_tc_ok]
  step with native_schema_byte_equality name (toStr "Stripe-Version") as ⟨stripe, stripeMeaning⟩
  change stripe = decide (schemaSliceBytes name = stripeVersionName) at stripeMeaning
  cases stripe with
  | true => simp [headerIndex, ← stripeMeaning]
  | false =>
      simp only [Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
      step with native_schema_byte_equality name (toStr "X-GitHub-Api-Version") as ⟨github, githubMeaning⟩
      change github = decide (schemaSliceBytes name = githubVersionName) at githubMeaning
      cases github with
      | true => simp [headerIndex, ← stripeMeaning, ← githubMeaning]
      | false =>
          simp only [Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
          step with native_schema_byte_equality name (toStr "Stripe-Account") as ⟨account, accountMeaning⟩
          change account = decide (schemaSliceBytes name = stripeAccountName) at accountMeaning
          cases account <;> simp [headerIndex, ← stripeMeaning, ← githubMeaning, ← accountMeaning]

@[step] theorem native_version_byte_exact (byte : Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.version_byte_valid byte ⦃ actual =>
      actual = decide (VersionByte byte.val) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.header_compiler.version_byte_valid
  step with native_schema_alphanumeric_exact byte as ⟨alpha, alphaMeaning⟩
  repeat' split
  all_goals simp_all [VersionByte, RequestConstruction.alphanumeric,
    OperationIdentity.Alphanumeric, UScalar.eq_equiv, Bool.eq_iff_iff]

@[step] theorem native_date_byte_exact (position : Std.Usize) (byte : Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.date_byte_valid position byte ⦃ actual =>
      actual = decide (DateByte position.val byte.val) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.header_compiler.date_byte_valid
  repeat' split
  all_goals simp_all [DateByte, Digit, UScalar.eq_equiv, UScalar.le_equiv]

private theorem native_version_suffix (value : Slice Std.U8) (position : Std.Usize)
    (positionBound : position.val ≤ value.val.length) :
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.stripe_version_valid_loop value position
      ⦃ actual => actual = decide (∀ byte ∈ value.val.drop position.val, VersionByte byte.val) ⦄ := by
  generalize remaining : value.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.header_compiler.stripe_version_valid_loop
      by_cases inside : position.val < value.val.length
      · have nativeInside : position < value.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        step with Slice.index_usize_spec value position inside as ⟨byte, byteAt⟩
        have suffix : value.val.drop position.val = byte :: value.val.drop (position.val + 1) := by
          simpa only [byteAt] using List.drop_eq_getElem_cons inside
        step with native_version_byte_exact byte as ⟨valid, validMeaning⟩
        cases valid with
        | false => simp [suffix, ← validMeaning]
        | true =>
            simp only [Bool.true_eq_true, ↓reduceIte]
            step as ⟨next, nextValue⟩
            apply spec_mono (ih _ (by omega) next (by omega) rfl)
            intro actual exact
            simpa only [suffix, List.mem_cons, forall_eq_or_imp, ← validMeaning,
              decide_true, true_and, nextValue] using exact
      · have ended : value.val.length ≤ position.val := by omega
        have nativeEnded : ¬position < value.len := by scalar_tac
        simp [nativeEnded, List.drop_eq_nil_of_le ended]

@[step] theorem native_stripe_version_exact (value : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.stripe_version_valid value ⦃ actual =>
      actual = decide (StripeVersionValid (schemaSliceBytes value)) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.header_compiler.stripe_version_valid
  by_cases short : value.val.length < 10
  · have nativeShort : value.len < 10#usize := by scalar_tac
    simp [nativeShort, StripeVersionValid, schemaSliceBytes, Nat.not_le.mpr short]
  · have minimum : 10 ≤ value.val.length := by omega
    have nativeMinimum : ¬value.len < 10#usize := by scalar_tac
    simp only [nativeMinimum, ↓reduceIte]
    by_cases large : 64 < value.val.length
    · have nativeLarge : value.len > 64#usize := by scalar_tac
      simp [nativeLarge, StripeVersionValid, schemaSliceBytes, Nat.not_le.mpr large]
    · have maximum : value.val.length ≤ 64 := by omega
      have nativeMaximum : ¬value.len > 64#usize := by scalar_tac
      simp only [nativeMaximum, ↓reduceIte]
      step with Slice.index_usize_spec value 0#usize (by omega) as ⟨first, firstAt⟩
      have originalHead : (schemaSliceBytes value).headD 0 = first.val := by
        cases original : value.val with
        | nil => simp only [original, List.length_nil] at minimum; omega
        | cons head tail =>
            have same : first = head := by simpa only [original] using firstAt
            simp [schemaSliceBytes, original, same]
      by_cases below : first.val < 48
      · have nativeBelow : first < 48#u8 := by scalar_tac
        simp [nativeBelow, StripeVersionValid, schemaSliceBytes, minimum, maximum,
          originalHead, Digit, Nat.not_le.mpr below]
      · have nativeBelow : ¬first < 48#u8 := by scalar_tac
        simp only [nativeBelow, ↓reduceIte]
        by_cases above : 57 < first.val
        · have nativeAbove : first > 57#u8 := by scalar_tac
          simp [nativeAbove, StripeVersionValid, schemaSliceBytes, originalHead,
            Digit, Nat.not_le.mpr above]
        · have nativeAbove : ¬first > 57#u8 := by scalar_tac
          simp only [nativeAbove, ↓reduceIte]
          have digit : Digit first.val := by constructor <;> omega
          apply spec_mono (native_version_suffix value 0#usize (by simp))
          intro actual exact
          simpa only [StripeVersionValid, schemaSliceBytes, List.length_map, minimum, maximum,
            originalHead, digit, true_and, List.forall_mem_map, List.drop_zero] using exact

private def dateSuffix (value : Slice Std.U8) (position : Nat) : Prop :=
  ∀ index, position ≤ index → index < value.val.length →
    DateByte index ((schemaSliceBytes value)[index]?.getD 0)

private instance (value : Slice Std.U8) (position : Nat) : Decidable (dateSuffix value position) :=
  decidable_of_iff (∀ index ∈ List.range value.val.length,
    position ≤ index → DateByte index ((schemaSliceBytes value)[index]?.getD 0))
    (by simp [dateSuffix, List.mem_range]; tauto)

private theorem native_date_suffix (value : Slice Std.U8) (position : Std.Usize)
    (positionBound : position.val ≤ value.val.length) :
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.iso_date_valid_loop value position
      ⦃ actual => actual = decide (dateSuffix value position.val) ⦄ := by
  generalize remaining : value.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.header_compiler.iso_date_valid_loop
      by_cases inside : position.val < value.val.length
      · have nativeInside : position < value.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        step with Slice.index_usize_spec value position inside as ⟨byte, byteAt⟩
        have originalByte : ((schemaSliceBytes value)[position.val]?.getD 0) = byte.val := by
          simp only [schemaSliceBytes, List.getElem?_map, List.getElem?_eq_getElem inside,
            Option.map_some, Option.getD_some, byteAt]
        have suffix : dateSuffix value position.val ↔
            DateByte position.val byte.val ∧ dateSuffix value (position.val + 1) := by
          constructor
          · intro all
            exact ⟨by simpa only [originalByte] using all position.val (by omega) inside,
              fun index after before => all index (by omega) before⟩
          · rintro ⟨head, tail⟩ index after before
            by_cases same : index = position.val
            · simpa only [same, originalByte] using head
            · exact tail index (by omega) before
        step with native_date_byte_exact position byte as ⟨valid, validMeaning⟩
        cases valid with
        | false => simp [suffix, ← validMeaning]
        | true =>
            simp only [Bool.true_eq_true, ↓reduceIte]
            step as ⟨next, nextValue⟩
            apply spec_mono (ih _ (by omega) next (by omega) rfl)
            intro actual exact
            simpa only [suffix, ← validMeaning, decide_true, true_and, nextValue] using exact
      · have ended : value.val.length ≤ position.val := by omega
        have nativeEnded : ¬position < value.len := by scalar_tac
        have noSuffix : dateSuffix value position.val := by
          intro index after before
          omega
        simp [nativeEnded, noSuffix]

@[step] theorem native_iso_date_exact (value : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.iso_date_valid value ⦃ actual =>
      actual = decide (IsoDateValid (schemaSliceBytes value)) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.header_compiler.iso_date_valid
  by_cases length : value.val.length = 10
  · have nativeLength : value.len = 10#usize := by scalar_tac
    simp only [nativeLength, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
    apply spec_mono (native_date_suffix value 0#usize (by simp))
    intro actual exact
    simpa [IsoDateValid, dateSuffix, schemaSliceBytes, length, List.mem_range] using exact
  · have nativeLength : value.len ≠ 10#usize := by scalar_tac
    simp [nativeLength, IsoDateValid, schemaSliceBytes, length]

@[step] theorem native_version_header_exact (name value : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.version_header_valid name value ⦃ actual =>
      actual = decide (VersionValid (schemaSliceBytes name) (schemaSliceBytes value)) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.header_compiler.version_header_valid
  step with native_header_index_exact name as ⟨index, indexMeaning⟩
  cases index with
  | none =>
      have invalid : ¬VersionValid (schemaSliceBytes name) (schemaSliceBytes value) := by
        rw [version_valid_by_index, ← indexMeaning]
        simp
      simp [invalid]
  | some position =>
      by_cases zero : position.val = 0
      · simp only [zero]
        step with native_stripe_version_exact value as ⟨actual, meaning⟩
        simpa [version_valid_by_index, ← indexMeaning, zero] using meaning
      · by_cases one : position.val = 1
        · simp only [zero, one]
          step with native_iso_date_exact value as ⟨actual, meaning⟩
          simpa [version_valid_by_index, ← indexMeaning, one] using meaning
        · have invalid : ¬VersionValid (schemaSliceBytes name) (schemaSliceBytes value) := by
            rw [version_valid_by_index, ← indexMeaning]
            simp only [Option.map_some]
            split <;> simp_all
          simp [zero, one, invalid]

end Auths.Product.NativeCompiler.Refinement
