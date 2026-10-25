import Auths.Product.NativeCompilerHeaderGrammar
import Auths.Product.RecipeCredentialAdmission

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open HeaderCompiler

set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

@[step] theorem native_ascii_lower_exact (byte : Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.ascii_lower byte ⦃ actual =>
      actual.val = asciiLower byte.val ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.header_compiler.ascii_lower
  by_cases lower : 65 ≤ byte.val
  · have nativeLower : byte ≥ 65#u8 := by scalar_tac
    simp only [nativeLower, ↓reduceIte]
    by_cases upper : byte.val ≤ 90
    · have nativeUpper : byte ≤ 90#u8 := by scalar_tac
      simp only [nativeUpper, ↓reduceIte]
      step as ⟨offset, offsetMeaning⟩
      step as ⟨actual, actualMeaning⟩
      simp [asciiLower, lower, upper]
      omega
    · have nativeUpper : ¬byte ≤ 90#u8 := by scalar_tac
      simp [nativeUpper, asciiLower, lower, upper]
  · have nativeLower : ¬byte ≥ 65#u8 := by scalar_tac
    simp [nativeLower, asciiLower, lower]

private theorem native_ascii_name_suffix (left right : Slice Std.U8) (position : Std.Usize)
    (equal : Bool) (sizes : left.val.length = right.val.length)
    (bound : position.val ≤ left.val.length) :
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.ascii_name_equal_loop left right position equal ⦃ actual =>
      actual = (equal && decide
        ((left.val.drop position.val).map (fun byte => asciiLower byte.val) =
         (right.val.drop position.val).map (fun byte => asciiLower byte.val))) ⦄ := by
  generalize remaining : left.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position equal with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.header_compiler.ascii_name_equal_loop
      split <;> rename_i within
      · have inside : position.val < left.val.length := by simpa using within
        cases equal with
        | false => simp
        | true =>
            simp only [Bool.true_eq_true, ↓reduceIte]
            step with Slice.index_usize_spec left position inside as ⟨first, firstAt⟩
            step with native_ascii_lower_exact first as ⟨firstLower, firstMeaning⟩
            step with Slice.index_usize_spec right position (by omega) as ⟨second, secondAt⟩
            step with native_ascii_lower_exact second as ⟨secondLower, secondMeaning⟩
            step as ⟨next, nextMeaning⟩
            have nextBound : next.val ≤ left.val.length := by omega
            have smaller : left.val.length - next.val < count := by omega
            apply spec_mono (ih _ smaller next (decide (firstLower = secondLower)) nextBound rfl)
            intro actual meaning
            have leftSuffix : left.val.drop position.val = first :: left.val.drop next.val := by
              simpa only [firstAt, nextMeaning] using List.drop_eq_getElem_cons inside
            have rightSuffix : right.val.drop position.val = second :: right.val.drop next.val := by
              simpa only [secondAt, nextMeaning] using List.drop_eq_getElem_cons (show position.val < right.val.length by omega)
            simpa [leftSuffix, rightSuffix, List.cons.injEq, UScalar.eq_equiv,
              firstMeaning, secondMeaning, decide_and] using meaning
      · have leftEnded : left.val.length ≤ position.val := by simpa using within
        have rightEnded : right.val.length ≤ position.val := by omega
        simp [List.drop_eq_nil_of_le leftEnded, List.drop_eq_nil_of_le rightEnded]

/-- Complete original byte alignment with ASCII folding only. Length mismatch,
shared prefixes and non-ASCII bytes retain their actual source behavior. -/
@[step] theorem native_ascii_name_equal_exact (left right : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.ascii_name_equal left right ⦃ actual =>
      actual = decide (AsciiNameEqual (schemaSliceBytes left) (schemaSliceBytes right)) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.header_compiler.ascii_name_equal
  by_cases sizes : left.val.length = right.val.length
  · have nativeSizes : left.len = right.len := by scalar_tac
    simp only [nativeSizes, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
    apply spec_mono (native_ascii_name_suffix left right 0#usize true sizes (by simp))
    intro actual meaning
    simpa [AsciiNameEqual, schemaSliceBytes, List.map_map] using meaning
  · have nativeSizes : left.len ≠ right.len := by scalar_tac
    have different : ¬AsciiNameEqual (schemaSliceBytes left) (schemaSliceBytes right) := by
      intro same
      have lengths := ascii_name_equality_keeps_length _ _ same
      simp only [schemaSliceBytes, List.length_map] at lengths
      exact sizes lengths
    simp [nativeSizes, different]

@[step] theorem native_registered_credential_header_exact (name : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.registered_header_name name ⦃ actual =>
      actual = decide (RegisteredCredentialHeader (schemaSliceBytes name)) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.header_compiler.registered_header_name
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.STRIPE_VERSION_BYTES
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.GITHUB_VERSION_BYTES
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.STRIPE_ACCOUNT_BYTES
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.STRIPE_VERSION
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.GITHUB_VERSION
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.STRIPE_ACCOUNT
    AuthsNativeRecipe.core.str.Str.as_bytes _root_.core.str.Str.as_bytes
  simp only [bind_tc_ok]
  step with native_ascii_name_equal_exact name (toStr "Stripe-Version") as ⟨stripe, stripeMeaning⟩
  change stripe = decide (AsciiNameEqual (schemaSliceBytes name) stripeVersionName) at stripeMeaning
  cases stripe with
  | true => simp [RegisteredCredentialHeader, ← stripeMeaning]
  | false =>
      simp only [Bool.false_eq_true, ↓reduceIte]
      step with native_ascii_name_equal_exact name (toStr "X-GitHub-Api-Version") as ⟨github, githubMeaning⟩
      change github = decide (AsciiNameEqual (schemaSliceBytes name) githubVersionName) at githubMeaning
      cases github with
      | true => simp [RegisteredCredentialHeader, ← stripeMeaning, ← githubMeaning]
      | false =>
          simp only [Bool.false_eq_true, ↓reduceIte]
          apply spec_mono (native_ascii_name_equal_exact name (toStr "Stripe-Account"))
          intro actual meaning
          simpa [RegisteredCredentialHeader, ← stripeMeaning, ← githubMeaning,
            stripeAccountName, schemaSliceBytes] using meaning

@[step] theorem native_reserved_credential_header_exact (name : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.reserved_credential_header_name name ⦃ actual =>
      actual = decide (∃ reserved ∈ RecipeCredentialAdmission.transportHeaderNames,
        AsciiNameEqual (schemaSliceBytes name) reserved) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.header_compiler.reserved_credential_header_name
  repeat' first
    | progress simp only [lift, bind_tc_ok]
    | step with native_ascii_name_equal_exact
    | split
  all_goals simp_all [RecipeCredentialAdmission.transportHeaderNames, schemaSliceBytes]

end Auths.Product.NativeCompiler.Refinement
