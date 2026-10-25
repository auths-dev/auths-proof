import Auths.Product.NativeCompilerFormGrammar

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def nativeMemberMaximum : NativeMemberDomain → Std.Usize
  | .Json => 32#usize
  | .Form => 16#usize

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open TemplateMembers
set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

private theorem native_echo_name_valid_exact (domain : NativeMemberDomain) (name : Slice Std.U8) :
    (match domain with
    | .Json => AuthsNativeRecipe.auths_gateway_kernel.identity.valid_token name 64#usize
    | .Form => AuthsNativeRecipe.auths_gateway_kernel.template_members.form_echo_name_valid name)
      ⦃ actual => actual = decide (EchoName (nativeMemberDomain domain) (schemaSliceBytes name)) ⦄ := by
  cases domain with
  | Json =>
      apply spec_mono (native_schema_token_exact name 64#usize)
      intro actual exact
      simpa [EchoName, nativeMemberDomain] using exact
  | Form =>
      apply spec_mono (native_form_echo_name_exact name)
      intro actual exact
      simpa [EchoName, nativeMemberDomain] using exact

/-- Full original public selector outcome, including the order of malformed
ordinary-key refusal before malformed/colliding/over-capacity echo refusal. -/
@[step] theorem native_canonical_members_exact (keys : Slice NativeKey)
    (echo : Option (Slice Std.U8)) (domain : NativeMemberDomain) :
    AuthsNativeRecipe.auths_gateway_kernel.template_members.canonical_members keys echo domain ⦃ actual =>
      nativeMemberResult nativeChoices actual = canonicalMembers (nativeKeyColumn keys)
        (echo.map schemaSliceBytes) (nativeMemberDomain domain) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_members.canonical_members
  step with native_keys_ordered_exact keys domain as ⟨ordered, orderedMeaning⟩
  cases ordered with
  | false =>
      have invalid : ¬KeyColumn (nativeKeyColumn keys) (nativeMemberDomain domain) := by
        simpa using orderedMeaning.symm
      simp [nativeMemberResult, nativeMemberErrorMeaning, canonicalMembers, invalid]
  | true =>
      have column : KeyColumn (nativeKeyColumn keys) (nativeMemberDomain domain) := by
        simpa using orderedMeaning.symm
      have count : keys.val.length ≤ 32 := by
        have bounded := column.2.1
        cases domain <;> simp_all [nativeKeyColumn, nativeMemberDomain, maximum]
      simp only [Bool.true_eq_true, ↓reduceIte]
      have maximumResult : (match domain with
          | .Json => (ok 32#usize : Result Std.Usize)
          | .Form => ok 16#usize) = ok (nativeMemberMaximum domain) := by cases domain <;> rfl
      rw [maximumResult]
      simp only [bind_tc_ok]
      cases echo with
      | none =>
          step with native_merge_members_exact keys none count as ⟨merged, mergedMeaning⟩
          simpa [canonicalMembers, column] using mergedMeaning
      | some name =>
          step with native_echo_name_valid_exact domain name as ⟨valid, validMeaning⟩
          cases valid with
          | false =>
              have invalid : ¬EchoName (nativeMemberDomain domain) (schemaSliceBytes name) := by
                simpa using validMeaning.symm
              simp [canonicalMembers, column, invalid, nativeMemberResult, nativeMemberErrorMeaning]
          | true =>
              have echoValid : EchoName (nativeMemberDomain domain) (schemaSliceBytes name) := by
                simpa using validMeaning.symm
              simp only [Bool.true_eq_true, ↓reduceIte]
              by_cases capacity : keys.val.length < maximum (nativeMemberDomain domain)
              · have nativeCapacity : ¬keys.len >= nativeMemberMaximum domain := by
                  cases domain <;> simp_all [nativeMemberDomain, nativeMemberMaximum, maximum] <;> scalar_tac
                simp only [nativeCapacity, ↓reduceIte]
                step with native_merge_members_exact keys (some name) count as ⟨merged, mergedMeaning⟩
                simpa [canonicalMembers, column, echoValid, nativeKeyColumn, capacity] using mergedMeaning
              · have nativeCapacity : keys.len >= nativeMemberMaximum domain := by
                  cases domain <;> simp_all [nativeMemberDomain, nativeMemberMaximum, maximum] <;> scalar_tac
                have modelCapacity : ¬(nativeKeyColumn keys).length < maximum (nativeMemberDomain domain) := by
                  simpa [nativeKeyColumn] using capacity
                simp [nativeCapacity, canonicalMembers, column, echoValid, modelCapacity,
                  nativeMemberResult, nativeMemberErrorMeaning]

/-- Success of the real selector earns canonical labels and every original
member, plus exactly the declared new echo. No selected-name oracle is an
input to the source theorem. -/
theorem native_canonical_members_have_original_meaning (keys : Slice NativeKey)
    (echo : Option (Slice Std.U8)) (domain : NativeMemberDomain) :
    AuthsNativeRecipe.auths_gateway_kernel.template_members.canonical_members keys echo domain ⦃ actual =>
      ∀ output, actual = .Ok output → ∃ labels,
        selectedNames (nativeKeyColumn keys) (echo.map schemaSliceBytes) (nativeChoices output) = some labels ∧
        labels.Pairwise (· < ·) ∧ labels.Perm (nativeKeyColumn keys ++ (echo.map schemaSliceBytes).toList) ⦄ := by
  apply spec_mono (native_canonical_members_exact keys echo domain)
  intro actual exact output accepted
  rw [accepted] at exact
  exact canonical_selected_names _ _ _ _ (by simpa only [nativeMemberResult] using exact.symm)

end Auths.Product.NativeCompiler.Refinement
