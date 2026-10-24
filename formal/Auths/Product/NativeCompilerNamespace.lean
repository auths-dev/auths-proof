import Auths.Product.NativeCompilerText
import Auths.Product.NativeCompilerSchemaAtoms
import Auths.Product.NativeCompilerConstructorTrace

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def nativeNamespaceOutcome : core.result.Result AuthsNativeRecipe.recipe.OperatorNamespace NativeRecipeError →
    Except NativeRecipeError (List Nat)
  | .Err error => .error error
  | .Ok namespaceValue => .ok (textBytes namespaceValue)

def namespaceVerdict (original : List Nat) : Except NativeRecipeError (List Nat) :=
  if OperationIdentity.validToken original 64 then .ok original else .error .InvalidNamespace

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel

set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

@[step] theorem native_recipe_token_exact (input : Str) (maximum : Std.Usize) :
    AuthsNativeRecipe.recipe.valid_token input maximum ⦃ actual =>
      actual = OperationIdentity.validToken (schemaSliceBytes input) maximum.val ⦄ := by
  unfold AuthsNativeRecipe.recipe.valid_token
  simp only [AuthsNativeRecipe.core.str.Str.as_bytes, _root_.core.str.Str.as_bytes, bind_tc_ok]
  exact native_schema_token_exact input maximum

/-- All represented native str inputs have the exact namespace success/refusal
outcome. Acceptance earns lexical validity and full original bytes before the
owned copy; invalid UTF-8 cannot reach that copy through an admitted token. -/
@[step] theorem native_namespace_parse_exact (input : Str) :
    AuthsNativeRecipe.recipe.OperatorNamespace.parse input ⦃ actual =>
      nativeNamespaceOutcome actual = namespaceVerdict (schemaSliceBytes input) ⦄ := by
  unfold AuthsNativeRecipe.recipe.OperatorNamespace.parse
  step with native_recipe_token_exact input 64#usize as ⟨valid, validMeaning⟩
  by_cases token : OperationIdentity.validToken (schemaSliceBytes input) 64 = true
  · have accepted : valid = true := by simpa using validMeaning.trans token
    simp only [accepted, Bool.true_eq_true, ↓reduceIte]
    step with native_token_owned_exact input 64 token as ⟨owned, original⟩
    simp [nativeNamespaceOutcome, namespaceVerdict, token, original]
  · have refused : valid = false := by
      cases valid <;> simp_all
    simp [refused, nativeNamespaceOutcome, namespaceVerdict, token]

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

@[step] theorem native_constructor_namespace_exact (source : NativeConstructorSource)
    (fits : TextFits source.operator_namespace) :
    constructorNamespace source ⦃ actual =>
      nativeNamespaceOutcome actual = namespaceVerdict (textBytes source.operator_namespace) ⦄ := by
  unfold constructorNamespace
  step with native_deref_text_exact source.operator_namespace fits as ⟨original, same, originalBytes⟩
  apply spec_mono (native_namespace_parse_exact original)
  intro actual meaning
  simpa [originalBytes] using meaning

/-- Namespace bytes are earned from the actual constructor result and remain
exactly those of the original source. No getter or private record suffices. -/
theorem native_constructor_success_earns_namespace (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (fits : TextFits source.operator_namespace) (checked : NativeConstructorRecord)
    (completed : AuthsNativeRecipe.recipe.validate.validate_source source lock canonical = ok (.Ok checked)) :
    textBytes checked.«namespace» = textBytes source.operator_namespace ∧
      OperationIdentity.validToken (textBytes source.operator_namespace) 64 = true := by
  have trace := native_constructor_success_earns_original_trace source lock canonical checked completed
  have meaning := native_constructor_namespace_exact source fits
  rw [trace.namespaceChecked] at meaning
  have outcome : Except.ok (textBytes checked.«namespace») = namespaceVerdict (textBytes source.operator_namespace) := by
    simpa [spec_ok, nativeNamespaceOutcome] using meaning
  by_cases valid : OperationIdentity.validToken (textBytes source.operator_namespace) 64 = true
  · exact ⟨by simpa [namespaceVerdict, valid] using outcome, valid⟩
  · simp [namespaceVerdict, valid] at outcome

/-- Actual complete compilation cannot normalize or substitute its operator
namespace. The accepted token additionally excludes embedded NUL framing. -/
theorem native_compile_success_earns_namespace (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (fits : TextFits source.operator_namespace) (output : AuthsNativeRecipe.recipe.CompiledRecipe)
    (completed : AuthsNativeRecipe.recipe.compile_decoded source lock canonical = ok (.Ok output)) :
    textBytes output.«namespace» = textBytes source.operator_namespace ∧
      OperationIdentity.validToken (textBytes output.«namespace») 64 = true ∧
      OperationIdentity.NulFree (textBytes output.«namespace») := by
  obtain ⟨checked, admitted, digest, plans, original, namespaceValue⟩ :=
    native_compile_success_keeps_all_stage_results source lock canonical output completed
  obtain ⟨same, valid⟩ := native_constructor_success_earns_namespace source lock canonical fits checked admitted
  have originalBytes : textBytes output.«namespace» = textBytes source.operator_namespace := by
    simpa [namespaceValue] using same
  have token : OperationIdentity.validToken (textBytes output.«namespace») 64 = true := by
    simpa [originalBytes] using valid
  exact ⟨originalBytes, token, OperationIdentity.token_nul_free _ _ token⟩

end Auths.Product.NativeCompiler.Refinement
