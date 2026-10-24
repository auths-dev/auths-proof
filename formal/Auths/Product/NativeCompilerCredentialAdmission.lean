import Auths.Product.NativeCompilerCredentialNames
import Auths.Product.NativeCompilerNamespace

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

abbrev NativeCredentialRequirement := AuthsNativeRecipe.recipe.CredentialRequirement

def nativeCredentialRequirement : NativeCredentialRequirement → RecipeCredentialAdmission.Requirement
  | .Bearer => .bearer
  | .HeaderApiKey name => .headerApiKey (textBytes name)

def nativeSourceCredentialRequirement : AuthsNativeRecipe.recipe.source.CredentialSource →
    RecipeCredentialAdmission.Requirement
  | .Bearer _ => .bearer
  | .HeaderApiKey name _ => .headerApiKey (textBytes name)

def NativeCredentialFits : NativeCredentialRequirement → Prop
  | .Bearer => True
  | .HeaderApiKey name => TextFits name

def NativeSourceCredentialFits : AuthsNativeRecipe.recipe.source.CredentialSource → Prop
  | .Bearer _ => True
  | .HeaderApiKey name _ => TextFits name

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open RecipeCredentialAdmission

set_option maxHeartbeats 12000000
set_option maxRecDepth 4096

private theorem native_credential_token_tail (input : Slice Std.U8) (position : Std.Usize) (valid : Bool)
    (positive : 0 < position.val) (bound : position.val ≤ input.val.length) :
    AuthsNativeRecipe.recipe.credential_header_token_loop input position valid ⦃ actual =>
      actual = (valid && decide (∀ byte ∈ input.val.drop position.val,
        OperationIdentity.Alphanumeric byte.val ∨ byte.val = 45)) ⦄ := by
  generalize remaining : input.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position valid with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.credential_header_token_loop
      split <;> rename_i within
      · have inside : position.val < input.val.length := by simpa using within
        cases valid with
        | false => simp
        | true =>
            simp only [Bool.true_eq_true, ↓reduceIte]
            step with Slice.index_usize_spec input position inside as ⟨byte, byteAt⟩
            step with native_schema_alphanumeric_exact byte as ⟨alpha, alphaMeaning⟩
            have nativePositive : position > 0#usize := by scalar_tac
            have suffix : input.val.drop position.val = byte :: input.val.drop (position.val + 1) := by
              simpa only [byteAt] using List.drop_eq_getElem_cons inside
            have recurse (next : Std.Usize) (nextValue : next.val = position.val + 1) (flag : Bool) :
                AuthsNativeRecipe.recipe.credential_header_token_loop input next flag ⦃ actual =>
                  actual = (flag && decide (∀ byte ∈ input.val.drop next.val,
                    OperationIdentity.Alphanumeric byte.val ∨ byte.val = 45)) ⦄ := by
              exact ih _ (by omega) next flag (by omega) (by omega) rfl
            repeat' first | step with recurse | step | split
            all_goals simp_all [suffix, nativePositive, UScalar.eq_equiv, Bool.and_assoc,
              decide_and, decide_or]
      · have ended : input.val.length ≤ position.val := by simpa using within
        simp [List.drop_eq_nil_of_le ended]

@[step] theorem native_credential_header_body_exact (input : Str) :
    AuthsNativeRecipe.recipe.credential_header_token input ⦃ actual =>
      actual = decide (HeaderTokenBody (schemaSliceBytes input)) ⦄ := by
  unfold AuthsNativeRecipe.recipe.credential_header_token
  simp only [AuthsNativeRecipe.core.str.Str.as_bytes, _root_.core.str.Str.as_bytes, bind_tc_ok]
  cases original : input.val with
  | nil =>
      simp [AuthsNativeRecipe.recipe.credential_header_token_loop, original,
        schemaSliceBytes, HeaderTokenBody]
  | cons first rest =>
      unfold AuthsNativeRecipe.recipe.credential_header_token_loop
      have inside : 0#usize < input.len := by simp [original]; scalar_tac
      simp only [inside, Bool.true_eq_true, ↓reduceIte]
      step with Slice.index_usize_spec input 0#usize (by simp [original]) as ⟨byte, byteAt⟩
      have originalByte : byte = first := by simpa [original] using byteAt
      step with native_schema_alphanumeric_exact byte as ⟨alpha, alphaMeaning⟩
      have recurse (next : Std.Usize) (nextValue : next.val = 1) (flag : Bool) :
          AuthsNativeRecipe.recipe.credential_header_token_loop input next flag ⦃ actual =>
            actual = (flag && decide (∀ byte ∈ rest,
              OperationIdentity.Alphanumeric byte.val ∨ byte.val = 45)) ⦄ := by
        apply spec_mono (native_credential_token_tail input next flag (by omega)
          (by simp [original]; omega))
        intro actual meaning
        simpa [nextValue, original] using meaning
      repeat' first | step with recurse | step | split
      all_goals simp_all [schemaSliceBytes, original, originalByte, HeaderTokenBody,
        Bool.eq_iff_iff, List.forall_mem_map]

@[step] theorem native_registered_provider_header_exact (input : Str) :
    AuthsNativeRecipe.recipe.registered_provider_header input ⦃ actual =>
      actual = decide (HeaderCompiler.RegisteredCredentialHeader (schemaSliceBytes input)) ⦄ := by
  unfold AuthsNativeRecipe.recipe.registered_provider_header
  simp only [AuthsNativeRecipe.core.str.Str.as_bytes, _root_.core.str.Str.as_bytes, bind_tc_ok]
  exact native_registered_credential_header_exact input

/-- Complete actual credential-header admission, including original byte count,
first-byte grammar, every later byte, and both complete ASCII-folded catalogs.
The source guard is a separate subsequent rule, not assumed here. -/
@[step] theorem native_credential_requirement_exact (requirement : NativeCredentialRequirement)
    (fits : NativeCredentialFits requirement) :
    AuthsNativeRecipe.recipe.CredentialRequirement.validate requirement ⦃ actual =>
      nativeLockOutcome actual = validateRequirement NativeRecipeError.InvalidCredential
        (nativeCredentialRequirement requirement) ⦄ := by
  cases requirement with
  | Bearer =>
      simp [AuthsNativeRecipe.recipe.CredentialRequirement.validate, nativeLockOutcome,
        validateRequirement, RequirementAdmitted, nativeCredentialRequirement]
  | HeaderApiKey name =>
      have fits : TextFits name := fits
      unfold AuthsNativeRecipe.recipe.CredentialRequirement.validate
      step with native_text_empty_exact name as ⟨empty, emptyMeaning⟩
      by_cases absent : textBytes name = []
      · have refused : empty = true := by simpa [absent] using emptyMeaning
        simp [refused, nativeLockOutcome, validateRequirement, RequirementAdmitted,
          nativeCredentialRequirement, CredentialHeaderAdmitted, credential_header_token_iff, absent]
      · have present : empty = false := by simpa [absent] using emptyMeaning
        simp only [present, Bool.false_eq_true, ↓reduceIte]
        step with native_text_size_exact name fits as ⟨size, sizeMeaning⟩
        by_cases large : 64 < (textBytes name).length
        · have refused : size > 64#usize := by scalar_tac
          simp [refused, nativeLockOutcome, validateRequirement, RequirementAdmitted,
            nativeCredentialRequirement, CredentialHeaderAdmitted, credential_header_token_iff,
            Nat.not_le.mpr large]
        · have bounded : (textBytes name).length ≤ 64 := by omega
          have accepted : ¬size > 64#usize := by scalar_tac
          simp only [accepted, ↓reduceIte]
          step with native_deref_text_exact name fits as ⟨borrowed, original, originalBytes⟩
          step with native_credential_header_body_exact borrowed as ⟨bodyValid, bodyMeaning⟩
          by_cases body : HeaderTokenBody (textBytes name)
          · have bodyTrue : bodyValid = true := by simpa [originalBytes, body] using bodyMeaning
            simp only [bodyTrue, Bool.true_eq_true, ↓reduceIte]
            step with borrow_text_exact name fits as ⟨raw, rawMeaning⟩
            step with native_reserved_credential_header_exact raw as ⟨reserved, reservedMeaning⟩
            by_cases collision : ∃ item ∈ transportHeaderNames, HeaderCompiler.AsciiNameEqual (textBytes name) item
            · have reservedTrue : reserved = true := by simpa [schemaSliceBytes, rawMeaning, collision] using reservedMeaning
              have forbidden : ¬CredentialHeaderAdmitted (textBytes name) := by
                intro admitted
                obtain ⟨item, member, equal⟩ := collision
                exact admitted.2.1 item member equal
              simp [reservedTrue, nativeLockOutcome, validateRequirement, RequirementAdmitted,
                nativeCredentialRequirement, forbidden]
            · have reservedFalse : reserved = false := by simpa [schemaSliceBytes, rawMeaning, collision] using reservedMeaning
              simp only [reservedFalse, Bool.false_eq_true, ↓reduceIte]
              step with native_registered_provider_header_exact borrowed as ⟨registered, registeredMeaning⟩
              by_cases provider : HeaderCompiler.RegisteredCredentialHeader (textBytes name)
              · have registeredTrue : registered = true := by simpa [originalBytes, provider] using registeredMeaning
                simp [registeredTrue, nativeLockOutcome, validateRequirement, RequirementAdmitted,
                  nativeCredentialRequirement, CredentialHeaderAdmitted, provider]
              · have registeredFalse : registered = false := by simpa [originalBytes, provider] using registeredMeaning
                simp [registeredFalse, nativeLockOutcome, validateRequirement, RequirementAdmitted,
                  nativeCredentialRequirement, CredentialHeaderAdmitted, credential_header_token_iff,
                  absent, bounded, body, collision, provider, not_exists]
          · have bodyFalse : bodyValid = false := by simpa [originalBytes, body] using bodyMeaning
            simp [bodyFalse, nativeLockOutcome, validateRequirement, RequirementAdmitted,
              nativeCredentialRequirement, CredentialHeaderAdmitted, credential_header_token_iff, body]

@[step] theorem native_source_credential_requirement_exact (source : AuthsNativeRecipe.recipe.source.CredentialSource) :
    AuthsNativeRecipe.recipe.credential_requirement source ⦃ actual =>
      nativeCredentialRequirement actual = nativeSourceCredentialRequirement source ∧
      (NativeSourceCredentialFits source → NativeCredentialFits actual) ⦄ := by
  cases source <;> simp [AuthsNativeRecipe.recipe.credential_requirement,
    AuthsNativeRecipe.alloc.string.String.Insts.CoreCloneClone.clone,
    nativeCredentialRequirement, nativeSourceCredentialRequirement,
    NativeSourceCredentialFits, NativeCredentialFits]

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

@[step] theorem native_constructor_credential_exact (source : NativeConstructorSource)
    (fits : NativeSourceCredentialFits source.credential) :
    constructorCredential source ⦃ actual =>
      nativeLockOutcome actual = validateRequirement NativeRecipeError.InvalidCredential
        (nativeSourceCredentialRequirement source.credential) ⦄ := by
  unfold constructorCredential
  step with native_source_credential_requirement_exact source.credential as ⟨requirement, original, bound⟩
  apply spec_mono (native_credential_requirement_exact requirement (bound fits))
  intro actual meaning
  simpa [original] using meaning

/-- The actual native constructor earns its original header admission, rather
than relying on a getter or accepting a standard-library callback decision. -/
theorem native_constructor_success_earns_credential (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (fits : NativeSourceCredentialFits source.credential) (checked : NativeConstructorRecord)
    (completed : AuthsNativeRecipe.recipe.validate.validate_source source lock canonical = ok (.Ok checked)) :
    RequirementAdmitted (nativeSourceCredentialRequirement source.credential) := by
  have trace := native_constructor_success_earns_original_trace source lock canonical checked completed
  have meaning := native_constructor_credential_exact source fits
  rw [trace.credentialChecked] at meaning
  have accepted : validateRequirement NativeRecipeError.InvalidCredential
      (nativeSourceCredentialRequirement source.credential) = .ok () := by
    have outcome : (Except.ok () : Except NativeRecipeError Unit) =
        validateRequirement NativeRecipeError.InvalidCredential
          (nativeSourceCredentialRequirement source.credential) := by
      simpa [spec_ok, nativeLockOutcome] using meaning
    exact outcome.symm
  by_contra refused
  simp [validateRequirement, refused] at accepted

theorem native_compile_success_earns_credential (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (fits : NativeSourceCredentialFits source.credential) (output : AuthsNativeRecipe.recipe.CompiledRecipe)
    (completed : AuthsNativeRecipe.recipe.compile_decoded source lock canonical = ok (.Ok output)) :
    RequirementAdmitted (nativeSourceCredentialRequirement output.source.credential) := by
  obtain ⟨checked, admitted, digest, plans, original, namespaceValue⟩ :=
    native_compile_success_keeps_all_stage_results source lock canonical output completed
  have allowed := native_constructor_success_earns_credential source lock canonical fits checked admitted
  simpa [original] using allowed

end Auths.Product.NativeCompiler.Refinement
