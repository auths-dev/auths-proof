import Auths.Product.NativeCompilerOutcome
import Auths.Product.NativeCompilerLockDigest
import Auths.Product.NativeCompilerCompileProvenance

open Aeneas Aeneas.Std Result

namespace Auths.Product.NativeCompiler

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

abbrev NativeConstructorSource := AuthsNativeRecipe.recipe.source.RecipeSource
abbrev NativeConstructorRecord := AuthsNativeRecipe.recipe.validate.ValidatedSource
abbrev NativeRuleFields := AuthsNativeRecipe.alloc.collections.btree.map.BTreeMap String NativeScalarSchema Global

def constructorSourceTag (source : NativeConstructorSource) : Result Bool := do
  let schema ← AuthsNativeRecipe.alloc.string.String.as_bytes source.schema
  AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.source_schema_supported schema

def constructorProfileBinding (source : NativeConstructorSource) (lock : NativeProfileLock) : Result Bool := do
  let service ← AuthsNativeRecipe.alloc.string.String.as_bytes source.service
  let tool ← AuthsNativeRecipe.alloc.string.String.as_bytes source.tool
  let digest ← AuthsNativeRecipe.alloc.string.String.as_bytes source.profile_schema_digest
  let lockService ← AuthsNativeRecipe.alloc.string.String.as_bytes lock.service
  let lockTool ← AuthsNativeRecipe.alloc.string.String.as_bytes lock.tool
  let lockDigest ← AuthsNativeRecipe.alloc.string.String.as_bytes lock.schema_digest
  AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.source_matches_profile
    ⟨service, tool, digest⟩ ⟨lockService, lockTool, lockDigest⟩

def constructorNamespace (source : NativeConstructorSource) :
    Result (core.result.Result AuthsNativeRecipe.recipe.OperatorNamespace NativeRecipeError) := do
  let original ← AuthsNativeRecipe.alloc.string.String.Insts.CoreOpsDerefDerefStr.deref source.operator_namespace
  AuthsNativeRecipe.recipe.OperatorNamespace.parse original

def constructorCredential (source : NativeConstructorSource) : Result (core.result.Result Unit NativeRecipeError) := do
  let requirement ← AuthsNativeRecipe.recipe.credential_requirement source.credential
  AuthsNativeRecipe.recipe.CredentialRequirement.validate requirement

def constructorOrigin (source : NativeConstructorSource) : Result (core.result.Result String NativeRecipeError) := do
  let original ← AuthsNativeRecipe.alloc.string.String.Insts.CoreOpsDerefDerefStr.deref source.origin
  AuthsNativeRecipe.recipe.validate_origin original

/-- An operational trace earned from the actual constructor's successful
return. These child outcomes are conclusions, never validator-success premises.
They still need independent semantic refinements; this record alone is not an
admission specification, usefulness proof or resource bound. -/
structure NativeConstructorTrace (source : NativeConstructorSource) (lock : NativeProfileLock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) (checked : NativeConstructorRecord) : Prop where
  originalSource : checked.source = source
  canonicalSource : checked.canonical_source = canonical.source
  sourceTag : constructorSourceTag source = ok true
  lockChecked : AuthsNativeRecipe.recipe.validate_lock lock canonical.schema = ok (.Ok ())
  profileBound : constructorProfileBinding source lock = ok true
  fieldsChecked : AuthsNativeRecipe.recipe.parse_root_fields lock.command_schema = ok (.Ok checked.field_specs)
  namespaceChecked : constructorNamespace source = ok (.Ok checked.«namespace»)
  bindingFields : AuthsNativeRecipe.recipe.validate_binding_fields
    (AuthsNativeRecipe.alloc.vec.Vec.deref checked.field_specs) checked.«namespace» = ok (.Ok ())
  ruleFields : ∃ fields : NativeRuleFields,
    AuthsNativeRecipe.recipe.profile.rule_fields (AuthsNativeRecipe.alloc.vec.Vec.deref checked.field_specs) =
      ok (.Ok fields) ∧ AuthsNativeRecipe.recipe.validate.validate_source_rules source fields = ok (.Ok ())
  credentialChecked : constructorCredential source = ok (.Ok ())
  originChecked : constructorOrigin source = ok (.Ok checked.parsed_host)

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.Outcome
open Aeneas.Std.WP
open Auths.Product.NativeCompiler.StdModel

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

set_option maxHeartbeats 12000000
set_option maxRecDepth 4096

/-- All original columns and every actual admission stage are earned from the
successful native constructor. No getter/private-record invariant or child
success is taken as an admission premise. -/
theorem native_constructor_success_earns_original_trace
    (source : NativeConstructorSource) (lock : NativeProfileLock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) (checked : NativeConstructorRecord)
    (completed : AuthsNativeRecipe.recipe.validate.validate_source source lock canonical = ok (.Ok checked)) :
    NativeConstructorTrace source lock canonical checked := by
  unfold AuthsNativeRecipe.recipe.validate.validate_source at completed
  obtain ⟨schema, schemaRead, afterSchema⟩ := successful_bind _ _ (.Ok checked) completed
  obtain ⟨tag, tagStep, afterTag⟩ := successful_bind _ _ (.Ok checked) afterSchema
  cases tag with
  | false => simp at afterTag
  | true =>
      simp only [Bool.true_eq_true, ↓reduceIte] at afterTag
      obtain ⟨lockUnit, lockStep, afterLock⟩ := successful_try _ _ checked afterTag
      cases lockUnit
      obtain ⟨service, serviceRead, afterService⟩ := successful_bind _ _ (.Ok checked) afterLock
      obtain ⟨tool, toolRead, afterTool⟩ := successful_bind _ _ (.Ok checked) afterService
      obtain ⟨digest, digestRead, afterDigest⟩ := successful_bind _ _ (.Ok checked) afterTool
      obtain ⟨lockService, lockServiceRead, afterLockService⟩ := successful_bind _ _ (.Ok checked) afterDigest
      obtain ⟨lockTool, lockToolRead, afterLockTool⟩ := successful_bind _ _ (.Ok checked) afterLockService
      obtain ⟨lockDigest, lockDigestRead, afterLockDigest⟩ := successful_bind _ _ (.Ok checked) afterLockTool
      obtain ⟨matches, bindingStep, afterBinding⟩ := successful_bind _ _ (.Ok checked) afterLockDigest
      cases matches with
      | false => simp at afterBinding
      | true =>
          simp only [Bool.true_eq_true, ↓reduceIte] at afterBinding
          obtain ⟨fields, fieldStep, afterFields⟩ := successful_try _ _ checked afterBinding
          obtain ⟨namespaceInput, namespaceRead, afterNamespaceInput⟩ := successful_bind _ _ (.Ok checked) afterFields
          obtain ⟨namespaceValue, namespaceStep, afterNamespace⟩ := successful_try _ _ checked afterNamespaceInput
          obtain ⟨bindingUnit, bindingFieldsStep, afterBindingFields⟩ := successful_try _ _ checked afterNamespace
          cases bindingUnit
          obtain ⟨ruleFields, ruleFieldsStep, afterRuleFields⟩ := successful_try _ _ checked afterBindingFields
          obtain ⟨requirement, requirementRead, afterRequirement⟩ := successful_bind _ _ (.Ok checked) afterRuleFields
          obtain ⟨credentialUnit, credentialStep, afterCredential⟩ := successful_try _ _ checked afterRequirement
          cases credentialUnit
          obtain ⟨originInput, originRead, afterOriginInput⟩ := successful_bind _ _ (.Ok checked) afterCredential
          obtain ⟨host, originStep, afterOrigin⟩ := successful_try _ _ checked afterOriginInput
          obtain ⟨rulesUnit, sourceRulesStep, afterRules⟩ := successful_try _ _ checked afterOrigin
          cases rulesUnit
          have built : ({ source := source, field_specs := fields, «namespace» := namespaceValue,
              parsed_host := host, canonical_source := canonical.source } : NativeConstructorRecord) = checked := by
            simpa using afterRules
          cases built
          refine {
            originalSource := rfl
            canonicalSource := rfl
            sourceTag := ?_
            lockChecked := lockStep
            profileBound := ?_
            fieldsChecked := fieldStep
            namespaceChecked := ?_
            bindingFields := bindingFieldsStep
            ruleFields := ⟨ruleFields, ruleFieldsStep, sourceRulesStep⟩
            credentialChecked := ?_
            originChecked := ?_
          }
          · simp [constructorSourceTag, schemaRead, tagStep]
          · simp [constructorProfileBinding, serviceRead, toolRead, digestRead,
              lockServiceRead, lockToolRead, lockDigestRead, bindingStep]
          · simp [constructorNamespace, namespaceRead, namespaceStep]
          · simp [constructorCredential, requirementRead, credentialStep]
          · simp [constructorOrigin, originRead, originStep]

/-- The actual complete compile caller retains this constructor trace alongside
its exact digest, plan bundle and consumed namespace. -/
theorem native_compile_success_earns_constructor_trace
    (source : NativeConstructorSource) (lock : NativeProfileLock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (output : AuthsNativeRecipe.recipe.CompiledRecipe)
    (completed : AuthsNativeRecipe.recipe.compile_decoded source lock canonical = ok (.Ok output)) :
    ∃ checked : NativeConstructorRecord, NativeConstructorTrace source lock canonical checked ∧
      AuthsNativeRecipe.recipe.validate.ValidatedSource.digest checked = ok (.Ok output.digest) ∧
      AuthsNativeRecipe.recipe.lower.plans checked = ok (.Ok output.plans) ∧
      output.source = source ∧ output.«namespace» = checked.«namespace» := by
  obtain ⟨checked, admitted, digest, plans, original, namespaceValue⟩ :=
    native_compile_success_keeps_all_stage_results source lock canonical output completed
  exact ⟨checked, native_constructor_success_earns_original_trace source lock canonical checked admitted,
    digest, plans, original, namespaceValue⟩

/-- Overall success earns canonical-source success and the exact original
recipe preimage. The foreign serializer relation must separately establish
that this retained outcome came from serialization of the original source. -/
theorem native_compile_success_earns_original_commitment (hash : List Nat → List Nat)
    (library : NativeSha256LibraryContract hash) (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (hashRoom : NativeCanonicalFits 32 canonical.source) (output : AuthsNativeRecipe.recipe.CompiledRecipe)
    (completed : AuthsNativeRecipe.recipe.compile_decoded source lock canonical = ok (.Ok output)) :
    output.source = source ∧ ∃ original, canonical.source = .Ok original ∧
      nativeDigestArrayBytes output.digest = hash (RecipeBinding.digestPreimage (bytes original)) := by
  obtain ⟨checked, trace, digestStep, plansStep, original, namespaceValue⟩ :=
    native_compile_success_earns_constructor_trace source lock canonical output completed
  have checkedRoom : NativeCanonicalFits 32 checked.canonical_source := by
    simpa only [trace.canonicalSource] using hashRoom
  have digestMeaning := native_checked_recipe_digest_exact hash library checked checkedRoom
  rw [digestStep] at digestMeaning
  have meaning : Except.ok (nativeDigestArrayBytes output.digest) =
      RecipeLockAdmission.recipeDigest compilerLockErrors hash (nativeCanonicalOutcome canonical.source) := by
    simpa [spec_ok, nativeDigestOutcome, trace.canonicalSource] using digestMeaning
  refine ⟨original, ?_⟩
  cases canonicalOutcome : canonical.source with
  | Err reason => cases reason; simp [RecipeLockAdmission.recipeDigest, nativeCanonicalOutcome, canonicalOutcome] at meaning
  | Ok canonicalBytes =>
      refine ⟨canonicalBytes, canonicalOutcome, ?_⟩
      simpa [RecipeLockAdmission.recipeDigest, nativeCanonicalOutcome, canonicalOutcome] using meaning

@[step] theorem native_constructor_unsupported_schema (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (fits : TextFits source.schema) (unsupported : textBytes source.schema ≠ RecipeBinding.sourceSchema) :
    AuthsNativeRecipe.recipe.validate.validate_source source lock canonical ⦃ actual =>
      actual = .Err NativeRecipeError.InvalidSource ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.validate_source
  step with borrow_text_exact source.schema fits as ⟨schema, schemaMeaning⟩
  step with native_source_schema_exact schema as ⟨supported, supportedMeaning⟩
  have refused : supported = false := by
    simpa [schemaSliceBytes, schemaMeaning, unsupported] using supportedMeaning
  simp [refused]

end Auths.Product.NativeCompiler.Refinement
