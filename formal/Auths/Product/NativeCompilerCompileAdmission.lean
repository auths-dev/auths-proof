import Auths.Product.RecipeCompilerAdmission
import Auths.Product.NativeCompilerPlanAdmissionDomain

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def compilerValue (output : AuthsNativeRecipe.recipe.CompiledRecipe) : RecipeCompilerAdmission.Value :=
  ⟨textBytes output.«namespace», nativeDigestArrayBytes output.digest, nativePlans output.plans⟩

def compilerOutcome : core.result.Result AuthsNativeRecipe.recipe.CompiledRecipe NativeRecipeError →
    Except NativeRecipeError RecipeCompilerAdmission.Value
  | .Err error => .error error
  | .Ok output => .ok (compilerValue output)

def CompilerFrame (source : NativeConstructorSource)
    (actual : core.result.Result AuthsNativeRecipe.recipe.CompiledRecipe NativeRecipeError) : Prop :=
  ∀ output, actual = .Ok output → output.source = source

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

def decodedCompilerModel (hash : List Nat → List Nat) (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (schema : ProfileSchema.Value) (body : TemplateAst.Body) (fits : ConstructorSourceFits source) :
    Except NativeRecipeError RecipeCompilerAdmission.Value :=
  RecipeCompilerAdmission.compile constructorErrors compilerLockErrors planErrors hash
    (originalConstructorSource source body) (originalConstructorLock lock canonical schema)
    (constructorParsedOrigin source fits) (planSource source body)

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

set_option maxHeartbeats 30000000
set_option maxRecDepth 4096

/-- Complete actual decoded compiler, all constructor/digest/lowering outcomes
and source order. The constructor earns the checked record's lowering domain;
no chosen checked record, successful native child, expected plan or callback is
a premise. Canonical bytes and named hash/URL library adequacy remain explicit
outer boundaries; this is not a public-byte or physical-cost theorem. -/
@[step] theorem native_compile_decoded_admission_exact (hash : List Nat → List Nat)
    (library : NativeSha256LibraryContract hash) (source : NativeConstructorSource) (lock : NativeProfileLock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) (schema : ProfileSchema.Value)
    (schemaBounds : JsonBounds lock.command_schema) (schemaMeaning : JsonMeaning lock.command_schema schema)
    (body : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body body)
    (fits : ConstructorSourceFits source) (lockFits : NativeProfileLockFits lock)
    (schemaRoom : NativeCanonicalFits 0 canonical.schema) (sourceRoom : NativeCanonicalFits 32 canonical.source) :
    AuthsNativeRecipe.recipe.compile_decoded source lock canonical ⦃ actual =>
      compilerOutcome actual = decodedCompilerModel hash source lock canonical schema body fits ∧
      CompilerFrame source actual ⦄ := by
  unfold AuthsNativeRecipe.recipe.compile_decoded
  step with native_constructor_admission_with_plan_domain hash library source lock canonical schema schemaBounds schemaMeaning
    body bodyMeaning fits lockFits schemaRoom as ⟨admission, semantic, frame, domain⟩
  cases admission with
  | Err error =>
      have modelAt : RecipeConstructorAdmission.validate constructorErrors hash (originalConstructorSource source body)
          (originalConstructorLock lock canonical schema) (constructorParsedOrigin source fits) = .error error := by
        simpa [constructorOutcome] using semantic.symm
      simp [decodedCompilerModel, RecipeCompilerAdmission.compile, modelAt, compilerOutcome, CompilerFrame,
        core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from]
  | Ok checked =>
      have modelAt : RecipeConstructorAdmission.validate constructorErrors hash (originalConstructorSource source body)
          (originalConstructorLock lock canonical schema) (constructorParsedOrigin source fits) = .ok (constructorValue checked) := by
        simpa [constructorOutcome] using semantic.symm
      obtain ⟨originalSource, originalCanonical⟩ := frame checked rfl
      have checkedRoom : NativeCanonicalFits 32 checked.canonical_source := by
        simpa only [originalCanonical] using sourceRoom
      have originalBody : BodySourceMeaning checked.source.write.body body := by
        simpa only [originalSource] using bodyMeaning
      simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      step with native_checked_recipe_digest_exact hash library checked checkedRoom as ⟨digested, digestMeaning⟩
      cases digested with
      | Err error =>
          have digestAt : RecipeLockAdmission.recipeDigest compilerLockErrors hash
              (constructorValue checked).canonicalSource = .error error := by
            simpa [constructorValue, nativeDigestOutcome] using digestMeaning.symm
          simp [decodedCompilerModel, RecipeCompilerAdmission.compile, modelAt,
            RecipeCompilerAdmission.afterConstructor, digestAt, compilerOutcome, CompilerFrame,
            core.result.Result.Insts.CoreOpsTry.branch,
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame, core.convert.FromSame.from]
      | Ok digest =>
          have digestAt : RecipeLockAdmission.recipeDigest compilerLockErrors hash
              (constructorValue checked).canonicalSource = .ok (nativeDigestArrayBytes digest) := by
            simpa [constructorValue, nativeDigestOutcome] using digestMeaning.symm
          simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
          step with native_plans_exact checked body originalBody (domain checked rfl) as ⟨lowered, plansMeaning⟩
          cases lowered with
          | Err error =>
              have plansAt : RecipePlanModel.compile planErrors
                  (RecipeCompilerAdmission.fieldsOfPairs (constructorValue checked).fields)
                  (constructorValue checked).host (planSource source body) = .error error := by
                simpa [constructorValue, RecipeCompilerAdmission.original_fields_roundtrip,
                  originalSource, nativeRecipeResult] using plansMeaning.symm
              simp [decodedCompilerModel, RecipeCompilerAdmission.compile, modelAt,
                RecipeCompilerAdmission.afterConstructor, digestAt, RecipeCompilerAdmission.afterDigest, plansAt,
                compilerOutcome, CompilerFrame, core.result.Result.Insts.CoreOpsTry.branch,
                core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                core.convert.FromSame, core.convert.FromSame.from]
          | Ok plans =>
              have plansAt : RecipePlanModel.compile planErrors
                  (RecipeCompilerAdmission.fieldsOfPairs (constructorValue checked).fields)
                  (constructorValue checked).host (planSource source body) = .ok (nativePlans plans) := by
                simpa [constructorValue, RecipeCompilerAdmission.original_fields_roundtrip,
                  originalSource, nativeRecipeResult] using plansMeaning.symm
              simp [decodedCompilerModel, RecipeCompilerAdmission.compile, modelAt,
                RecipeCompilerAdmission.afterConstructor, digestAt, RecipeCompilerAdmission.afterDigest, plansAt,
                compilerOutcome, compilerValue, constructorValue, CompilerFrame,
                core.result.Result.Insts.CoreOpsTry.branch,
                AuthsNativeRecipe.recipe.validate.ValidatedSource.into_namespace]

theorem native_compile_decoded_useful (hash : List Nat → List Nat) (library : NativeSha256LibraryContract hash)
    (source : NativeConstructorSource) (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (schema : ProfileSchema.Value) (schemaBounds : JsonBounds lock.command_schema) (schemaMeaning : JsonMeaning lock.command_schema schema)
    (body : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body body)
    (fits : ConstructorSourceFits source) (lockFits : NativeProfileLockFits lock)
    (schemaRoom : NativeCanonicalFits 0 canonical.schema) (sourceRoom : NativeCanonicalFits 32 canonical.source)
    (value : RecipeCompilerAdmission.Value)
    (admitted : decodedCompilerModel hash source lock canonical schema body fits = .ok value) :
    AuthsNativeRecipe.recipe.compile_decoded source lock canonical ⦃ actual =>
      ∃ output, actual = .Ok output ∧ compilerValue output = value ∧ output.source = source ⦄ := by
  apply spec_mono (native_compile_decoded_admission_exact hash library source lock canonical schema schemaBounds schemaMeaning
    body bodyMeaning fits lockFits schemaRoom sourceRoom)
  rintro actual ⟨semantic, frame⟩
  cases actual with
  | Err error => simp [compilerOutcome, admitted] at semantic
  | Ok output =>
      have original : compilerValue output = value := by simpa [compilerOutcome, admitted] using semantic
      exact ⟨output, rfl, original, frame output rfl⟩

theorem native_compile_decoded_refusal (hash : List Nat → List Nat) (library : NativeSha256LibraryContract hash)
    (source : NativeConstructorSource) (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (schema : ProfileSchema.Value) (schemaBounds : JsonBounds lock.command_schema) (schemaMeaning : JsonMeaning lock.command_schema schema)
    (body : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body body)
    (fits : ConstructorSourceFits source) (lockFits : NativeProfileLockFits lock)
    (schemaRoom : NativeCanonicalFits 0 canonical.schema) (sourceRoom : NativeCanonicalFits 32 canonical.source)
    (error : NativeRecipeError) (refused : decodedCompilerModel hash source lock canonical schema body fits = .error error) :
    AuthsNativeRecipe.recipe.compile_decoded source lock canonical ⦃ actual => actual = .Err error ⦄ := by
  apply spec_mono (native_compile_decoded_admission_exact hash library source lock canonical schema schemaBounds schemaMeaning
    body bodyMeaning fits lockFits schemaRoom sourceRoom)
  rintro actual ⟨semantic, _⟩
  cases actual <;> simp_all [compilerOutcome]

/-- Independent useful source, canonical bytes and plan construction yield an
actual complete compiler result, preserving the original source and every
semantic plan column. No actual successful helper is supplied. -/
theorem native_compile_from_independent_source_and_plans (hash : List Nat → List Nat)
    (library : NativeSha256LibraryContract hash) (source : NativeConstructorSource) (lock : NativeProfileLock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) (schema : ProfileSchema.Value)
    (schemaBounds : JsonBounds lock.command_schema) (schemaMeaning : JsonMeaning lock.command_schema schema)
    (body : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body body)
    (fits : ConstructorSourceFits source) (lockFits : NativeProfileLockFits lock)
    (schemaRoom : NativeCanonicalFits 0 canonical.schema) (sourceRoom : NativeCanonicalFits 32 canonical.source)
    (admitted : RecipeConstructorAdmission.Value) (canonicalBytes : List Nat) (plans : RecipePlanModel.Plans)
    (sourceAt : RecipeConstructorAdmission.validate constructorErrors hash (originalConstructorSource source body)
      (originalConstructorLock lock canonical schema) (constructorParsedOrigin source fits) = .ok admitted)
    (canonicalAt : admitted.canonicalSource = .ok canonicalBytes)
    (plansAt : RecipePlanModel.compile planErrors (RecipeCompilerAdmission.fieldsOfPairs admitted.fields)
      admitted.host (planSource source body) = .ok plans) :
    AuthsNativeRecipe.recipe.compile_decoded source lock canonical ⦃ actual =>
      ∃ output, actual = .Ok output ∧ output.source = source ∧
        textBytes output.«namespace» = admitted.namespaceBytes ∧
        nativeDigestArrayBytes output.digest = hash (RecipeBinding.digestPreimage canonicalBytes) ∧
        nativePlans output.plans = plans ⦄ := by
  have model := RecipeCompilerAdmission.independently_admitted_source_and_plans_compile
    constructorErrors compilerLockErrors planErrors hash (originalConstructorSource source body)
    (originalConstructorLock lock canonical schema) (constructorParsedOrigin source fits) (planSource source body)
    admitted canonicalBytes plans sourceAt canonicalAt plansAt
  apply spec_mono (native_compile_decoded_useful hash library source lock canonical schema schemaBounds schemaMeaning
    body bodyMeaning fits lockFits schemaRoom sourceRoom _ model)
  rintro actual ⟨output, completed, meaning, original⟩
  exact ⟨output, completed, original, congrArg RecipeCompilerAdmission.Value.namespaceBytes meaning,
    congrArg RecipeCompilerAdmission.Value.digest meaning, congrArg RecipeCompilerAdmission.Value.plans meaning⟩

theorem native_compile_success_has_original_components (hash : List Nat → List Nat)
    (library : NativeSha256LibraryContract hash) (source : NativeConstructorSource) (lock : NativeProfileLock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) (schema : ProfileSchema.Value)
    (schemaBounds : JsonBounds lock.command_schema) (schemaMeaning : JsonMeaning lock.command_schema schema)
    (body : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body body)
    (fits : ConstructorSourceFits source) (lockFits : NativeProfileLockFits lock)
    (schemaRoom : NativeCanonicalFits 0 canonical.schema) (sourceRoom : NativeCanonicalFits 32 canonical.source)
    (output : AuthsNativeRecipe.recipe.CompiledRecipe)
    (completed : AuthsNativeRecipe.recipe.compile_decoded source lock canonical = ok (.Ok output)) :
    output.source = source ∧ RecipeCompilerAdmission.Meaning constructorErrors compilerLockErrors planErrors hash
      (originalConstructorSource source body) (originalConstructorLock lock canonical schema)
      (constructorParsedOrigin source fits) (planSource source body) (compilerValue output) := by
  have exact := native_compile_decoded_admission_exact hash library source lock canonical schema schemaBounds schemaMeaning
    body bodyMeaning fits lockFits schemaRoom sourceRoom
  rw [completed] at exact
  have facts : compilerOutcome (.Ok output) = decodedCompilerModel hash source lock canonical schema body fits ∧
      CompilerFrame source (.Ok output) := by simpa only [spec_ok] using exact
  refine ⟨facts.2 output rfl, ?_⟩
  apply RecipeCompilerAdmission.success_has_original_components constructorErrors compilerLockErrors planErrors hash
    (originalConstructorSource source body) (originalConstructorLock lock canonical schema)
    (constructorParsedOrigin source fits) (planSource source body) (compilerValue output)
  simpa only [decodedCompilerModel, compilerOutcome] using facts.1.symm

end Auths.Product.NativeCompiler.Refinement
