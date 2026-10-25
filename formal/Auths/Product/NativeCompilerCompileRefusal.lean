import Auths.Product.NativeCompilerConstructorAdmission

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

set_option maxHeartbeats 20000000
set_option maxRecDepth 4096

/-- The actual digest consumes canonical-source failure before touching its
hash stages. This data branch makes no serializer-success or hash premise. -/
@[step] theorem native_checked_digest_canonical_failure (checked : NativeConstructorRecord)
    (failed : checked.canonical_source = .Err ()) :
    AuthsNativeRecipe.recipe.validate.ValidatedSource.digest checked ⦃ actual => actual = .Err .InvalidSource ⦄ := by
  simp [AuthsNativeRecipe.recipe.validate.ValidatedSource.digest, failed]

/-- The complete compiler propagates the first independent constructor error;
neither digest nor lowering is used to justify accepting a refused source. -/
theorem native_compile_constructor_refusal (hash : List Nat → List Nat) (library : NativeSha256LibraryContract hash)
    (source : NativeConstructorSource) (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (schema : ProfileSchema.Value) (schemaBounds : JsonBounds lock.command_schema) (schemaMeaning : JsonMeaning lock.command_schema schema)
    (body : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body body)
    (fits : ConstructorSourceFits source) (lockFits : NativeProfileLockFits lock) (hashRoom : NativeCanonicalFits 0 canonical.schema)
    (error : NativeRecipeError)
    (refused : RecipeConstructorAdmission.validate constructorErrors hash (originalConstructorSource source body)
      (originalConstructorLock lock canonical schema) (constructorParsedOrigin source fits) = .error error) :
    AuthsNativeRecipe.recipe.compile_decoded source lock canonical ⦃ actual => actual = .Err error ⦄ := by
  unfold AuthsNativeRecipe.recipe.compile_decoded
  step with native_constructor_refusal hash library source lock canonical schema schemaBounds schemaMeaning body bodyMeaning
    fits lockFits hashRoom error refused as ⟨checked, result⟩
  simp [result, core.result.Result.Insts.CoreOpsTry.branch,
    core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
    core.convert.FromSame, core.convert.FromSame.from]

/-- Source canonicalization failure is consumed after constructor admission.
Earlier lock/profile/schema/namespace/credential/origin/rule errors still win;
otherwise the actual compiler refuses InvalidSource before lowering. -/
@[step] theorem native_compile_failed_source_outcome_exact (hash : List Nat → List Nat)
    (library : NativeSha256LibraryContract hash) (source : NativeConstructorSource) (lock : NativeProfileLock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) (schema : ProfileSchema.Value)
    (schemaBounds : JsonBounds lock.command_schema) (schemaMeaning : JsonMeaning lock.command_schema schema)
    (body : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body body)
    (fits : ConstructorSourceFits source) (lockFits : NativeProfileLockFits lock)
    (hashRoom : NativeCanonicalFits 0 canonical.schema) (failed : canonical.source = .Err ()) :
    AuthsNativeRecipe.recipe.compile_decoded source lock canonical ⦃ actual =>
      actual = match RecipeConstructorAdmission.validate constructorErrors hash (originalConstructorSource source body)
          (originalConstructorLock lock canonical schema) (constructorParsedOrigin source fits) with
        | .error error => .Err error
        | .ok _ => .Err .InvalidSource ⦄ := by
  unfold AuthsNativeRecipe.recipe.compile_decoded
  step with native_constructor_admission_exact hash library source lock canonical schema schemaBounds schemaMeaning body bodyMeaning
    fits lockFits hashRoom as ⟨checked, semantic, frame⟩
  cases verdict : RecipeConstructorAdmission.validate constructorErrors hash (originalConstructorSource source body)
      (originalConstructorLock lock canonical schema) (constructorParsedOrigin source fits) with
  | error error =>
      have refused : checked = .Err error := by cases checked <;> simp_all [constructorOutcome]
      simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, verdict]
  | ok value =>
      cases checked with
      | Err error => simp [constructorOutcome, verdict] at semantic
      | Ok record =>
          have recordFailed : record.canonical_source = .Err () := (frame record rfl).2.trans failed
          simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
          step with native_checked_digest_canonical_failure record recordFailed as ⟨digest, digestFailure⟩
          simp [digestFailure, core.result.Result.Insts.CoreOpsTry.branch,
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame, core.convert.FromSame.from, verdict]

end Auths.Product.NativeCompiler.Refinement
