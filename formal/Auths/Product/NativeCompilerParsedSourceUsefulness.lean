import Auths.Product.NativeCompilerSourceMapOrder
import Auths.Product.NativeCompilerCompleteUsefulness

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

/-- Useful decoded compilation now consumes order from the same native body
representation, rather than an independently supplied abstract AST property.
The actual strict parser/serde/BTreeMap boundary must earn that representation,
all byte bounds and canonical provenance; it is not qualified by this wrapper. -/
theorem native_compile_useful_with_original_map_order (hash : List Nat → List Nat)
    (library : NativeSha256LibraryContract hash) (source : NativeConstructorSource) (lock : NativeProfileLock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) (schema : ProfileSchema.Value)
    (schemaBounds : JsonBounds lock.command_schema) (schemaMeaning : JsonMeaning lock.command_schema schema)
    (body : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body body)
    (fits : ConstructorSourceFits source) (lockFits : NativeProfileLockFits lock)
    (order : NativeBodyMapOrder source.write.body) (schemaRoom : NativeCanonicalFits 0 canonical.schema)
    (sourceRoom : NativeCanonicalFits 32 canonical.source) (admitted : RecipeConstructorAdmission.Value)
    (sourceAt : RecipeConstructorAdmission.validate constructorErrors hash (originalConstructorSource source body)
      (originalConstructorLock lock canonical schema) (constructorParsedOrigin source fits) = .ok admitted)
    (canonicalBytes : NativeVec Std.U8) (canonicalAt : canonical.source = .Ok canonicalBytes) :
    AuthsNativeRecipe.recipe.compile_decoded source lock canonical ⦃ actual => ∃ output,
      actual = .Ok output ∧ output.source = source ∧ textBytes output.«namespace» = admitted.namespaceBytes ∧
      nativeDigestArrayBytes output.digest = hash (RecipeBinding.digestPreimage (bytes canonicalBytes)) ∧
      RecipeConstructorAdmission.fieldPairs (nativeFieldsMeaning output.plans.field_schemas) = admitted.fields ⦄ := by
  exact native_compile_useful_from_source_admission hash library source lock canonical schema schemaBounds schemaMeaning
    body bodyMeaning fits lockFits (original_body_map_order _ _ bodyMeaning order) schemaRoom sourceRoom admitted sourceAt canonicalBytes canonicalAt

end Auths.Product.NativeCompiler.Refinement
