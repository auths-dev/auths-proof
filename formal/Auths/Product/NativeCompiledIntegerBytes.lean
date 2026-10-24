import Auths.Product.AdmittedIntegerBytes
import Auths.Product.NativeCompiledNumericSerialization

/-!
Actual decoded compiler success earns expected exact decimal bytes for every
original numeric occurrence of the complete source AND command schema. This
does not assert that the native Serialize/cast/ryu/writer produced those bytes;
that implementation adequacy and canonical/hash provenance remain explicit.
-/
namespace Auths.Product.NativeSerde
open RecipeSerdeGrammar NativeCompiler
open Aeneas Aeneas.Std Result

theorem original_numeric_serialization_earns_exact_decimal (source : NativeRecord .recipe) (lock : NativeRecord .lock)
    (serialized schema : RecipeSerde.Json) (original : OriginalNumericSerialization source lock serialized schema) :
    (∀ number, FullJsonNumericSafety.NumberIn number serialized → AdmittedIntegerBytes.ExactDecimal number) ∧
    (∀ number, FullJsonNumericSafety.NumberIn number schema → AdmittedIntegerBytes.ExactDecimal number) :=
  ⟨AdmittedIntegerBytes.every_original_number_has_exact_decimal serialized original.2.2.1,
    AdmittedIntegerBytes.every_original_number_has_exact_decimal schema original.2.2.2.2.2⟩

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

theorem successful_native_compile_earns_exact_decimal (rawSource rawLock : RawJson)
    (source : NativeRecord .recipe) (lock : NativeRecord .lock)
    (sourceOriginal : SourceMeaning rawSource source) (lockOriginal : LockMeaning rawLock lock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) (output : AuthsNativeRecipe.recipe.CompiledRecipe)
    (completed : AuthsNativeRecipe.recipe.compile_decoded source lock canonical = ok (.Ok output)) :
    output.source = source ∧ ∃ serialized schema, OriginalNumericSerialization output.source lock serialized schema ∧
      (∀ number, FullJsonNumericSafety.NumberIn number serialized → AdmittedIntegerBytes.ExactDecimal number) ∧
      (∀ number, FullJsonNumericSafety.NumberIn number schema → AdmittedIntegerBytes.ExactDecimal number) := by
  obtain ⟨sameSource, serialized, schema, original⟩ := successful_native_compile_earns_numeric_serialization
    rawSource rawLock source lock sourceOriginal lockOriginal canonical output completed
  have exactBytes := original_numeric_serialization_earns_exact_decimal output.source lock serialized schema original
  exact ⟨sameSource, serialized, schema, original, exactBytes⟩

end Auths.Product.NativeSerde
