import Auths.Product.JcsTreeByteBounds
import Auths.Product.NativeCompiledNumericSerialization

/-!
Actual decoded compiler success constructs complete expected source/schema
trees, all child bytes and nested formatter schedules. This removes supplied
canonical-child buffers at the reference boundary. Native byte-entry/serde,
cast/ryu/formatter/library adequacy and actual canonical/hash input provenance
remain explicit outer requirements; no byte or hash equality is assumed here.
-/
namespace Auths.Product.NativeSerde
open RecipeSerdeGrammar NativeCompiler
open Aeneas Aeneas.Std Result

def CompleteTreeWriter (value : RecipeSerde.Json) (bytes : List Nat) (events : List JcsWriterFrames.Event) : Prop :=
  JcsTreeEncoding.Encoding value bytes ∧ JcsTreeWriter.Trace value bytes events ∧ JcsObjectBytes.BytesBounded bytes ∧
    ∀ state, JcsWriterFrames.run events state = (.ok (), JcsWriterFrames.emit bytes state)

theorem original_serialization_earns_complete_tree_writers (source : NativeRecord .recipe) (lock : NativeRecord .lock)
    (serialized schema : RecipeSerde.Json) (original : OriginalNumericSerialization source lock serialized schema) :
    ∃ sourceBytes sourceEvents schemaBytes schemaEvents,
      CompleteTreeWriter serialized sourceBytes sourceEvents ∧ CompleteTreeWriter schema schemaBytes schemaEvents := by
  obtain ⟨sourceBytes, sourceEvents, sourceEncoding, sourceTrace, sourceBounds, sourceSchedule⟩ :=
    JcsTreeEncoding.complete_unique_safe_tree_earns_bounded_writer serialized original.2.2.1 original.2.1
  obtain ⟨schemaBytes, schemaEvents, schemaEncoding, schemaTrace, schemaBounds, schemaSchedule⟩ :=
    JcsTreeEncoding.complete_unique_safe_tree_earns_bounded_writer schema original.2.2.2.2.2 original.2.2.2.2.1
  exact ⟨sourceBytes, sourceEvents, schemaBytes, schemaEvents,
    ⟨sourceEncoding, sourceTrace, sourceBounds, sourceSchedule⟩, ⟨schemaEncoding, schemaTrace, schemaBounds, schemaSchedule⟩⟩

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

/-- Neither expected child buffers nor successful serializer/canonicalizer
outcomes are premises. This is a partial success consequence of the actual
decoded compiler, not useful native execution or actual canonical provenance. -/
theorem successful_native_compile_earns_complete_tree_writers (rawSource rawLock : RawJson)
    (source : NativeRecord .recipe) (lock : NativeRecord .lock)
    (sourceOriginal : SourceMeaning rawSource source) (lockOriginal : LockMeaning rawLock lock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) (output : AuthsNativeRecipe.recipe.CompiledRecipe)
    (completed : AuthsNativeRecipe.recipe.compile_decoded source lock canonical = ok (.Ok output)) :
    output.source = source ∧ ∃ serialized schema sourceBytes sourceEvents schemaBytes schemaEvents,
      OriginalNumericSerialization output.source lock serialized schema ∧
      CompleteTreeWriter serialized sourceBytes sourceEvents ∧ CompleteTreeWriter schema schemaBytes schemaEvents := by
  obtain ⟨sameSource, serialized, schema, original⟩ := successful_native_compile_earns_numeric_serialization
    rawSource rawLock source lock sourceOriginal lockOriginal canonical output completed
  obtain ⟨sourceBytes, sourceEvents, schemaBytes, schemaEvents, sourceWriter, schemaWriter⟩ :=
    original_serialization_earns_complete_tree_writers output.source lock serialized schema original
  exact ⟨sameSource, serialized, schema, sourceBytes, sourceEvents, schemaBytes, schemaEvents, original, sourceWriter, schemaWriter⟩

end Auths.Product.NativeSerde
