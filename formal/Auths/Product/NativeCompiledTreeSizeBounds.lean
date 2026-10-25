import Auths.Product.JcsTreeSizeBounds
import Auths.Product.JcsTreeWeight
import Auths.Product.NativeCompiledTreeEncoding

/-!
Actual decoded compiler success earns complete expected source/schema output
lengths from those SAME original full values. No child/canonical lengths,
capacity flag or selected schema/body is supplied. Native canonical-input
provenance, raw-byte-to-tree size accounting and aggregate physical resources
remain outer requirements; this does not discharge NativeCanonicalFits.
-/
namespace Auths.Product.NativeSerde
open RecipeSerdeGrammar NativeCompiler
open Aeneas Aeneas.Std Result

def SizeBoundedTreeWriter (value : RecipeSerde.Json) (bytes : List Nat) (events : List JcsWriterFrames.Event) : Prop :=
  CompleteTreeWriter value bytes events ∧ bytes.length ≤ JcsTreeEncoding.outputBound value

theorem size_bounded_writer_is_linear_in_original_weight (value : RecipeSerde.Json) (bytes : List Nat)
    (events : List JcsWriterFrames.Event) (bounded : SizeBoundedTreeWriter value bytes events) :
    bytes.length ≤ 17 * JcsTreeEncoding.treeWeight value :=
  bounded.2.trans (JcsTreeEncoding.output_bound_is_linear_in_original_weight value)

theorem original_serialization_earns_size_bounded_tree_writers (source : NativeRecord .recipe) (lock : NativeRecord .lock)
    (serialized schema : RecipeSerde.Json) (original : OriginalNumericSerialization source lock serialized schema) :
    ∃ sourceBytes sourceEvents schemaBytes schemaEvents,
      SizeBoundedTreeWriter serialized sourceBytes sourceEvents ∧ SizeBoundedTreeWriter schema schemaBytes schemaEvents := by
  obtain ⟨sourceBytes, sourceEvents, schemaBytes, schemaEvents, sourceWriter, schemaWriter⟩ :=
    original_serialization_earns_complete_tree_writers source lock serialized schema original
  have sourceSize := JcsTreeEncoding.complete_encoding_length_bound sourceWriter.1 original.2.1
  have schemaSize := JcsTreeEncoding.complete_encoding_length_bound schemaWriter.1 original.2.2.2.2.1
  exact ⟨sourceBytes, sourceEvents, schemaBytes, schemaEvents, ⟨sourceWriter, sourceSize⟩, ⟨schemaWriter, schemaSize⟩⟩

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

theorem successful_native_compile_earns_tree_size_bounds (rawSource rawLock : RawJson)
    (source : NativeRecord .recipe) (lock : NativeRecord .lock)
    (sourceOriginal : SourceMeaning rawSource source) (lockOriginal : LockMeaning rawLock lock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) (output : AuthsNativeRecipe.recipe.CompiledRecipe)
    (completed : AuthsNativeRecipe.recipe.compile_decoded source lock canonical = ok (.Ok output)) :
    output.source = source ∧ ∃ serialized schema sourceBytes sourceEvents schemaBytes schemaEvents,
      OriginalNumericSerialization output.source lock serialized schema ∧
      SizeBoundedTreeWriter serialized sourceBytes sourceEvents ∧ SizeBoundedTreeWriter schema schemaBytes schemaEvents := by
  obtain ⟨sameSource, serialized, schema, original⟩ := successful_native_compile_earns_numeric_serialization
    rawSource rawLock source lock sourceOriginal lockOriginal canonical output completed
  obtain ⟨sourceBytes, sourceEvents, schemaBytes, schemaEvents, sourceWriter, schemaWriter⟩ :=
    original_serialization_earns_size_bounded_tree_writers output.source lock serialized schema original
  exact ⟨sameSource, serialized, schema, sourceBytes, sourceEvents, schemaBytes, schemaEvents, original, sourceWriter, schemaWriter⟩

end Auths.Product.NativeSerde
