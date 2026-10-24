import Auths.Product.RecipeSerdeGrammar
import Auths.Product.NativeCompilerAstMeaning

/-!
Actual native types and COMPLETE field columns for the closed serde grammar.
Every field is read directly from its original native record/variant; there
is no selected field, truncating zip, decoder callback or admission predicate.
This is a representation bridge, not a theorem about the Rust serde derives.
-/
namespace Auths.Product.NativeSerde
open RecipeSerdeGrammar
open NativeCompiler
open Aeneas Aeneas.Std

def NativeRecord : Record → Type
  | .recipe => AuthsNativeRecipe.recipe.source.RecipeSource
  | .lock => AuthsNativeRecipe.recipe.ProfileLockFile
  | .guard => AuthsNativeRecipe.recipe.source.GuardSource
  | .probe => AuthsNativeRecipe.recipe.source.ProbeSource
  | .accountRead => AuthsNativeRecipe.recipe.source.AccountReadSource
  | .deniedRead => AuthsNativeRecipe.recipe.source.DeniedReadSource
  | .accountScope => AuthsNativeRecipe.recipe.source.AccountScopeSource
  | .bounds => AuthsNativeRecipe.recipe.source.BoundsSource
  | .sumBound => AuthsNativeRecipe.recipe.source.SumBoundSource
  | .relativeCeiling => AuthsNativeRecipe.recipe.source.RelativeCeilingSource
  | .binding => AuthsNativeRecipe.recipe.source.BindSource
  | .write => AuthsNativeRecipe.recipe.source.WriteSource
  | .idempotencyLocation => AuthsNativeRecipe.recipe.source.IdempotencyLocation
  | .observation => AuthsNativeRecipe.recipe.source.ObservationSource
  | .echo => AuthsNativeRecipe.recipe.source.EchoSource
  | .preEntry => AuthsNativeRecipe.recipe.source.PreEntrySource
  | .preconditions => AuthsNativeRecipe.recipe.source.PreconditionSource

def NativeEnum : Enum → Type
  | .credential => AuthsNativeRecipe.recipe.source.CredentialSource
  | .idempotency => AuthsNativeRecipe.recipe.source.IdempotencySource
  | .path => AuthsNativeRecipe.recipe.source.PathSegment
  | .body => AuthsNativeRecipe.recipe.source.BodySource
  | .form => AuthsNativeRecipe.recipe.source.FormExpr
  | .value => AuthsNativeRecipe.recipe.source.ValueExpr
  | .echoPlacement => AuthsNativeRecipe.recipe.source.EchoPlacement

def NativeKind : Kind → Type
  | .text => String
  | .boolean => Bool
  | .signed64 => Std.I64
  | .unsigned8 => Std.U8
  | .unsigned16 => Std.U16
  | .unsigned64 => Std.U64
  | .word => Std.Usize
  | .json => NativeCompiler.Json
  | .writeMethod => AuthsNativeRecipe.recipe.WriteMethod
  | .option inner => Option (NativeKind inner)
  | .vector inner => NativeVec (NativeKind inner)
  | .map inner => SourceMap (NativeKind inner)
  | .record name => NativeRecord name
  | .internal name => NativeEnum name

structure Slot where
  kind : Kind
  value : NativeKind kind

def recordSlots (name : Record) (input : NativeRecord name) : List Slot :=
  match name, input with
  | .recipe, input => [⟨.text, input.schema⟩, ⟨.text, input.profile_schema_digest⟩,
      ⟨.text, input.service⟩, ⟨.text, input.tool⟩, ⟨.text, input.operator_namespace⟩,
      ⟨.internal .credential, input.credential⟩, ⟨.text, input.origin⟩,
      ⟨.option (.map .text), input.provider_headers⟩,
      ⟨.option (.record .accountScope), input.account_scope⟩,
      ⟨.option (.record .bounds), input.bounds⟩,
      ⟨.option (.record .relativeCeiling), input.relative_ceiling⟩,
      ⟨.record .write, input.write⟩,
      ⟨.option (.record .observation), input.observation⟩,
      ⟨.option (.record .echo), input.echo⟩,
      ⟨.option (.record .preEntry), input.pre_entry⟩,
      ⟨.option (.record .preconditions), input.preconditions⟩]
  | .lock, input => [⟨.text, input.schema⟩, ⟨.text, input.profile⟩,
      ⟨.unsigned16, input.version⟩, ⟨.text, input.service⟩, ⟨.text, input.tool⟩,
      ⟨.text, input.schema_digest⟩, ⟨.json, input.command_schema⟩, ⟨.unsigned8, input.generator_format⟩]
  | .guard, input => [⟨.vector .text, input.prefixes⟩, ⟨.option (.record .probe), input.probe⟩,
      ⟨.option (.record .accountRead), input.account⟩,
      ⟨.option (.vector (.record .deniedRead)), input.denied_reads⟩]
  | .probe, input => [⟨.vector (.internal .path), input.path⟩, ⟨.text, input.json_pointer⟩,
      ⟨.json, input.equals⟩, ⟨.unsigned64, input.maximum_response_bytes⟩]
  | .accountRead, input => [⟨.vector (.internal .path), input.path⟩, ⟨.text, input.json_pointer⟩,
      ⟨.unsigned64, input.maximum_response_bytes⟩]
  | .deniedRead, input => [⟨.text, input.method⟩, ⟨.vector (.internal .path), input.path⟩,
      ⟨.vector .unsigned64, input.refused_status⟩]
  | .accountScope, input => [⟨.text, input.header⟩, ⟨.text, input.field⟩]
  | .bounds, input => [⟨.option (.record .sumBound), input.sum⟩]
  | .sumBound, input => [⟨.text, input.argument⟩, ⟨.option .text, input.partition⟩]
  | .relativeCeiling, input => [⟨.text, input.argument⟩, ⟨.unsigned64, input.basis_points⟩,
      ⟨.vector (.internal .path), input.path⟩, ⟨.text, input.json_pointer⟩,
      ⟨.option .text, input.subtract_pointer⟩,
      ⟨.option (.vector (.record .binding)), input.bind⟩, ⟨.unsigned64, input.maximum_response_bytes⟩]
  | .binding, input => [⟨.text, input.pointer⟩, ⟨.text, input.field⟩]
  | .write, input => [⟨.writeMethod, input.method⟩, ⟨.vector (.internal .path), input.path⟩,
      ⟨.internal .body, input.body⟩, ⟨.option (.internal .idempotency), input.idempotency⟩]
  | .idempotencyLocation, input => [⟨.option .text, input.json_pointer⟩,
      ⟨.option .text, input.form_field⟩, ⟨.option .text, input.pointer⟩]
  | .observation, input => [⟨.vector (.internal .path), input.path⟩,
      ⟨.text, input.json_pointer⟩, ⟨.text, input.expected_field⟩, ⟨.word, input.maximum_response_bytes⟩]
  | .echo, input => [⟨.internal .echoPlacement, input.write⟩, ⟨.text, input.observe⟩]
  | .preEntry, input => [⟨.vector (.internal .path), input.path⟩,
      ⟨.vector .text, input.pointers⟩, ⟨.unsigned64, input.maximum_response_bytes⟩]
  | .preconditions, input => [⟨.option .text, input.read_back_subject⟩, ⟨.vector .text, input.verified⟩]

def variantIndex (name : Enum) (input : NativeEnum name) : Nat :=
  match name, input with
  | .credential, .Bearer _ => 0
  | .credential, .HeaderApiKey _ _ => 1
  | .idempotency, .DerivedHeader _ => 0
  | .idempotency, .OperationIdField _ _ => 1
  | .path, .Fixed _ => 0
  | .path, .Field _ => 1
  | .path, .ResponseField _ _ => 2
  | .path, .Echo => 3
  | .body, .Json _ => 0
  | .body, .Form _ => 1
  | .form, .String _ => 0
  | .form, .Field _ => 1
  | .form, .Json _ => 2
  | .form, .Echo => 3
  | .value, .String _ => 0
  | .value, .Integer _ => 1
  | .value, .Boolean _ => 2
  | .value, .Field _ => 3
  | .value, .Object _ => 4
  | .value, .Array _ => 5
  | .value, .Echo => 6
  | .echoPlacement, .JsonPointer _ => 0
  | .echoPlacement, .FormField _ => 1

theorem native_variant_index_bounded (name : Enum) (input : NativeEnum name) :
    variantIndex name input < (variants name).length := by
  cases name <;> cases input <;> decide

/-- Use the closed grammar declaration itself, rather than a second copied
tag/field declaration that could silently drift from numeric variant indices. -/
def nativeVariant (name : Enum) (input : NativeEnum name) : Variant :=
  (variants name)[variantIndex name input]'(native_variant_index_bounded name input)

def variantSlots (name : Enum) (input : NativeEnum name) : List Slot :=
  match name, input with
  | .credential, .Bearer guard => [⟨.option (.record .guard), guard⟩]
  | .credential, .HeaderApiKey header guard => [⟨.text, header⟩, ⟨.option (.record .guard), guard⟩]
  | .idempotency, .DerivedHeader retention => [⟨.unsigned64, retention⟩]
  | .idempotency, .OperationIdField location retention =>
      [⟨.record .idempotencyLocation, location⟩, ⟨.unsigned64, retention⟩]
  | .path, .Fixed value => [⟨.text, value⟩]
  | .path, .Field name => [⟨.text, name⟩]
  | .path, .ResponseField pointer maximum => [⟨.text, pointer⟩, ⟨.unsigned64, maximum⟩]
  | .path, .Echo => []
  | .body, .Json value => [⟨.internal .value, value⟩]
  | .body, .Form fields => [⟨.map (.internal .form), fields⟩]
  | .form, .String value => [⟨.text, value⟩]
  | .form, .Field name => [⟨.text, name⟩]
  | .form, .Json value => [⟨.internal .value, value⟩]
  | .form, .Echo => []
  | .value, .String value => [⟨.text, value⟩]
  | .value, .Integer value => [⟨.signed64, value⟩]
  | .value, .Boolean value => [⟨.boolean, value⟩]
  | .value, .Field name => [⟨.text, name⟩]
  | .value, .Object fields => [⟨.map (.internal .value), fields⟩]
  | .value, .Array items => [⟨.vector (.internal .value), items⟩]
  | .value, .Echo => []
  | .echoPlacement, .JsonPointer pointer => [⟨.text, pointer⟩]
  | .echoPlacement, .FormField name => [⟨.text, name⟩]

theorem native_record_slot_kinds_exact (name : Record) (input : NativeRecord name) :
    (recordSlots name input).map Slot.kind = (recordFields name).map SerdeFieldLayout.Field.kind := by
  cases name <;> rfl

theorem native_variant_is_declared (name : Enum) (input : NativeEnum name) :
    nativeVariant name input ∈ variants name := by
  simpa only [nativeVariant] using List.getElem_mem (native_variant_index_bounded name input)

theorem native_variant_slot_kinds_exact (name : Enum) (input : NativeEnum name) :
    (variantSlots name input).map Slot.kind =
      ((nativeVariant name input).fields.getD []).map SerdeFieldLayout.Field.kind := by
  cases name <;> cases input <;> rfl

end Auths.Product.NativeSerde
