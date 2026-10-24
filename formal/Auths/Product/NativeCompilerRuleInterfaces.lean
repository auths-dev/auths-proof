import Auths.Product.NativeCompilerRulesModel
import Auths.Product.NativeCompilerSchemaNames

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

abbrev NativeRuleMap := AuthsNativeRecipe.alloc.collections.btree.map.BTreeMap String NativeScalarSchema Global

def nativeRuleMapMeaning (input : NativeRuleMap) : List Rules.Entry :=
  input.entries.val.map (fun entry => (entry.1, nativeScalarMeaning entry.2))

def nativeRuleResult : core.result.Result NativeRuleMap AuthsNativeRecipe.recipe.GatewayRecipeError →
    Except AuthsNativeRecipe.recipe.GatewayRecipeError (List Rules.Entry)
  | .Ok rules => .ok (nativeRuleMapMeaning rules)
  | .Err error => .error error

def sourceRuleVerdict (prefix : List Rules.Entry) (fields : List FieldProjection.Field) :
    Except AuthsNativeRecipe.recipe.GatewayRecipeError (List Rules.Entry) :=
  (Rules.build prefix fields).mapError (fun _ => .InvalidProfileLock)

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

def utf8StringValue : core.result.Result String AuthsNativeRecipe.alloc.string.FromUtf8Error → Option String
  | .Ok name => some name
  | .Err _ => none

theorem native_byte_column_in_range (input : NativeVec Std.U8) : Rules.ByteRange (bytes input) := by
  intro byte member
  obtain ⟨original, _, rfl⟩ := List.mem_map.mp member
  have bounded := original.property
  scalar_tac

/-- The native foreign UTF-8 function and the independent byte model make the
same complete decision. Out-of-range natural bytes are refused in the model;
the actual U8 carrier earns that range check without an extra premise. -/
@[step] theorem native_rule_name_decode (input : NativeVec Std.U8) :
    AuthsNativeRecipe.alloc.string.String.from_utf8 input ⦃ actual =>
      utf8StringValue actual = Rules.decodeName (bytes input) ⦄ := by
  have bounded := native_byte_column_in_range input
  have sameBytes : Rules.nameBytes (bytes input) =
      Auths.Codec.StdModel.bytes (AuthsNativeRecipe.alloc.vec.Vec.deref input) := by
    simp only [Rules.nameBytes, bytes, Auths.Codec.StdModel.bytes, native_deref_contents, List.map_map]
    rfl
  unfold AuthsNativeRecipe.alloc.string.String.from_utf8
  cases decoded : String.fromUTF8? (Auths.Codec.StdModel.bytes (AuthsNativeRecipe.alloc.vec.Vec.deref input)) <;>
    simp only [decoded, spec_ok, utf8StringValue, Rules.decodeName, if_pos bounded, sameBytes]

theorem native_string_order_exact (left right : String) :
    AuthsNativeRecipe.alloc.string.String.Insts.CoreCmpOrd.cmp left right = ok (compare left right) := by
  simp only [AuthsNativeRecipe.alloc.string.String.Insts.CoreCmpOrd.cmp,
    _root_.alloc.string.String.Insts.CoreCmpOrd.cmp]

private theorem native_insert_pairs_exact {V : Type} (key : String) (value : V)
    (entries : List (String × V)) :
    AuthsNativeRecipe.NativeModel.insertPairs AuthsNativeRecipe.alloc.string.String.Insts.CoreCmpOrd key value entries =
      ok (Rules.insert key value entries) := by
  induction entries with
  | nil => rfl
  | cons first rest ih =>
      rcases first with ⟨previousKey, previousValue⟩
      unfold AuthsNativeRecipe.NativeModel.insertPairs
      rw [native_string_order_exact]
      cases comparison : compare key previousKey <;>
        simp only [comparison, bind_tc_ok, Rules.insert, ih]

/-- Ordinary concrete map insertion, with its actual replaced value and complete
resulting pair sequence. This is a standard-container contract; Auths separately
checks the replacement flag and refuses duplicates. -/
@[step] theorem native_rule_map_insert (output : NativeRuleMap) (key : String)
    (schema : NativeScalarSchema) (room : output.entries.val.length < Usize.max) :
    AuthsNativeRecipe.alloc.collections.btree.map.BTreeMap.insert core.core.clone.CloneGlobal
      AuthsNativeRecipe.alloc.string.String.Insts.CoreCmpOrd output key schema ⦃ actual =>
      actual.1 = (Rules.insert key schema output.entries.val).1 ∧
      actual.2.entries.val = (Rules.insert key schema output.entries.val).2 ⦄ := by
  unfold AuthsNativeRecipe.alloc.collections.btree.map.BTreeMap.insert
  rw [native_insert_pairs_exact]
  have bounded : (Rules.insert key schema output.entries.val).2.length ≤ Usize.max :=
    (Rules.insert_length key schema output.entries.val).trans (by omega)
  simp only [bind_tc_ok, dif_pos bounded, spec_ok]
  refine ⟨rfl, ?_⟩
  simp only [AuthsNativeRecipe.alloc.vec.Vec.ofBase, AuthsNativeRecipe.alloc.vec.Vec.val,
    auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.Vec.val,
    auths_composition.alloc.vec.SizedList.toList_ofList]

end Auths.Product.NativeCompiler.StdModel
