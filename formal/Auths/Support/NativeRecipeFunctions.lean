import qualification.aeneas.generated.native_recipe.Types
import qualification.aeneas.generated.codec.FunsExternal

/-!
Concrete foreign functions for the inspected native compiler ABI. This selected
footprint uses the Global allocator and ordinary String order. JSON maps retain
the actual preserve_order insertion sequence; native BTreeMaps insert in key
order and retain an existing equal key. These are standard-container/JSON-kind
contracts, never replacements for Auths validation or request compilation.
All bodies still require the final elaboration/model-review/qualification pass.
-/
open Aeneas Aeneas.Std Result

namespace AuthsNativeRecipe

abbrev core.option.Option.as_ref := @_root_.core.option.Option.as_ref

def core.option.Option.as_deref {T Target : Type}
    (deref : core.ops.deref.Deref T Target) (input : Option T) : Result (Option Target) := do
  match input with
  | none => ok none
  | some value =>
      let borrowed ← deref.deref value
      ok (some borrowed)

def core.option.Option.Insts.CoreCloneClone.clone {T : Type}
    (clone : core.clone.Clone T) (input : Option T) : Result (Option T) := do
  match input with
  | none => ok none
  | some value =>
      let copied ← clone.clone value
      ok (some copied)

abbrev core.result.Result.map_err := @_root_.core.result.Result.map_err
abbrev core.str.Str.as_bytes := _root_.core.str.Str.as_bytes

namespace NativeModel

def textBytes (text : String) : List Std.U8 :=
  text.toByteArray.toList.map fun byte =>
    UScalar.ofNatCore byte.toNat (by have bound := UInt8.toNat_lt byte; scalar_tac)

def insertPairs {K V : Type} (order : core.cmp.Ord K) (key : K) (value : V) :
    List (K × V) → Result (Option V × List (K × V))
  | [] => ok (none, [(key, value)])
  | (existing, previous) :: rest => do
      let comparison ← order.cmp key existing
      match comparison with
      | .lt => ok (none, (key, value) :: (existing, previous) :: rest)
      | .eq => ok (some previous, (existing, value) :: rest)
      | .gt =>
          let (replaced, updated) ← insertPairs order key value rest
          ok (replaced, (existing, previous) :: updated)

/-- Immutable borrowing iteration returns one complete original pair and its
suffix; it neither selects a known key nor changes the relative order. -/
def nextPair {K V : Type} (iterator : alloc.collections.btree.map.Iter K V) :
    Result (Option (K × V) × alloc.collections.btree.map.Iter K V) := by
  cases iterator with
  | mk size entries bound =>
    cases entries with
    | nil => exact ok (none, ⟨0, .nil, by omega⟩)
    | @cons count first rest =>
        exact ok (some first, ⟨count, rest, by omega⟩)

end NativeModel

namespace alloc.collections.btree.map

def BTreeMapKVGlobal.new (K V : Type) : Result (BTreeMap K V Global) :=
  ok ⟨alloc.vec.Vec.new (K × V)⟩

def BTreeMap.insert {K V A : Type} (_allocator : core.clone.Clone A)
    (order : core.cmp.Ord K) (map : BTreeMap K V A) (key : K) (value : V) :
    Result (Option V × BTreeMap K V A) := do
  let (previous, entries) ← NativeModel.insertPairs order key value map.entries.val
  if bound : entries.length ≤ Usize.max then
    ok (previous, ⟨alloc.vec.Vec.ofBase ⟨entries, bound⟩⟩)
  else fail .panic

def Iter.Insts.CoreIterTraitsIteratorIteratorPairSharedAKSharedAV.next {K V : Type} :=
  @NativeModel.nextPair K V

end alloc.collections.btree.map

def SharedABTreeMap.Insts.CoreIterTraitsCollectIntoIteratorPairSharedAKSharedAVIter.into_iter
    {K V A : Type} (_allocator : core.clone.Clone A)
    (map : alloc.collections.btree.map.BTreeMap K V A) :
    Result (alloc.collections.btree.map.Iter K V) := ok map.entries

abbrev alloc.string.String.Insts.CoreCmpPartialEqString.eq :=
  _root_.alloc.string.String.Insts.CoreCmpPartialEqString.eq
abbrev alloc.string.String.Insts.CoreCmpOrd.cmp :=
  _root_.alloc.string.String.Insts.CoreCmpOrd.cmp

def alloc.string.String.Insts.CoreCmpPartialOrdString.partial_cmp (left right : String) :
    Result (Option Ordering) := do
  let comparison ← alloc.string.String.Insts.CoreCmpOrd.cmp left right
  ok (some comparison)

def alloc.string.String.from_utf8 (bytes : alloc.vec.Vec Std.U8) :
    Result (core.result.Result String alloc.string.FromUtf8Error) :=
  match _root_.String.fromUTF8? (Auths.Codec.StdModel.bytes (alloc.vec.Vec.deref bytes)) with
  | some text => ok (.Ok text)
  | none => ok (.Err ⟨bytes, ()⟩)

def alloc.string.String.as_bytes (text : String) : Result (Slice Std.U8) :=
  let bytes := NativeModel.textBytes text
  if bound : bytes.length ≤ Usize.max then ok ⟨bytes, bound⟩ else fail .panic

def alloc.string.String.Insts.CoreCmpPartialEqShared0Str.eq (left : String) (right : Str) :
    Result Bool := ok (decide (NativeModel.textBytes left = right.val))

/-- Native String borrowing has the native usize representation domain.
The protocol codec's separate U32 wire-length restriction is not a String API
restriction and must not leak into the compiler's ordinary foreign model. -/
def alloc.string.String.Insts.CoreOpsDerefDerefStr.deref (text : String) : Result Str :=
  alloc.string.String.as_bytes text

def alloc.vec.Vec.as_slice {T : Type} (_allocator : Type) (input : alloc.vec.Vec T) :
    Result (Slice T) := ok (alloc.vec.Vec.deref input)

def alloc.vec.Vec.is_empty {T : Type} (_allocator : Type) (input : alloc.vec.Vec T) :
    Result Bool := ok input.val.isEmpty

def serde_json.map.Iter.Insts.CoreIterTraitsIteratorIteratorPairSharedAStringSharedAValue.next
    (iterator : serde_json.map.Iter) :
    Result (Option (String × serde_json.value.Value) × serde_json.map.Iter) :=
  NativeModel.nextPair iterator

def SharedAMapStringValue.Insts.CoreIterTraitsCollectIntoIteratorPairSharedAStringSharedAValueIter.into_iter
    (map : serde_json.map.Map String serde_json.value.Value) : Result serde_json.map.Iter :=
  ok map.entries

def serde_json.number.Number.as_i64 (number : serde_json.number.Number) :
    Result (Option Std.I64) :=
  match number with
  | .PosInt value =>
      if bounded : value.val ≤ 9223372036854775807 then
        ok (some ⟨Int.ofNat value.val, by scalar_tac⟩)
      else ok none
  | .NegInt value => ok (some value)
  | .Float _ => ok none

def serde_json.number.Number.as_u64 (number : serde_json.number.Number) :
    Result (Option Std.U64) :=
  match number with
  | .PosInt value => ok (some value)
  | .NegInt _ | .Float _ => ok none

end AuthsNativeRecipe
