import Auths.Support.NativeRecipeFunctions

/-!
Concrete ordinary interfaces from the successful seventeen-root constructor
ABI. These execute supplied callbacks only on the matching Option/Result arm,
preserve original byte slices, and retain inclusive-range exhaustion semantics.
They supply no Auths validation or authority decision. Final elaboration and
exact foreign-model inventory review remain required.
-/
open Aeneas Aeneas.Std Result

namespace AuthsNativeRecipe

def core.borrow.Borrow.Blanket.borrow {T : Type} (value : T) : Result T := ok value

def Shared0T.Insts.CoreConvertAsRef.as_ref {T U : Type}
    (reference : core.convert.AsRef T U) (value : T) : Result U := reference.as_ref value

def Slice.Insts.CoreConvertAsRefSlice.as_ref {T : Type} (value : Slice T) : Result (Slice T) := ok value

def core.num.I64.unsigned_abs (value : Std.I64) : Result Std.U64 :=
  ok (UScalar.ofNatCore value.val.natAbs (by
    have signed : -9223372036854775808 ≤ value.val ∧ value.val ≤ 9223372036854775807 := by scalar_tac
    have magnitude : (value.val.natAbs : Int) ≤ 9223372036854775808 := by
      rw [Int.natCast_natAbs]
      exact abs_le.mpr ⟨by omega, by omega⟩
    scalar_tac))

def core.ops.range.RangeInclusive.contains {Idx U : Type}
    (_sameOrder : core.cmp.PartialOrd Idx Idx)
    (lowerOrder : core.cmp.PartialOrd Idx U) (upperOrder : core.cmp.PartialOrd U Idx)
    (range : core.ops.range.RangeInclusive Idx) (value : U) : Result Bool := do
  let lower ← lowerOrder.le range.start value
  if !lower then ok false
  else if range.exhausted then upperOrder.lt value range.end
  else upperOrder.le value range.end

def core.option.Option.is_some_and {T F : Type}
    (callback : core.ops.function.FnOnce F T Bool) (value : Option T) (closure : F) : Result Bool :=
  match value with
  | none => ok false
  | some input => callback.call_once closure input

def core.option.Option.map {T U F : Type} (callback : core.ops.function.FnOnce F T U)
    (value : Option T) (closure : F) : Result (Option U) := do
  match value with
  | none => ok none
  | some input => ok (some (← callback.call_once closure input))

def core.option.Option.ok_or {T E : Type} (value : Option T) (error : E) : Result (core.result.Result T E) :=
  ok (match value with | none => .Err error | some input => .Ok input)

def core.option.Option.or_else {T F : Type} (callback : core.ops.function.FnOnce F Unit (Option T))
    (value : Option T) (closure : F) : Result (Option T) :=
  match value with
  | none => callback.call_once closure ()
  | some input => ok (some input)

def core.option.Option.Insts.CoreCmpPartialEqOption.eq {T : Type}
    (equality : core.cmp.PartialEq T T) (left right : Option T) : Result Bool :=
  match left, right with
  | none, none => ok true
  | some first, some second => equality.eq first second
  | _, _ => ok false

def core.option.Option.Insts.CoreOpsTry_traitTry.branch {T : Type} (value : Option T) :
    Result (core.ops.control_flow.ControlFlow (Option core.convert.Infallible) T) :=
  ok (match value with | none => .Break none | some input => .Continue input)

def core.option.Option.Insts.CoreOpsTry_traitFromResidualOptionInfallible.from_residual
    (T : Type) (residual : Option core.convert.Infallible) : Result (Option T) :=
  match residual with
  | none => ok none
  | some impossible => nomatch impossible

def core.result.Result.map {T E U F : Type} (callback : core.ops.function.FnOnce F T U)
    (value : core.result.Result T E) (closure : F) : Result (core.result.Result U E) := do
  match value with
  | .Err error => ok (.Err error)
  | .Ok input => ok (.Ok (← callback.call_once closure input))

namespace NativeModel

def equalLists {T : Type} (equality : core.cmp.PartialEq T T) : List T → List T → Result Bool
  | [], [] => ok true
  | first :: rest, second :: tail => do
      let same ← equality.eq first second
      if same then equalLists equality rest tail else ok false
  | _, _ => ok false

def byteOrdering (left right : List Std.U8) : Ordering :=
  compare (left.map (·.val)) (right.map (·.val))

end NativeModel

def core.slice.Slice.first {T : Type} (input : Slice T) : Result (Option T) := ok input.val.head?

def core.slice.Slice.starts_with {T : Type} (equality : core.cmp.PartialEq T T)
    (input prefix : Slice T) : Result Bool :=
  if input.val.length < prefix.val.length then ok false
  else NativeModel.equalLists equality (input.val.take prefix.val.length) prefix.val

def core.slice.Slice.ends_with {T : Type} (equality : core.cmp.PartialEq T T)
    (input suffix : Slice T) : Result Bool :=
  if input.val.length < suffix.val.length then ok false
  else NativeModel.equalLists equality (input.val.drop (input.val.length - suffix.val.length)) suffix.val

def core.str.converts.from_utf8 (input : Slice Std.U8) :
    Result (core.result.Result Str core.str.error.Utf8Error) :=
  match _root_.String.fromUTF8? (Auths.Codec.StdModel.bytes input) with
  | some _ => ok (.Ok input)
  | none => ok (.Err ())

def core.str.Str.len (input : Str) : Result Std.Usize :=
  ok (UScalar.ofNatCore input.val.length (by have bound := input.property; scalar_tac))

def core.str.Str.get {I Output : Type} (index : core.slice.index.SliceIndex I Str Output)
    (input : Str) (range : I) : Result (Option Output) := index.get range input

def Str.Insts.CoreCmpPartialOrdStr.partial_cmp (left right : Str) : Result (Option Ordering) :=
  ok (some (NativeModel.byteOrdering left.val right.val))

def Str.Insts.CoreCmpPartialEqStr.eq (left right : Str) : Result Bool := ok (decide (left.val = right.val))

def Str.Insts.CoreCmpOrd.cmp (left right : Str) : Result Ordering :=
  ok (NativeModel.byteOrdering left.val right.val)

def alloc.string.String.Insts.CoreBorrowBorrowStr.borrow (input : String) : Result Str :=
  alloc.string.String.as_bytes input

def Str.Insts.AllocBorrowToOwnedString.to_owned (input : Str) : Result String :=
  match _root_.String.fromUTF8? (Auths.Codec.StdModel.bytes input) with
  | some text => ok text
  | none => fail .undef

def alloc.string.String.len (input : String) : Result Std.Usize :=
  if fits : input.toByteArray.size ≤ Usize.max then
    ok (UScalar.ofNatCore input.toByteArray.size (by scalar_tac))
  else fail .panic

def alloc.string.String.is_empty (input : String) : Result Bool := ok input.toByteArray.isEmpty

def alloc.string.String.Insts.CoreCloneClone.clone (input : String) : Result String := ok input

def SharedAVec.Insts.CoreIterTraitsCollectIntoIteratorSharedATIter.into_iter {T : Type}
    (_allocator : Type) (input : alloc.vec.Vec T) : Result (core.slice.iter.Iter T) :=
  ok ⟨alloc.vec.Vec.deref input, 0⟩

end AuthsNativeRecipe
