-- REVIEWED TRANSPARENT STANDARD-LIBRARY MODELS; NO AUTHS ALGORITHM IS OPAQUE.
import qualification.aeneas.generated.codec.Types
import qualification.aeneas.generated.model.FunsExternal
open Aeneas Aeneas.Std Result
set_option linter.unusedVariables false

-- UTF-8 error payload is unobserved; all failures map to Malformed.
def Auths.Codec.StdModel.bytes (bytes : Str) : ByteArray :=
  (bytes.val.map (fun byte => UInt8.ofNat byte.val)).toByteArray

def Usize.Insts.CoreConvertTryFromU64TryFromIntError.try_from (value : Std.U64) :=
  core.num.tryFromUScalar .Usize value

def U64.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from (value : Std.Usize) :=
  core.num.tryFromUScalar .U64 value

def U8.Insts.CoreConvertTryFromU64TryFromIntError.try_from (value : Std.U64) :=
  core.num.tryFromUScalar .U8 value

def U16.Insts.CoreConvertTryFromU64TryFromIntError.try_from (value : Std.U64) :=
  core.num.tryFromUScalar .U16 value

def core.option.Option.Some {T : Type} (value : T) : Result (Option T) := ok (some value)
def core.option.Option.as_ref {T : Type} (value : Option T) : Result (Option T) := ok value

def core.option.Option.ok_or {T E : Type} (value : Option T) (error : E) :
    Result (core.result.Result T E) :=
  ok (match value with | some x => .Ok x | none => .Err error)

def core.option.Option.Insts.CoreCmpPartialEqOption.eq {T : Type}
    (eqInst : core.cmp.PartialEq T T) (left right : Option T) : Result Bool :=
  match left, right with
  | none, none => ok true
  | some left, some right => eqInst.eq left right
  | _, _ => ok false

def core.result.Result.map {T E U F : Type}
    (function : core.ops.function.FnOnce F T U)
    (value : core.result.Result T E) (callback : F) : Result (core.result.Result U E) := do
  match value with
  | .Ok value =>
    let output ← function.call_once callback value
    ok (.Ok output)
  | .Err error => ok (.Err error)

def core.result.Result.map_err {T E F O : Type}
    (function : core.ops.function.FnOnce O E F)
    (value : core.result.Result T E) (callback : O) : Result (core.result.Result T F) := do
  match value with
  | .Ok value => ok (.Ok value)
  | .Err error =>
    let output ← function.call_once callback error
    ok (.Err output)

def core.result.Result.unwrap_or {T E : Type} (value : core.result.Result T E) (fallback : T) :
    Result T := ok (match value with | .Ok value => value | .Err _ => fallback)

def core.str.converts.from_utf8 (bytes : Slice Std.U8) :
    Result (core.result.Result Str core.str.error.Utf8Error) :=
  ok (if (Auths.Codec.StdModel.bytes bytes).IsValidUTF8 then .Ok bytes else .Err ())

def alloc.string.String.Insts.CoreOpsDerefDerefStr.deref (value : String) : Result Str :=
  if bounded : value.toByteArray.size ≤ U32.max then ok (toStr value bounded) else fail .panic

def alloc.string.String.Insts.CoreConvertFromShared0Str.from (value : Str) : Result String :=
  match String.fromUTF8? (Auths.Codec.StdModel.bytes value) with
  | some value => ok value
  | none => fail .panic

def alloc.vec.Vec.as_slice {T : Type} (A : Type) (value : alloc.vec.Vec T) : Result (Slice T) :=
  ok (alloc.vec.Vec.deref value)

def alloc.vec.Vec.is_empty {T : Type} (A : Type) (value : alloc.vec.Vec T) : Result Bool :=
  ok value.val.isEmpty

-- The sole extracted call uses a stateless Unit closure for the digest key.
-- This sorting model is sound only after proving purity and total-order laws
-- for that concrete callback; it is not an arbitrary FnMut Rust algorithm model.
private def insertKey {T K F : Type} (key : core.ops.function.FnMut F T K)
    (order : core.cmp.Ord K) (callback : F) (item : T) :
    (items : List T) → Result {output : List T // output.length = items.length + 1}
  | [] => ok ⟨[item], rfl⟩
  | first :: rest => do
    let (left, _) ← key.call_mut callback item
    let (right, _) ← key.call_mut callback first
    let comparison ← order.cmp left right
    if comparison = .gt then
      let inserted ← insertKey key order callback item rest
      ok ⟨first :: inserted.val, by simp [inserted.property]⟩
    else ok ⟨item :: first :: rest, rfl⟩

private def sortKey {T K F : Type} (key : core.ops.function.FnMut F T K)
    (order : core.cmp.Ord K) (callback : F) :
    (items : List T) → Result {output : List T // output.length = items.length}
  | [] => ok ⟨[], rfl⟩
  | first :: rest => do
    let sorted ← sortKey key order callback rest
    let inserted ← insertKey key order callback first sorted.val
    ok ⟨inserted.val, by simp [inserted.property, sorted.property]⟩

def alloc.slice.Slice.sort_by_key {T K F : Type}
    (key : core.ops.function.FnMut F T K) (order : core.cmp.Ord K)
    (input : Slice T) (callback : F) : Result (Slice T) := do
  let output ← sortKey key order callback input.val
  ok ⟨output.val, by rw [output.property]; exact input.property⟩
