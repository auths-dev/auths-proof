import qualification.aeneas.generated.scope_codec.Types
import qualification.aeneas.generated.codec.FunsExternal
open Aeneas Aeneas.Std Result
namespace AuthsScopeCodec
abbrev Usize.Insts.CoreConvertTryFromU64TryFromIntError.try_from := _root_.Usize.Insts.CoreConvertTryFromU64TryFromIntError.try_from
abbrev U8.Insts.CoreConvertTryFromU64TryFromIntError.try_from := _root_.U8.Insts.CoreConvertTryFromU64TryFromIntError.try_from
abbrev core.option.Option.Some := @_root_.core.option.Option.Some
abbrev core.option.Option.ok_or := @_root_.core.option.Option.ok_or
abbrev core.option.Option.Insts.CoreCmpPartialEqOption.eq := @_root_.core.option.Option.Insts.CoreCmpPartialEqOption.eq
abbrev core.result.Result.map := @_root_.core.result.Result.map
abbrev core.result.Result.map_err := @_root_.core.result.Result.map_err
abbrev core.str.converts.from_utf8 := _root_.core.str.converts.from_utf8
abbrev core.str.Str.len := _root_.core.str.Str.len
abbrev core.str.Str.is_empty := _root_.core.str.Str.is_empty
abbrev core.str.Str.as_bytes := _root_.core.str.Str.as_bytes
abbrev alloc.string.String.Insts.CoreCmpPartialEqString.eq := _root_.alloc.string.String.Insts.CoreCmpPartialEqString.eq
abbrev alloc.string.String.Insts.CoreCmpOrd.cmp := _root_.alloc.string.String.Insts.CoreCmpOrd.cmp
abbrev alloc.string.String.Insts.CoreConvertFromShared0Str.from := _root_.alloc.string.String.Insts.CoreConvertFromShared0Str.from
abbrev alloc.vec.Vec.is_empty := @_root_.alloc.vec.Vec.is_empty

def identityKey {T : Type} : core.ops.function.FnMut Unit T T := {
  FnOnceInst := { call_once := fun _ value => ok value }
  call_mut := fun _ value => ok (value, ())
}

/-- Ordinary sorting delegates to the previously reviewed stable key-sort
    model using a pure, stateless identity key. String comparison laws and
    totality are earned separately for the actual native Ord dictionary. -/
def alloc.slice.Slice.sort {T : Type} (order : core.cmp.Ord T) (values : Slice T) : Result (Slice T) :=
  _root_.alloc.slice.Slice.sort_by_key identityKey order values ()

def core.ops.range.RangeInclusive.contains {Idx U : Type}
    (_indexOrder : core.cmp.PartialOrd Idx Idx) (lowerOrder : core.cmp.PartialOrd Idx U)
    (upperOrder : core.cmp.PartialOrd U Idx) (range : core.ops.range.RangeInclusive Idx) (item : U) : Result Bool := do
  let lower ← lowerOrder.le range.start item
  if lower then upperOrder.le item range.end else ok false
abbrev core.result.Result.unwrap_or := @_root_.core.result.Result.unwrap_or
end AuthsScopeCodec
