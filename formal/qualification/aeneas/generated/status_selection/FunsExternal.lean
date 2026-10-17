import qualification.aeneas.generated.status_selection.Types
import qualification.aeneas.generated.model.FunsExternal
open Aeneas Aeneas.Std Result
namespace AuthsStatusSelection

@[trait_default]
def core.cmp.PartialOrd.lt.default {Self Rhs : Type}
    (implementation : Aeneas.Std.core.cmp.PartialOrd Self Rhs)
    (left : Self) (right : Rhs) : Result Bool :=
  Aeneas.Std.core.cmp.PartialOrd.lt.default implementation.partial_cmp left right
@[trait_default]
def core.cmp.PartialOrd.gt.default {Self Rhs : Type}
    (implementation : Aeneas.Std.core.cmp.PartialOrd Self Rhs)
    (left : Self) (right : Rhs) : Result Bool :=
  Aeneas.Std.core.cmp.PartialOrd.gt.default implementation.partial_cmp left right
@[trait_default]
def core.cmp.Ord.max.default {Self : Type}
    (implementation : Aeneas.Std.core.cmp.Ord Self) (left right : Self) : Result Self :=
  Aeneas.Std.core.cmp.Ord.max.default implementation.partialOrdInst.lt left right
abbrev alloc.string.String.Insts.CoreCmpPartialEqString.eq :=
  _root_.alloc.string.String.Insts.CoreCmpPartialEqString.eq
abbrev alloc.string.String.Insts.CoreCmpOrd.cmp :=
  _root_.alloc.string.String.Insts.CoreCmpOrd.cmp

/-- Reviewed standard-library boundary: pinned Rust binary_search_by's exact
    size/base transition and final comparison, including unsorted inputs.
    Fuel is initial length + 1; exhausted/invalid indexing refuses explicitly.
    This is not an Auths algorithm or an assumption of whitelist membership. -/
def binarySearchLoop {T : Type} (order : Aeneas.Std.core.cmp.Ord T)
    (values : List T) (target : T) : Nat → Nat → Nat → Result (core.result.Result Nat Nat)
  | 0, _, _ => fail .panic
  | fuel + 1, base, size => do
    if size > 1 then
      let half := size / 2
      let mid := base + half
      match values[mid]? with
      | none => fail .panic
      | some value =>
        let comparison ← order.cmp value target
        binarySearchLoop order values target fuel
          (if comparison = .gt then base else mid) (size - half)
    else
      match values[base]? with
      | none => fail .panic
      | some value =>
        let comparison ← order.cmp value target
        if comparison = .eq then ok (.Ok base)
        else ok (.Err (base + if comparison = .lt then 1 else 0))

def core.slice.Slice.binary_search {T : Type} (order : Aeneas.Std.core.cmp.Ord T)
    (values : Slice T) (target : T) : Result (core.result.Result Std.Usize Std.Usize) := do
  if values.val.isEmpty then ok (.Err 0#usize)
  else
    let result ← binarySearchLoop order values.val target (values.val.length + 1) 0 values.val.length
    match result with
    | .Ok index =>
      let result ← UScalar.tryMk .Usize index
      ok (.Ok result)
    | .Err index =>
      let result ← UScalar.tryMk .Usize index
      ok (.Err result)
theorem lt_default_delegates {Self Rhs : Type}
    (implementation : Aeneas.Std.core.cmp.PartialOrd Self Rhs) (left : Self) (right : Rhs) :
    core.cmp.PartialOrd.lt.default implementation left right =
      Aeneas.Std.core.cmp.PartialOrd.lt.default implementation.partial_cmp left right := rfl

theorem gt_default_delegates {Self Rhs : Type}
    (implementation : Aeneas.Std.core.cmp.PartialOrd Self Rhs) (left : Self) (right : Rhs) :
    core.cmp.PartialOrd.gt.default implementation left right =
      Aeneas.Std.core.cmp.PartialOrd.gt.default implementation.partial_cmp left right := rfl

theorem max_default_delegates {Self : Type}
    (implementation : Aeneas.Std.core.cmp.Ord Self) (left right : Self) :
    core.cmp.Ord.max.default implementation left right =
      Aeneas.Std.core.cmp.Ord.max.default implementation.partialOrdInst.lt left right := rfl
end AuthsStatusSelection
