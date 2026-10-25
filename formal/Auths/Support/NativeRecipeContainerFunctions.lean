import Auths.Support.NativeRecipeCoreFunctions

/-!
Borrowed BTreeMap/BTreeSet lookup and ordered set insertion for the actual
constructor ABI. The representation contract requires lawful, stateless native
ordering and Borrow agreement. Lookups retain original complete payloads;
equal-key insertion retains the existing key. This is a standard-library model,
not an Auths field/schema/consumption decision. No native model is qualified
until the final source/model/inventory review and elaboration pass.
-/
open Aeneas Aeneas.Std Result

namespace AuthsNativeRecipe.NativeModel

def lookupBorrowed {K V Q : Type} (borrow : core.borrow.Borrow K Q)
    (order : core.cmp.Ord Q) (query : Q) : List (K × V) → Result (Option V)
  | [] => ok none
  | (key, value) :: rest => do
      let original ← borrow.borrow key
      let comparison ← order.cmp query original
      if comparison = .eq then ok (some value) else lookupBorrowed borrow order query rest

def containsBorrowed {T Q : Type} (borrow : core.borrow.Borrow T Q)
    (order : core.cmp.Ord Q) (query : Q) : List T → Result Bool
  | [] => ok false
  | value :: rest => do
      let original ← borrow.borrow value
      let comparison ← order.cmp query original
      if comparison = .eq then ok true else containsBorrowed borrow order query rest

def insertElement {T : Type} (order : core.cmp.Ord T) (value : T) :
    List T → Result (Bool × List T)
  | [] => ok (true, [value])
  | first :: rest => do
      let comparison ← order.cmp value first
      match comparison with
      | .lt => ok (true, value :: first :: rest)
      | .eq => ok (false, first :: rest)
      | .gt =>
          let (inserted, tail) ← insertElement order value rest
          ok (inserted, first :: tail)

end AuthsNativeRecipe.NativeModel

namespace AuthsNativeRecipe.alloc.collections.btree.map

def BTreeMap.get {K V A Q : Type} (_allocator : core.clone.Clone A)
    (borrow : core.borrow.Borrow K Q) (_keyOrder : core.cmp.Ord K)
    (queryOrder : core.cmp.Ord Q) (input : BTreeMap K V A) (query : Q) : Result (Option V) :=
  NativeModel.lookupBorrowed borrow queryOrder query input.entries.val

def BTreeMap.contains_key {K V A Q : Type} (allocator : core.clone.Clone A)
    (borrow : core.borrow.Borrow K Q) (keyOrder : core.cmp.Ord K)
    (queryOrder : core.cmp.Ord Q) (input : BTreeMap K V A) (query : Q) : Result Bool := do
  let selected ← BTreeMap.get allocator borrow keyOrder queryOrder input query
  ok selected.isSome

def BTreeMap.len {K V A : Type} (_allocator : core.clone.Clone A) (input : BTreeMap K V A) : Result Std.Usize :=
  ok (UScalar.ofNatCore input.entries.val.length (by have bound := input.entries.property; scalar_tac))

def BTreeMap.is_empty {K V A : Type} (_allocator : core.clone.Clone A) (input : BTreeMap K V A) : Result Bool :=
  ok input.entries.val.isEmpty

end AuthsNativeRecipe.alloc.collections.btree.map

namespace AuthsNativeRecipe.alloc.collections.btree.set

def BTreeSet.contains {T A Q : Type} (_allocator : core.clone.Clone A)
    (borrow : core.borrow.Borrow T Q) (_valueOrder : core.cmp.Ord T)
    (queryOrder : core.cmp.Ord Q) (input : BTreeSet T A) (query : Q) : Result Bool :=
  NativeModel.containsBorrowed borrow queryOrder query input.elements.val

def BTreeSet.insert {T A : Type} (_allocator : core.clone.Clone A)
    (order : core.cmp.Ord T) (input : BTreeSet T A) (value : T) : Result (Bool × BTreeSet T A) := do
  let (inserted, entries) ← NativeModel.insertElement order value input.elements.val
  if bound : entries.length ≤ Usize.max then
    ok (inserted, ⟨alloc.vec.Vec.ofBase ⟨entries, bound⟩⟩)
  else fail .panic

def BTreeSetTGlobal.Insts.CoreDefaultDefault.default (T : Type) : Result (BTreeSet T Global) :=
  ok ⟨alloc.vec.Vec.new T⟩

end AuthsNativeRecipe.alloc.collections.btree.set
