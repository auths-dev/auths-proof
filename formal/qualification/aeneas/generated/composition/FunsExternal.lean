-- REVIEWED: exact standard-container links and the pinned Rust Ord::max rule.
-- Ordered-set models are scoped to Global + copied ProofRef values and their
-- proved lawful order. They model set behavior, not Rust allocation or tree cost.
import qualification.aeneas.generated.composition.Types
import qualification.aeneas.generated.codec.FunsExternal
open Aeneas Aeneas.Std Result

namespace auths_composition.alloc.vec

def Vec.with_capacity (T : Type) (capacity : Std.Usize) : Vec T :=
  Vec.ofBase (Aeneas.Std.alloc.vec.Vec.with_capacity T capacity)

def Vec.len {T : Type} (value : Vec T) : Std.Usize :=
  Aeneas.Std.alloc.vec.Vec.len value.toBase

def Vec.push {T : Type} (value : Vec T) (element : T) : Result (Vec T) := do
  let updated ← Aeneas.Std.alloc.vec.Vec.push value.toBase element
  ok (Vec.ofBase updated)

def Vec.is_empty {T : Type} (_A : Type) (value : Vec T) : Result Bool :=
  ok value.elements.toList.isEmpty

end auths_composition.alloc.vec

@[trait_default] def auths_composition.core.cmp.Ord.max.default {T : Type}
    (order : Aeneas.Std.core.cmp.Ord T) (left right : T) : Result T := do
  let greater ← order.partialOrdInst.lt right left
  if greater then ok left else ok right

def core.option.Option.Insts.CoreDefaultDefault.default (T : Type) : Result (Option T) := ok none

namespace alloc.collections.btree.set

def insertValues {T : Type} (order : core.cmp.Ord T) (value : T) :
    List T → Result (Bool × List T)
  | [] => ok (true, [value])
  | head :: tail => do
      let comparison ← order.cmp value head
      match comparison with
      | .lt => ok (true, value :: head :: tail)
      | .eq => ok (false, head :: tail)
      | .gt =>
          let (added, remaining) ← insertValues order value tail
          ok (added, head :: remaining)

def BTreeSetTGlobal.new (T : Type) : Result (BTreeSet T Global) :=
  ok ⟨[], by simp⟩

def BTreeSet.insert {T A : Type} (_allocator : core.clone.Clone A) (order : core.cmp.Ord T)
    (state : BTreeSet T A) (value : T) : Result (Bool × BTreeSet T A) := do
  let (added, values) ← insertValues order value state.values
  (if bound : values.length ≤ Usize.max then
    ok (added, ⟨values, bound⟩)
  else
    fail .maximumSizeExceeded)

def BTreeSet.len {T A : Type} (_allocator : core.clone.Clone A)
    (state : BTreeSet T A) : Result Std.Usize :=
  ok (Usize.ofNatCore state.values.length (by have bound := state.bound; scalar_tac))

def BTreeSet.Insts.CoreIterTraitsCollectIntoIteratorTIntoIter.into_iter
    {T A : Type} (_allocator : core.clone.Clone A) (state : BTreeSet T A) :
    Result (IntoIter T A) := ok ⟨state.values, state.bound⟩

def IntoIter.Insts.CoreIterTraitsIteratorIterator.next
    {T A : Type} (_allocator : core.clone.Clone A) (state : IntoIter T A) :
    Result (Option T × IntoIter T A) :=
  match same : state.values with
  | [] => ok (none, state)
  | head :: tail => ok (some head, ⟨tail, by have bound := state.bound; rw [same] at bound; simp only [List.length_cons] at bound; omega⟩)

end alloc.collections.btree.set
