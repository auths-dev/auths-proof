import Aeneas

open Aeneas Aeneas.Std Result

namespace Auths.Codec.CompareSortModel

/- Candidate standard stable comparison-sort interface. Its admitted domain
is a total, stateless comparison callback inducing a lawful weak order. This
does not specify the behaviour of arbitrary stateful Rust FnMut callbacks.
Concrete source callers must earn those leaf contracts; the fresh extracted
ABI and foreign-model inventory review remain mandatory. No Auths comparator,
constructor or normalizer is replaced by this standard-library model. -/

def insert {T F : Type} (comparison : core.ops.function.FnMut F (T × T) Ordering)
    (callback : F) (item : T) :
    (items : List T) → Result {output : List T // output.length = items.length + 1}
  | [] => ok ⟨[item], rfl⟩
  | first :: rest => do
    let (ordering, _) ← comparison.call_mut callback (item, first)
    if ordering = .gt then
      let inserted ← insert comparison callback item rest
      ok ⟨first :: inserted.val, by simp [inserted.property]⟩
    else ok ⟨item :: first :: rest, rfl⟩

def sort {T F : Type} (comparison : core.ops.function.FnMut F (T × T) Ordering)
    (callback : F) :
    (items : List T) → Result {output : List T // output.length = items.length}
  | [] => ok ⟨[], rfl⟩
  | first :: rest => do
    let sorted ← sort comparison callback rest
    let inserted ← insert comparison callback first sorted.val
    ok ⟨inserted.val, by simp [inserted.property, sorted.property]⟩

end Auths.Codec.CompareSortModel

namespace AuthsProtocolCodec

def alloc.slice.Slice.sort_by {T F : Type}
    (comparison : core.ops.function.FnMut F (T × T) Ordering)
    (values : Slice T) (callback : F) : Result (Slice T) := do
  let output ← Auths.Codec.CompareSortModel.sort comparison callback values.val
  ok ⟨output.val, by rw [output.property]; exact values.property⟩

end AuthsProtocolCodec
