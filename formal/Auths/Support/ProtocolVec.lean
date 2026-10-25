import Auths.Support.PositiveVec

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

/- The full protocol contains recursive plans inside bounded vectors. Reuse
the existing proved positive carrier isomorphism. Every operation below is a
transparent standard-container adapter; no Auths decoder/constructor is replaced.
Allocation and lawful concrete comparison contracts remain explicit. -/
namespace AuthsProtocolCodec.alloc.vec

abbrev SizedList := auths_composition.alloc.vec.SizedList
abbrev Vec := auths_composition.alloc.vec.Vec
abbrev Vec.toBase := @auths_composition.alloc.vec.Vec.toBase
abbrev Vec.ofBase := @auths_composition.alloc.vec.Vec.ofBase
abbrev Vec.deref := @auths_composition.alloc.vec.Vec.deref

abbrev Vec.val := @auths_composition.alloc.vec.Vec.val
abbrev Vec.property := @auths_composition.alloc.vec.Vec.property

def Vec.new (T : Type) : Vec T := Vec.ofBase (Aeneas.Std.alloc.vec.Vec.new T)
def Vec.with_capacity (T : Type) (capacity : Std.Usize) : Vec T :=
  Vec.ofBase (Aeneas.Std.alloc.vec.Vec.with_capacity T capacity)
def Vec.len {T : Type} (value : Vec T) : Std.Usize :=
  Aeneas.Std.alloc.vec.Vec.len value.toBase
def Vec.as_slice {T : Type} (_A : Type) (value : Vec T) : Result (Slice T) := ok (Vec.deref value)
def Vec.is_empty {T : Type} (_A : Type) (value : Vec T) : Result Bool := ok value.val.isEmpty

def Vec.push {T : Type} (value : Vec T) (element : T) : Result (Vec T) := do
  let next ← Aeneas.Std.alloc.vec.Vec.push value.toBase element
  ok (Vec.ofBase next)

-- Candidate concrete standard pop model for the positive carrier. Its actual
-- extracted ABI and foreign-model inventory entry must be reviewed with the
-- fresh protocol translation. This is a standard-container operation, not an
-- opaque replacement for any Auths normalization loop.
def Vec.pop_prefix {T : Type} (value : Vec T) : Vec T :=
  Vec.ofBase ⟨value.val.dropLast, by
    have bound := value.property
    simp only [List.length_dropLast]
    omega⟩

def Vec.pop {T : Type} (value : Vec T) : Result (Option T × Vec T) :=
  ok (value.val.getLast?, Vec.pop_prefix value)
def Vec.insert {T : Type} (value : Vec T) (index : Std.Usize) (element : T) : Result (Vec T) := do
  let next ← Aeneas.Std.alloc.vec.Vec.insert value.toBase index element
  ok (Vec.ofBase next)
def Vec.update {T : Type} (value : Vec T) (index : Std.Usize) (element : T) : Result (Vec T) := do
  let next ← Aeneas.Std.alloc.vec.Vec.update value.toBase index element
  ok (Vec.ofBase next)
def Vec.index_usize {T : Type} (value : Vec T) (index : Std.Usize) : Result T :=
  Aeneas.Std.alloc.vec.Vec.index_usize value.toBase index

def Vec.deref_mut {T : Type} (value : Vec T) : Slice T × (Slice T → Vec T) :=
  let result := Aeneas.Std.alloc.vec.Vec.deref_mut value.toBase
  (result.1, fun updated => Vec.ofBase (result.2 updated))

def Vec.index {T I Output : Type} (indexer : core.slice.index.SliceIndex I (Slice T) Output)
    (value : Vec T) (index : I) : Result Output :=
  Aeneas.Std.alloc.vec.Vec.index indexer value.toBase index

def Vec.index_mut {T I Output : Type} (indexer : core.slice.index.SliceIndex I (Slice T) Output)
    (value : Vec T) (index : I) : Result (Output × (Output → Vec T)) := do
  let result ← Aeneas.Std.alloc.vec.Vec.index_mut indexer value.toBase index
  ok (result.1, fun updated => Vec.ofBase (result.2 updated))

def Vec.Index {T I Output : Type} (indexer : core.slice.index.SliceIndex I (Slice T) Output) :
    core.ops.index.Index (Vec T) I Output := { index := Vec.index indexer }

def Vec.IndexMut {T I Output : Type} (indexer : core.slice.index.SliceIndex I (Slice T) Output) :
    core.ops.index.IndexMut (Vec T) I Output := {
  indexInst := Vec.Index indexer
  index_mut := Vec.index_mut indexer
}

def Vec.extend_from_slice {T : Type} (clone : core.clone.Clone T)
    (value : Vec T) (suffix : Slice T) : Result (Vec T) := do
  let next ← Aeneas.Std.alloc.vec.Vec.extend_from_slice clone value.toBase suffix
  ok (Vec.ofBase next)

def CloneVec.clone {T : Type} (clone : core.clone.Clone T) (value : Vec T) : Result (Vec T) := do
  let next ← Aeneas.Std.alloc.vec.CloneVec.clone clone value.toBase
  ok (Vec.ofBase next)

def FromVecArray.from {T : Type} {N : Std.Usize} (value : Array T N) : Result (Vec T) := do
  let next ← Aeneas.Std.alloc.vec.FromVecArray.from value
  ok (Vec.ofBase next)

def partial_eq.PartialEqVec.eq {T U : Type} (comparison : core.cmp.PartialEq T U)
    (left : Vec T) (right : Vec U) : Result Bool :=
  Aeneas.Std.alloc.vec.partial_eq.PartialEqVec.eq comparison left.toBase right.toBase

def partial_eq.PartialEqVec.ne {T U : Type} (comparison : core.cmp.PartialEq T U)
    (left : Vec T) (right : Vec U) : Result Bool :=
  Aeneas.Std.alloc.vec.partial_eq.PartialEqVec.ne comparison left.toBase right.toBase

theorem to_base_of_base {T : Type} (value : Aeneas.Std.alloc.vec.Vec T) :
    Vec.toBase (Vec.ofBase value) = value :=
  auths_composition.alloc.vec.Vec.toBase_ofBase value

theorem of_base_to_base {T : Type} (value : Vec T) : Vec.ofBase (Vec.toBase value) = value :=
  auths_composition.alloc.vec.Vec.ofBase_toBase value

theorem contents_injective {T : Type} : Function.Injective (Vec.val (α := T)) := by
  intro left right same
  have baseSame : left.toBase = right.toBase := Subtype.ext same
  calc
    left = Vec.ofBase left.toBase := (of_base_to_base left).symm
    _ = Vec.ofBase right.toBase := congrArg Vec.ofBase baseSame
    _ = right := of_base_to_base right

@[simp] theorem pop_prefix_contents {T : Type} (value : Vec T) :
    (Vec.pop_prefix value).val = value.val.dropLast := by
  simp [Vec.pop_prefix, Vec.ofBase, Vec.val,
    auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.Vec.val,
    auths_composition.alloc.vec.SizedList.toList_ofList]

theorem pop_exact {T : Type} (value : Vec T) :
    Vec.pop value = ok (value.val.getLast?, Vec.pop_prefix value) := rfl

theorem prefix_last_reassembles {T : Type} (values : List T) :
    values.dropLast ++ values.getLast?.toList = values := by
  induction values with
  | nil => rfl
  | cons first rest ih =>
    cases rest with
    | nil => rfl
    | cons second tail =>
      simpa only [List.dropLast_cons_cons, List.getLast?_cons_cons, List.cons_append] using
        congrArg (List.cons first) ih

theorem pop_reassembles {T : Type} (value : Vec T) :
    (Vec.pop_prefix value).val ++ value.val.getLast?.toList = value.val := by
  rw [pop_prefix_contents]
  exact prefix_last_reassembles value.val

@[step] theorem push_spec {T : Type} (value : Vec T) (element : T)
    (capacity : value.val.length < Usize.max) :
    Vec.push value element ⦃ next => next.val = value.val ++ [element] ⦄ := by
  unfold Vec.push
  step with Aeneas.Std.alloc.vec.Vec.push_spec value.toBase element capacity as ⟨next, appended⟩
  simp only [bind_tc_ok, spec_ok]
  simpa [Vec.ofBase, Vec.val, auths_composition.alloc.vec.Vec.ofBase,
    auths_composition.alloc.vec.Vec.val, auths_composition.alloc.vec.SizedList.toList_ofList] using appended

@[simp] theorem with_capacity_contents (T : Type) (capacity : Std.Usize) :
    (Vec.with_capacity T capacity).val = [] := by
  simp [Vec.with_capacity, Aeneas.Std.alloc.vec.Vec.with_capacity,
    Aeneas.Std.alloc.vec.Vec.new, Vec.ofBase, Vec.val,
    auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.Vec.val,
    auths_composition.alloc.vec.SizedList.toList_ofList]

@[simp] theorem new_contents (T : Type) : (Vec.new T).val = [] := by
  simp [Vec.new, Aeneas.Std.alloc.vec.Vec.new, Vec.ofBase, Vec.val,
    auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.Vec.val,
    auths_composition.alloc.vec.SizedList.toList_ofList]

theorem equality_delegates {T U : Type} (comparison : core.cmp.PartialEq T U)
    (left : Vec T) (right : Vec U) :
    partial_eq.PartialEqVec.eq comparison left right =
      Aeneas.Std.alloc.vec.partial_eq.PartialEqVec.eq comparison left.toBase right.toBase := rfl

theorem inequality_delegates {T U : Type} (comparison : core.cmp.PartialEq T U)
    (left : Vec T) (right : Vec U) :
    partial_eq.PartialEqVec.ne comparison left right =
      Aeneas.Std.alloc.vec.partial_eq.PartialEqVec.ne comparison left.toBase right.toBase := rfl

theorem deref_exact {T : Type} (value : Vec T) : (Vec.deref value).val = value.val := rfl

@[simp] theorem len_value {T : Type} (value : Vec T) : (Vec.len value).val = value.val.length := by
  simp [Vec.len, Aeneas.Std.alloc.vec.Vec.len, Vec.toBase,
    auths_composition.alloc.vec.Vec.toBase, Vec.val, auths_composition.alloc.vec.Vec.val]

theorem empty_exact {T : Type} (value : Vec T) :
    Vec.is_empty T value = ok (decide (value.val = [])) := by
  simp [Vec.is_empty]

theorem mutable_projection_exact {T : Type} (value : Vec T) (updated : Slice T) :
    ((Vec.deref_mut value).2 updated).toBase.val = updated.val := by
  simp [Vec.deref_mut, Aeneas.Std.alloc.vec.Vec.deref_mut, to_base_of_base]

end AuthsProtocolCodec.alloc.vec

namespace AuthsProtocolCodec
def core.cmp.PartialEqVec {T U : Type} (comparison : Aeneas.Std.core.cmp.PartialEq T U) :
    Aeneas.Std.core.cmp.PartialEq (alloc.vec.Vec T) (alloc.vec.Vec U) := {
  eq := alloc.vec.partial_eq.PartialEqVec.eq comparison
  ne := alloc.vec.partial_eq.PartialEqVec.ne comparison
}
def core.ops.deref.DerefVec {T : Type} :
    Aeneas.Std.core.ops.deref.Deref (alloc.vec.Vec T) (Slice T) := {
  deref := fun value => ok (alloc.vec.Vec.deref value)
}
def core.ops.deref.DerefMutVec {T : Type} :
    Aeneas.Std.core.ops.deref.DerefMut (alloc.vec.Vec T) (Slice T) := {
  derefInst := core.ops.deref.DerefVec
  deref_mut := fun value => ok (alloc.vec.Vec.deref_mut value)
}
def core.clone.CloneallocvecVec {T : Type} (clone : Aeneas.Std.core.clone.Clone T) :
    Aeneas.Std.core.clone.Clone (alloc.vec.Vec T) := { clone := alloc.vec.CloneVec.clone clone }
def core.convert.FromVecArray (T : Type) (N : Std.Usize) :
    Aeneas.Std.core.convert.From (alloc.vec.Vec T) (Array T N) := {
  «from» := alloc.vec.FromVecArray.from
}
end AuthsProtocolCodec
