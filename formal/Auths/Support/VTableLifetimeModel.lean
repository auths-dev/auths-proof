import Mathlib.Data.Set.Basic

/-!
Lifetime component of the generated-vtable representation boundary.

Forgetting the object-lifetime annotation of a borrowed dynamic receiver must
retain the receiver's actual liveness over the entire borrow. The object
region can then be reconstructed as that borrow region; no static lifetime is
inferred. These lemmas do not establish the pinned compiler's representation,
pointer casts, ownership/drop behavior, method bodies or Aeneas loan semantics.
The LLBC-to-model relation and those obligations remain separate required gates.
All declarations are authored; final elaboration and axiom audit are deferred.
-/
namespace Auths.Support.VTableLifetime

universe u v

abbrev Region (Point : Type v) := Set Point

def Outlives {Point : Type v} (longer shorter : Region Point) : Prop := shorter ⊆ longer

/-- An explicit object region and its evidence remain distinct from the
actual borrow. Neither region is silently strengthened to static. -/
structure BorrowedReceiver (Value : Type u) (Point : Type v)
    (live : Value → Point → Prop) (borrow : Region Point) where
  value : Value
  objectRegion : Region Point
  objectLive : ∀ point ∈ objectRegion, live value point
  borrowWithinObject : Outlives objectRegion borrow

/-- An erased annotation is usable only with the complete actual borrow
liveness evidence. The compiler's bare RErased marker is not this evidence. -/
structure ErasedReceiver (Value : Type u) (Point : Type v)
    (live : Value → Point → Prop) (borrow : Region Point) where
  value : Value
  borrowLive : ∀ point ∈ borrow, live value point

def erase {Value : Type u} {Point : Type v} {live : Value → Point → Prop}
    {borrow : Region Point} (receiver : BorrowedReceiver Value Point live borrow) :
    ErasedReceiver Value Point live borrow :=
  ⟨receiver.value, fun point member =>
    receiver.objectLive point (receiver.borrowWithinObject member)⟩

def restore {Value : Type u} {Point : Type v} {live : Value → Point → Prop}
    {borrow : Region Point} (receiver : ErasedReceiver Value Point live borrow) :
    BorrowedReceiver Value Point live borrow :=
  ⟨receiver.value, borrow, receiver.borrowLive, fun _ member => member⟩

theorem erase_restore {Value : Type u} {Point : Type v}
    {live : Value → Point → Prop} {borrow : Region Point}
    (receiver : ErasedReceiver Value Point live borrow) : erase (restore receiver) = receiver := by
  cases receiver
  rfl

theorem restore_preserves_value {Value : Type u} {Point : Type v}
    {live : Value → Point → Prop} {borrow : Region Point}
    (receiver : ErasedReceiver Value Point live borrow) :
    (restore receiver).value = receiver.value := rfl

theorem restore_uses_actual_borrow {Value : Type u} {Point : Type v}
    {live : Value → Point → Prop} {borrow : Region Point}
    (receiver : ErasedReceiver Value Point live borrow) :
    (restore receiver).objectRegion = borrow := rfl

theorem borrow_liveness_iff_object_witness {Value : Type u} {Point : Type v}
    (live : Value → Point → Prop) (value : Value) (borrow : Region Point) :
    (∀ point ∈ borrow, live value point) ↔
      ∃ objectRegion, Outlives objectRegion borrow ∧
        ∀ point ∈ objectRegion, live value point := by
  constructor
  · intro valid
    exact ⟨borrow, fun _ member => member, valid⟩
  · rintro ⟨objectRegion, within, valid⟩ point member
    exact valid point (within member)

def narrow {Value : Type u} {Point : Type v} {live : Value → Point → Prop}
    {borrow shorter : Region Point} (receiver : ErasedReceiver Value Point live borrow)
    (within : shorter ⊆ borrow) : ErasedReceiver Value Point live shorter :=
  ⟨receiver.value, fun point member => receiver.borrowLive point (within member)⟩

theorem narrow_preserves_value {Value : Type u} {Point : Type v}
    {live : Value → Point → Prop} {borrow shorter : Region Point}
    (receiver : ErasedReceiver Value Point live borrow) (within : shorter ⊆ borrow) :
    (narrow receiver within).value = receiver.value := rfl

theorem narrowing_composes {Value : Type u} {Point : Type v}
    {live : Value → Point → Prop} {borrow shorter shortest : Region Point}
    (receiver : ErasedReceiver Value Point live borrow)
    (first : shorter ⊆ borrow) (second : shortest ⊆ shorter) :
    narrow (narrow receiver first) second = narrow receiver (fun _ h => first (second h)) := by
  cases receiver
  rfl

namespace BoundaryExamples

def short : Region Bool := {point | point = false}
def live (_value : Unit) (point : Bool) : Prop := point = false
def receiver : ErasedReceiver Unit Bool live short := ⟨(), fun _ member => member⟩

theorem borrow_is_inhabited : false ∈ short := rfl

theorem short_receiver_restores : (restore receiver).objectRegion = short := rfl

theorem no_static_upgrade : ¬ ∀ point ∈ (Set.univ : Region Bool), live () point := by
  intro static
  have impossible : true = false := static true (Set.mem_univ true)
  cases impossible

end BoundaryExamples
end Auths.Support.VTableLifetime
