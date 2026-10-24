import Auths.Support.VTableLifetimeModel

/-!
Ownership-transfer component for one fixed trait's closed Box receiver family.
The implementation index is a ghost witness of the source type/dictionary;
the actual source producer must earn it. A concrete-to-dynamic cast moves the
same allocation and payload, changing only the handle's view. An occupied
destination, missing/already-dynamic source, or mismatched index refuses.

These state laws do not establish native layout, allocator/drop/unwind code,
inner borrowed-payload exclusivity/liveness, Rust/Aeneas loans, source-to-state
simulation or runtime selection. Those remain separate required obligations.
All declarations are authored; final elaboration/axiom audit are deferred.
-/
namespace Auths.Support.VTableOwnership

universe u v

structure Owner (Index : Type u) where
  allocation : Nat
  implementation : Index
  dynamicView : Bool
  deriving DecidableEq

structure State {Index : Type u} (Self : Index → Type v) where
  heap : Nat → Option (Sigma Self)
  locals : Nat → Option (Owner Index)

def Unique {Index : Type u} {Self : Index → Type v} (state : State Self) : Prop :=
  ∀ left right a b, state.locals left = some a → state.locals right = some b →
    a.allocation = b.allocation → left = right

def Typed {Index : Type u} {Self : Index → Type v} (state : State Self) : Prop :=
  ∀ local owner, state.locals local = some owner →
    ∃ value : Self owner.implementation, state.heap owner.allocation = some ⟨owner.implementation, value⟩

def Eligible {Index : Type u} {Self : Index → Type v} (state : State Self)
    (source target : Nat) (expected : Index) (owner : Owner Index) : Prop :=
  source ≠ target ∧ state.locals target = none ∧ owner.dynamicView = false ∧ owner.implementation = expected

def transfer {Index : Type u} {Self : Index → Type v} (state : State Self)
    (source target : Nat) (owner : Owner Index) : State Self :=
  { state with locals := fun local =>
      if local = source then none
      else if local = target then some { owner with dynamicView := true }
      else state.locals local }

def inject {Index : Type u} [DecidableEq Index] {Self : Index → Type v}
    (state : State Self) (source target : Nat) (expected : Index) : Option (State Self) :=
  match state.locals source with
  | none => none
  | some owner => if Eligible state source target expected owner then some (transfer state source target owner) else none

theorem inject_sound {Index : Type u} [DecidableEq Index] {Self : Index → Type v}
    (before after : State Self) (source target : Nat) (expected : Index)
    (accepted : inject before source target expected = some after) :
    ∃ owner, before.locals source = some owner ∧ Eligible before source target expected owner ∧
      after = transfer before source target owner := by
  cases original : before.locals source with
  | none => simp [inject, original] at accepted
  | some owner =>
      by_cases allowed : Eligible before source target expected owner
      · have same : transfer before source target owner = after := by
          simpa [inject, original, allowed] using accepted
        exact ⟨owner, original, allowed, same.symm⟩
      · simp [inject, original, allowed] at accepted

theorem eligible_injection_computes {Index : Type u} [DecidableEq Index] {Self : Index → Type v}
    (before : State Self) (source target : Nat) (expected : Index) (owner : Owner Index)
    (original : before.locals source = some owner) (allowed : Eligible before source target expected owner) :
    inject before source target expected = some (transfer before source target owner) := by
  simp [inject, original, allowed]

theorem transfer_preserves_heap {Index : Type u} {Self : Index → Type v}
    (before : State Self) (source target : Nat) (owner : Owner Index) :
    (transfer before source target owner).heap = before.heap := rfl

theorem transfer_source_consumed {Index : Type u} {Self : Index → Type v}
    (before : State Self) (source target : Nat) (owner : Owner Index) :
    (transfer before source target owner).locals source = none := by simp [transfer]

theorem transfer_destination_is_same_allocation {Index : Type u} {Self : Index → Type v}
    (before : State Self) (source target : Nat) (owner : Owner Index) (different : source ≠ target) :
    (transfer before source target owner).locals target = some { owner with dynamicView := true } := by
  simp [transfer, Ne.symm different]

theorem transfer_preserves_typing {Index : Type u} {Self : Index → Type v}
    (before : State Self) (source target : Nat) (original : Owner Index)
    (typed : Typed before) (sourceOwner : before.locals source = some original) :
    Typed (transfer before source target original) := by
  intro local owner present
  by_cases atSource : local = source
  · simp [transfer, atSource] at present
  · by_cases atTarget : local = target
    · have same : { original with dynamicView := true } = owner := by
        simpa [transfer, atSource, atTarget] using present
      subst owner
      exact typed source original sourceOwner
    · exact typed local owner (by simpa [transfer, atSource, atTarget] using present)

theorem transfer_preserves_unique_owner {Index : Type u} {Self : Index → Type v}
    (before : State Self) (source target : Nat) (original : Owner Index)
    (unique : Unique before) (sourceOwner : before.locals source = some original) :
    Unique (transfer before source target original) := by
  intro left right a b leftOwner rightOwner allocation
  by_cases leftSource : left = source
  · simp [transfer, leftSource] at leftOwner
  · by_cases rightSource : right = source
    · simp [transfer, rightSource] at rightOwner
    · by_cases leftTarget : left = target
      · by_cases rightTarget : right = target
        · exact leftTarget.trans rightTarget.symm
        · have same : { original with dynamicView := true } = a := by
            simpa [transfer, leftSource, leftTarget] using leftOwner
          have oldRight : before.locals right = some b := by
            simpa [transfer, rightSource, rightTarget] using rightOwner
          have sameAllocation : original.allocation = b.allocation := by simpa [← same] using allocation
          exact False.elim (rightSource (unique source right original b sourceOwner oldRight sameAllocation).symm)
      · by_cases rightTarget : right = target
        · have same : { original with dynamicView := true } = b := by
            simpa [transfer, rightSource, rightTarget] using rightOwner
          have oldLeft : before.locals left = some a := by
            simpa [transfer, leftSource, leftTarget] using leftOwner
          have sameAllocation : a.allocation = original.allocation := by simpa [← same] using allocation
          exact False.elim (leftSource (unique left source a original oldLeft sourceOwner sameAllocation))
        · exact unique left right a b
            (by simpa [transfer, leftSource, leftTarget] using leftOwner)
            (by simpa [transfer, rightSource, rightTarget] using rightOwner) allocation

theorem injection_preserves_heap_typing_and_ownership {Index : Type u} [DecidableEq Index]
    {Self : Index → Type v} (before after : State Self) (source target : Nat) (expected : Index)
    (typed : Typed before) (unique : Unique before)
    (accepted : inject before source target expected = some after) :
    after.heap = before.heap ∧ Typed after ∧ Unique after ∧ after.locals source = none := by
  obtain ⟨owner, original, _allowed, rfl⟩ := inject_sound before after source target expected accepted
  exact ⟨rfl, transfer_preserves_typing before source target owner typed original,
    transfer_preserves_unique_owner before source target owner unique original,
    transfer_source_consumed before source target owner⟩

theorem consumed_source_cannot_be_injected_again {Index : Type u} [DecidableEq Index]
    {Self : Index → Type v} (before after : State Self) (source target other : Nat) (expected : Index)
    (accepted : inject before source target expected = some after) : inject after source other expected = none := by
  obtain ⟨owner, _original, _allowed, rfl⟩ := inject_sound before after source target expected accepted
  simp [inject, transfer]

theorem occupied_destination_refused {Index : Type u} [DecidableEq Index] {Self : Index → Type v}
    (before : State Self) (source target : Nat) (expected : Index) (owner : Owner Index)
    (occupied : before.locals target = some owner) : inject before source target expected = none := by
  cases original : before.locals source <;> simp [inject, original, Eligible, occupied]

theorem wrong_implementation_refused {Index : Type u} [DecidableEq Index] {Self : Index → Type v}
    (before : State Self) (source target : Nat) (expected : Index) (owner : Owner Index)
    (original : before.locals source = some owner) (different : owner.implementation ≠ expected) :
    inject before source target expected = none := by
  simp [inject, original, Eligible, different]

theorem already_dynamic_source_refused {Index : Type u} [DecidableEq Index] {Self : Index → Type v}
    (before : State Self) (source target : Nat) (expected : Index) (owner : Owner Index)
    (original : before.locals source = some owner) (dynamic : owner.dynamicView = true) :
    inject before source target expected = none := by
  simp [inject, original, Eligible, dynamic]

namespace BoundaryExample

-- Semantic witnesses only: these numbers are not native allocation/layout
-- values or installed implementations.
def owner : Owner (Fin 1) := ⟨17, 0, false⟩
def before : State (fun _ : Fin 1 => Nat) := {
  heap := fun address => if address = 17 then some ⟨0, 37⟩ else none
  locals := fun local => if local = 0 then some owner else none }

theorem concrete_box_can_be_injected :
    inject before 0 1 0 = some (transfer before 0 1 owner) := by
  apply eligible_injection_computes
  · simp [before]
  · simp [Eligible, before, owner]

theorem injected_box_keeps_original_payload :
    (transfer before 0 1 owner).heap 17 = some ⟨0, 37⟩ := by simp [transfer, before]

theorem source_handle_is_consumed : (transfer before 0 1 owner).locals 0 = none := by simp [transfer]

end BoundaryExample

end Auths.Support.VTableOwnership
