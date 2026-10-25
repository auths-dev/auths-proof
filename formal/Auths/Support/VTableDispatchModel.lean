import Auths.Support.VTableLifetimeModel

/-!
Source-slot selection for a typed generated-vtable representation. A slot
contains the actual source method body, not a supplied desired output.
Selection refuses duplicate trait/method slots and a different function ID.
Receiver liveness is retained by VTableLifetime.ErasedReceiver.

The producer must still bind each identity, Self/input/output type and body to
the exact LLBC declaration, initializer/shim and original field ABI. These
general theorems do not qualify that source bridge or any dynamic call/drop.
No foreign implementation or Auths callback is installed by this module.
-/
namespace Auths.Support.VTableDispatch
open VTableLifetime

universe u v w x

structure Identity where
  traitId : Nat
  methodId : Nat
  functionId : Nat
  deriving DecidableEq, Repr

structure SourceMethod (Value : Type u) (Input : Type v) (Output : Type w) where
  identity : Identity
  body : Value → Input → Output

def sameSlot (expected actual : Identity) : Bool :=
  decide (actual.traitId = expected.traitId ∧ actual.methodId = expected.methodId)

def candidates {Value : Type u} {Input : Type v} {Output : Type w}
    (expected : Identity) (entries : List (SourceMethod Value Input Output)) :=
  entries.filter (fun entry => sameSlot expected entry.identity)

def select {Value : Type u} {Input : Type v} {Output : Type w}
    (expected : Identity) (entries : List (SourceMethod Value Input Output)) :
    Option (SourceMethod Value Input Output) :=
  match candidates expected entries with
  | [entry] => if entry.identity = expected then some entry else none
  | _ => none

theorem select_sound {Value : Type u} {Input : Type v} {Output : Type w}
    (expected : Identity) (entries : List (SourceMethod Value Input Output))
    (actual : SourceMethod Value Input Output) (accepted : select expected entries = some actual) :
    candidates expected entries = [actual] ∧ actual.identity = expected := by
  unfold select at accepted
  split at accepted
  · split at accepted <;> simp_all
  · simp_all

theorem selected_is_original {Value : Type u} {Input : Type v} {Output : Type w}
    (expected : Identity) (entries : List (SourceMethod Value Input Output))
    (actual : SourceMethod Value Input Output) (accepted : select expected entries = some actual) :
    actual ∈ entries := by
  have singleton := (select_sound expected entries actual accepted).1
  have member : actual ∈ candidates expected entries := by rw [singleton]; simp
  exact (List.mem_filter.mp member).1

theorem duplicate_slot_refused {Value : Type u} {Input : Type v} {Output : Type w}
    (expected : Identity) (entries : List (SourceMethod Value Input Output))
    (first second : SourceMethod Value Input Output) (rest : List (SourceMethod Value Input Output))
    (duplicate : candidates expected entries = first :: second :: rest) : select expected entries = none := by
  simp [select, duplicate]

def dispatch {Value : Type u} {Input : Type v} {Output : Type w} {Point : Type x}
    {live : Value → Point → Prop} {borrow : Region Point}
    (expected : Identity) (entries : List (SourceMethod Value Input Output))
    (receiver : ErasedReceiver Value Point live borrow) (input : Input) : Option Output :=
  (select expected entries).map (fun method => method.body receiver.value input)

theorem dispatch_exact_source_body {Value : Type u} {Input : Type v} {Output : Type w}
    {Point : Type x} {live : Value → Point → Prop} {borrow : Region Point}
    (expected : Identity) (entries : List (SourceMethod Value Input Output))
    (receiver : ErasedReceiver Value Point live borrow) (input : Input)
    (actual : SourceMethod Value Input Output) (selected : select expected entries = some actual) :
    dispatch expected entries receiver input = some (actual.body receiver.value input) := by
  simp [dispatch, selected]

theorem refused_slot_has_no_result {Value : Type u} {Input : Type v} {Output : Type w}
    {Point : Type x} {live : Value → Point → Prop} {borrow : Region Point}
    (expected : Identity) (entries : List (SourceMethod Value Input Output))
    (receiver : ErasedReceiver Value Point live borrow) (input : Input)
    (refused : select expected entries = none) : dispatch expected entries receiver input = none := by
  simp [dispatch, refused]

namespace BoundaryExamples

def expected : Identity := ⟨7, 3, 11⟩
def original : SourceMethod Nat Nat Nat := ⟨expected, fun value input => value + input⟩
def substituted : SourceMethod Nat Nat Nat := ⟨⟨7, 3, 12⟩, fun _ _ => 0⟩

theorem original_slot_selected : select expected [original] = some original := by rfl
theorem substituted_function_refused : select expected [substituted] = none := by rfl
theorem duplicate_method_refused : select expected [original, substituted] = none := by rfl

end BoundaryExamples

/-! A finite typed sum is the target representation for closed native dynamic
receivers. A constructor carries the implementation's actual Self value and
its liveness evidence together; the payload cannot be retagged as another
implementation's type. Injection explicitly requires borrow shortening.

The source producer still has to earn the constructor from the actual unsize
dictionary/static/operand and bind every branch to its translated source body.
These definitions do not establish that relation, Rust pointer layout, linear
mutable ownership, drop/unwind simulation, or source/Aeneas loan preservation.
All new proof terms remain unelaborated until the final checking batch. -/
namespace ClosedReceivers

structure Packed {count : Nat} (Self : Fin count → Type u) (Point : Type v)
    (live : (index : Fin count) → Self index → Point → Prop) (borrow : Region Point) where
  index : Fin count
  receiver : ErasedReceiver (Self index) Point (live index) borrow

def inject {count : Nat} {Self : Fin count → Type u} {Point : Type v}
    {live : (index : Fin count) → Self index → Point → Prop}
    {sourceBorrow dynamicBorrow : Region Point} (index : Fin count)
    (receiver : BorrowedReceiver (Self index) Point (live index) sourceBorrow)
    (within : dynamicBorrow ⊆ sourceBorrow) : Packed Self Point live dynamicBorrow :=
  ⟨index, narrow (erase receiver) within⟩

def restoreAt {count : Nat} {Self : Fin count → Type u} {Point : Type v}
    {live : (index : Fin count) → Self index → Point → Prop} {borrow : Region Point}
    (expected : Fin count) (packed : Packed Self Point live borrow) :
    Option (ErasedReceiver (Self expected) Point (live expected) borrow) :=
  match packed with
  | ⟨actual, receiver⟩ => if same : actual = expected then some (same ▸ receiver) else none

theorem restore_injected {count : Nat} {Self : Fin count → Type u} {Point : Type v}
    {live : (index : Fin count) → Self index → Point → Prop}
    {sourceBorrow dynamicBorrow : Region Point} (index : Fin count)
    (receiver : BorrowedReceiver (Self index) Point (live index) sourceBorrow)
    (within : dynamicBorrow ⊆ sourceBorrow) :
    restoreAt index (inject index receiver within) = some (narrow (erase receiver) within) := by
  simp [restoreAt, inject]

theorem different_implementation_refused {count : Nat} {Self : Fin count → Type u} {Point : Type v}
    {live : (index : Fin count) → Self index → Point → Prop}
    {sourceBorrow dynamicBorrow : Region Point} (actual expected : Fin count)
    (different : actual ≠ expected)
    (receiver : BorrowedReceiver (Self actual) Point (live actual) sourceBorrow)
    (within : dynamicBorrow ⊆ sourceBorrow) :
    restoreAt expected (inject actual receiver within) = none := by
  simp [restoreAt, inject, different]

theorem restored_index_is_original {count : Nat} {Self : Fin count → Type u} {Point : Type v}
    {live : (index : Fin count) → Self index → Point → Prop} {borrow : Region Point}
    (expected : Fin count) (packed : Packed Self Point live borrow)
    (receiver : ErasedReceiver (Self expected) Point (live expected) borrow)
    (accepted : restoreAt expected packed = some receiver) : packed.index = expected := by
  cases packed with
  | mk actual original =>
      by_cases same : actual = expected
      · exact same
      · simp [restoreAt, same] at accepted

def dispatch {count : Nat} {Self : Fin count → Type u} {Point : Type v}
    {live : (index : Fin count) → Self index → Point → Prop} {borrow : Region Point}
    {Input : Type w} {Output : Type x}
    (sourceBodies : (index : Fin count) → Self index → Input → Output)
    (packed : Packed Self Point live borrow) (input : Input) : Output :=
  sourceBodies packed.index packed.receiver.value input

theorem dispatch_injected_source_body {count : Nat} {Self : Fin count → Type u} {Point : Type v}
    {live : (index : Fin count) → Self index → Point → Prop}
    {sourceBorrow dynamicBorrow : Region Point} {Input : Type w} {Output : Type x}
    (sourceBodies : (index : Fin count) → Self index → Input → Output) (index : Fin count)
    (receiver : BorrowedReceiver (Self index) Point (live index) sourceBorrow)
    (within : dynamicBorrow ⊆ sourceBorrow) (input : Input) :
    dispatch sourceBodies (inject index receiver within) input = sourceBodies index receiver.value input := rfl

theorem injected_borrow_is_live {count : Nat} {Self : Fin count → Type u} {Point : Type v}
    {live : (index : Fin count) → Self index → Point → Prop}
    {sourceBorrow dynamicBorrow : Region Point} (index : Fin count)
    (receiver : BorrowedReceiver (Self index) Point (live index) sourceBorrow)
    (within : dynamicBorrow ⊆ sourceBorrow) :
    ∀ point ∈ dynamicBorrow, live index receiver.value point := by
  intro point member
  exact receiver.objectLive point (receiver.borrowWithinObject (within member))

/-- Reborrowing preserves the complete paired constructor, including its Self
value. An implementation index by itself is not a receiver identity witness. -/
def reborrow {count : Nat} {Self : Fin count → Type u} {Point : Type v}
    {live : (index : Fin count) → Self index → Point → Prop} {borrow shorter : Region Point}
    (packed : Packed Self Point live borrow) (within : shorter ⊆ borrow) :
    Packed Self Point live shorter :=
  ⟨packed.index, narrow packed.receiver within⟩

theorem reborrow_preserves_implementation {count : Nat} {Self : Fin count → Type u} {Point : Type v}
    {live : (index : Fin count) → Self index → Point → Prop} {borrow shorter : Region Point}
    (packed : Packed Self Point live borrow) (within : shorter ⊆ borrow) :
    (reborrow packed within).index = packed.index := rfl

theorem dispatch_reborrowed_source_body {count : Nat} {Self : Fin count → Type u} {Point : Type v}
    {live : (index : Fin count) → Self index → Point → Prop} {borrow shorter : Region Point}
    {Input : Type w} {Output : Type x}
    (sourceBodies : (index : Fin count) → Self index → Input → Output)
    (packed : Packed Self Point live borrow) (within : shorter ⊆ borrow) (input : Input) :
    dispatch sourceBodies (reborrow packed within) input = dispatch sourceBodies packed input := rfl

theorem restoration_commutes_with_reborrow {count : Nat} {Self : Fin count → Type u} {Point : Type v}
    {live : (index : Fin count) → Self index → Point → Prop} {borrow shorter : Region Point}
    (expected : Fin count) (packed : Packed Self Point live borrow) (within : shorter ⊆ borrow) :
    restoreAt expected (reborrow packed within) = (restoreAt expected packed).map (fun receiver => narrow receiver within) := by
  cases packed with
  | mk actual receiver =>
      by_cases same : actual = expected
      · subst expected
        simp [restoreAt, reborrow]
      · simp [restoreAt, reborrow, same]

theorem reborrow_composes {count : Nat} {Self : Fin count → Type u} {Point : Type v}
    {live : (index : Fin count) → Self index → Point → Prop}
    {borrow shorter shortest : Region Point} (packed : Packed Self Point live borrow)
    (first : shorter ⊆ borrow) (second : shortest ⊆ shorter) :
    reborrow (reborrow packed first) second = reborrow packed (fun _ member => first (second member)) := by
  cases packed
  rfl

namespace ReceiverIdentityExample

-- Equal dictionary indices do not permit substituting another receiver value.
-- These are semantic examples, not installed native methods or input fixtures.
def live (_index : Fin 1) (_value : Nat) (_point : Unit) : Prop := True
def first : Packed (fun _ : Fin 1 => Nat) Unit live Set.univ :=
  ⟨0, ⟨7, fun _ _ => True.intro⟩⟩
def second : Packed (fun _ : Fin 1 => Nat) Unit live Set.univ :=
  ⟨0, ⟨11, fun _ _ => True.intro⟩⟩
def sourceBody (_index : Fin 1) (value : Nat) (_input : Unit) : Nat := value

theorem equal_indices : first.index = second.index := rfl

theorem receiver_substitution_changes_observation :
    dispatch sourceBody first () ≠ dispatch sourceBody second () := by decide

end ReceiverIdentityExample

end ClosedReceivers
end Auths.Support.VTableDispatch
