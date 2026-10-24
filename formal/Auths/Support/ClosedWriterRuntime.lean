import Auths.Support.VTableLifetimeModel
import Auths.Support.SourceClosureRegions

/-!
Reference topology of the two actual source Write cases. A reference stores
an address and an existing loan identity, not a copy of its referent. MainWriter
references a cell containing the inner buffer reference; ObjectBuffer references
the buffer directly. Narrowing changes the permitted view, never either address
or loan identity, and never the invariant inner reference type.

This component requires actual source provenance, borrow inclusion and liveness.
It does not mint exclusive permissions or prove native Box allocation/layout,
Rust/Aeneas alias/loan simulation, source reachability, drop/unwind, or the
additional parent-writer/object outlives condition of the native overlay.
All new scripts await final elaboration/audits.
-/
namespace Auths.Support.ClosedWriterRuntime

open VTableLifetime
universe u v

inductive Case where
  | mainWriter
  | objectBuffer
  deriving DecidableEq, Repr

/-- The phantom pointee sort keeps the two levels of the main writer distinct.
Copying this address record alone conveys no usable mutable permission. -/
structure Address (Pointee : Type u) : Type u where
  cell : Nat
  loan : Nat
  deriving DecidableEq, Repr

def Target (Buffer : Type u) : Case → Type u
  | .mainWriter => Address Buffer
  | .objectBuffer => Buffer

structure World (Buffer : Type u) where
  references : Nat → Option (Address Buffer)
  buffers : Nat → Option Buffer

def resolve {Buffer : Type u} (world : World Buffer) :
    (kind : Case) → Address (Target Buffer kind) → Option (Address Buffer)
  | .mainWriter, reference => world.references reference.cell
  | .objectBuffer, reference => some reference

structure Source {Buffer : Type u} {Point : Type v}
    (live : (kind : Case) → Address (Target Buffer kind) → Point → Prop)
    (sourceBorrow : Case → Region Point) where
  kind : Case
  receiver : BorrowedReceiver (Address (Target Buffer kind)) Point (live kind) (sourceBorrow kind)

structure Native {Buffer : Type u} {Point : Type v}
    (live : (kind : Case) → Address (Target Buffer kind) → Point → Prop)
    (objectBorrow : Region Point) where
  kind : Case
  receiver : ErasedReceiver (Address (Target Buffer kind)) Point (live kind) objectBorrow

def encode {Buffer : Type u} {Point : Type v}
    {live : (kind : Case) → Address (Target Buffer kind) → Point → Prop}
    {sourceBorrow : Case → Region Point} {objectBorrow : Region Point}
    (source : Source live sourceBorrow)
    (within : objectBorrow ⊆ sourceBorrow source.kind) : Native live objectBorrow :=
  ⟨source.kind, narrow (erase source.receiver) within⟩

def reborrow {Buffer : Type u} {Point : Type v}
    {live : (kind : Case) → Address (Target Buffer kind) → Point → Prop}
    {objectBorrow shorter : Region Point} (native : Native live objectBorrow)
    (within : shorter ⊆ objectBorrow) : Native live shorter :=
  ⟨native.kind, narrow native.receiver within⟩

def sourceTarget {Buffer : Type u} {Point : Type v}
    {live : (kind : Case) → Address (Target Buffer kind) → Point → Prop}
    {sourceBorrow : Case → Region Point} (world : World Buffer)
    (source : Source live sourceBorrow) : Option (Address Buffer) :=
  resolve world source.kind source.receiver.value

def nativeTarget {Buffer : Type u} {Point : Type v}
    {live : (kind : Case) → Address (Target Buffer kind) → Point → Prop}
    {objectBorrow : Region Point} (world : World Buffer)
    (native : Native live objectBorrow) : Option (Address Buffer) :=
  resolve world native.kind native.receiver.value

theorem encoding_keeps_source_case {Buffer : Type u} {Point : Type v}
    {live : (kind : Case) → Address (Target Buffer kind) → Point → Prop}
    {sourceBorrow : Case → Region Point} {objectBorrow : Region Point}
    (source : Source live sourceBorrow) (within : objectBorrow ⊆ sourceBorrow source.kind) :
    (encode source within).kind = source.kind := rfl

theorem encoding_keeps_outer_address_and_loan {Buffer : Type u} {Point : Type v}
    {live : (kind : Case) → Address (Target Buffer kind) → Point → Prop}
    {sourceBorrow : Case → Region Point} {objectBorrow : Region Point}
    (source : Source live sourceBorrow) (within : objectBorrow ⊆ sourceBorrow source.kind) :
    (encode source within).receiver.value = source.receiver.value := rfl

theorem encoding_keeps_actual_buffer_target {Buffer : Type u} {Point : Type v}
    {live : (kind : Case) → Address (Target Buffer kind) → Point → Prop}
    {sourceBorrow : Case → Region Point} {objectBorrow : Region Point}
    (world : World Buffer) (source : Source live sourceBorrow)
    (within : objectBorrow ⊆ sourceBorrow source.kind) :
    nativeTarget world (encode source within) = sourceTarget world source := rfl

theorem reborrow_keeps_actual_buffer_target {Buffer : Type u} {Point : Type v}
    {live : (kind : Case) → Address (Target Buffer kind) → Point → Prop}
    {objectBorrow shorter : Region Point} (world : World Buffer)
    (native : Native live objectBorrow) (within : shorter ⊆ objectBorrow) :
    nativeTarget world (reborrow native within) = nativeTarget world native := rfl

theorem main_writer_resolves_through_original_inner_reference {Buffer : Type u}
    (world : World Buffer) (outer : Address (Address Buffer)) (inner : Address Buffer)
    (stored : world.references outer.cell = some inner) :
    resolve world .mainWriter outer = some inner := stored

theorem object_buffer_keeps_original_reference {Buffer : Type u}
    (world : World Buffer) (reference : Address Buffer) :
    resolve world .objectBuffer reference = some reference := rfl

/- Structural certificates for the emitted source/native payload schemas. -/
open SourceClosureRegions

def innerExclusiveReference : Expr → Option Expr
  | .node .mutRef [.region _, inner] => some inner
  | _ => none

/-- Specializing the parent type does not rewrite any region inside that type.
Other free variables or shapes are not accepted as this writer schema. -/
def instantiateMainPayload (schema parent : Expr) : Option Expr :=
  match schema with
  | .node .mutRef [region, .node .typeFree [.natural 0]] =>
      some (.node .mutRef [region, parent])
  | _ => none

theorem main_payload_specialization_keeps_invariant_parent (region parent : Expr) :
    (instantiateMainPayload (.node .mutRef [region, .node .typeFree [.natural 0]]) parent).bind
      innerExclusiveReference =
        (match region with | .region _ => some parent | _ => none) := by
  cases region <;> simp [instantiateMainPayload, innerExclusiveReference]

end Auths.Support.ClosedWriterRuntime
