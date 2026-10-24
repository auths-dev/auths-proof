import Auths.Support.SourceClosureCapture

/-!
Explicit source syntax for the straight-line closure constructor. Source local
numbers are preserved: local zero is the return place; input i is local i + 1.
The nominal closure identity and the move/copy distinction survive extraction.

The certificate records both this syntax and the proposed command program.
Lean checks lowering and evaluates the source syntax independently. This is a
restricted LLBC semantics, not the native reference/retag/loan semantics. The
connection to the pinned full LLBC interpreter and the original erased return
interface remains a required native-emission gate.
-/
namespace Auths.Support.SourceClosureSyntax

open Auths.Support.SourceClosureCapture
universe u

inductive Place where
  | local (index : Nat)
  | projected
  deriving DecidableEq, Repr

inductive Operand where
  | move (place : Place)
  | copy (place : Place)
  | unsupported
  deriving DecidableEq, Repr

inductive Instruction where
  | storageLive (local : Nat)
  | assignClosure (destination : Place) (nominal : Nat) (fields : List Operand)
  | storageDead (local : Nat)
  | returnValue
  | nop
  | unsupported
  deriving DecidableEq, Repr

structure Statement where
  identity : Nat
  instruction : Instruction
  deriving DecidableEq, Repr

def lowerOperand (arity : Nat) : Operand → Option Nat
  | .move (.local (index + 1)) => if index < arity then some index else none
  | _ => none

def lowerInstruction (arity nominal : Nat) : Instruction → Option Command
  | .storageLive 0 => some .openReturn
  | .assignClosure (.local 0) actual fields => do
      if actual ≠ nominal ∨ fields.length ≠ arity then none else
        return .capture (← fields.mapM (lowerOperand arity))
  | .storageDead (index + 1) => if index < arity then some (.endInput index) else none
  | .returnValue => some .finish
  | .nop => some .nop
  | _ => none

def lower (arity nominal : Nat) (source : List Statement) : Option (List Command) :=
  source.mapM fun statement => lowerInstruction arity nominal statement.instruction

/-- Opaque input values can include references; this semantics never reads,
copies, retags, dereferences, destroys or extends any such value. Native validity
of those references on entry/exit is a separate obligation. -/
inductive Value (Input : Type u) where
  | input (value : Input)
  | closure (nominal : Nat) (fields : List (Value Input))

structure State (Input : Type u) where
  locals : Nat → Option (Value Input)
  live : Nat → Bool
  returned : Bool

def initialState {Input : Type u} (inputs : List Input) : State Input :=
  { locals := fun index => match index with
      | 0 => none
      | index + 1 => inputs[index]?.map Value.input
    live := fun index => match index with
      | 0 => false
      | index + 1 => inputs[index]?.isSome
    returned := false }

def writeLocal {Input : Type u} (locals : Nat → Option (Value Input))
    (index : Nat) (value : Option (Value Input)) : Nat → Option (Value Input) :=
  fun current => if current = index then value else locals current

/-- Reading the original move operands consumes the original source locals.
Copy operands, projected places and moving the return place are refused. -/
def moveFields {Input : Type u} (live : Nat → Bool) (locals : Nat → Option (Value Input)) :
    List Operand → Option (List (Value Input) × (Nat → Option (Value Input)))
  | [] => some ([], locals)
  | .move (.local (index + 1)) :: rest => do
      if !live (index + 1) then none else do
        let value ← locals (index + 1)
        let (fields, after) ← moveFields live (writeLocal locals (index + 1) none) rest
        pure (value :: fields, after)
  | _ => none

def sourceStep {Input : Type u} (instruction : Instruction) (before : State Input) : Option (State Input) := do
  if before.returned then none else
    match instruction with
    | .storageLive 0 =>
        if before.live 0 || (before.locals 0).isSome then none
        else some { before with live := fun index => if index = 0 then true else before.live index }
    | .assignClosure (.local 0) nominal fields =>
        if !before.live 0 || (before.locals 0).isSome then none else do
          let (values, remaining) ← moveFields before.live before.locals fields
          some { before with locals := writeLocal remaining 0 (some (.closure nominal values)) }
    | .storageDead (index + 1) =>
        if !before.live (index + 1) || (before.locals (index + 1)).isSome then none
        else some { before with live := fun current => if current = index + 1 then false else before.live current }
    | .returnValue =>
        if !before.live 0 then none else
          match before.locals 0 with
          | some (.closure _ _) => some { before with returned := true }
          | _ => none
    | .nop => some before
    | _ => none

def sourceRun {Input : Type u} : List Statement → State Input → Option (State Input)
  | [], state => some state
  | statement :: rest, state => (sourceStep statement.instruction state).bind (sourceRun rest)

def sourceResult {Input : Type u} (source : List Statement) (inputs : List Input) : Option (Value Input) := do
  let after ← sourceRun source (initialState inputs)
  if after.returned then after.locals 0 else none

/-- Removing nominal information is explicit; the source theorem must still
establish the actual nominal identity before comparing command field order. -/
def inputFields {Input : Type u} : List (Value Input) → Option (List Input)
  | [] => some []
  | .input value :: rest => (inputFields rest).map (value :: ·)
  | .closure _ _ :: _ => none

def observedFields {Input : Type u} (nominal : Nat) : Value Input → Option (List Input)
  | .closure actual fields => if actual = nominal then inputFields fields else none
  | .input _ => none

theorem copied_operand_refused (arity : Nat) (place : Place) :
    lowerOperand arity (.copy place) = none := rfl

theorem projected_move_refused (arity : Nat) :
    lowerOperand arity (.move .projected) = none := rfl

theorem return_place_move_refused (arity : Nat) :
    lowerOperand arity (.move (.local 0)) = none := rfl

theorem out_of_range_move_refused (arity index : Nat) (outside : ¬ index < arity) :
    lowerOperand arity (.move (.local (index + 1))) = none := by
  simp [lowerOperand, outside]

theorem different_nominal_refused (arity expected actual : Nat) (different : actual ≠ expected)
    (fields : List Operand) :
    lowerInstruction arity expected (.assignClosure (.local 0) actual fields) = none := by
  simp [lowerInstruction, different]

theorem source_copy_cannot_capture {Input : Type u} (live : Nat → Bool)
    (locals : Nat → Option (Value Input)) (place : Place) (rest : List Operand) :
    moveFields live locals (.copy place :: rest) = none := rfl

theorem source_unmoved_input_cannot_end {Input : Type u} (before : State Input)
    (index : Nat) (value : Value Input) (present : before.locals (index + 1) = some value) :
    sourceStep (.storageDead (index + 1)) before = none := by
  cases returned : before.returned <;> simp [sourceStep, returned, present]

theorem source_returned_state_cannot_continue {Input : Type u} (before : State Input)
    (instruction : Instruction) (returned : before.returned = true) :
    sourceStep instruction before = none := by
  simp [sourceStep, returned]

theorem source_repeated_move_refused {Input : Type u} (live : Nat → Bool)
    (locals : Nat → Option (Value Input)) (index : Nat) :
    moveFields live locals [.move (.local (index + 1)), .move (.local (index + 1))] = none := by
  cases active : live (index + 1) <;>
    cases stored : locals (index + 1) <;> simp [moveFields, active, stored, writeLocal]

end Auths.Support.SourceClosureSyntax
