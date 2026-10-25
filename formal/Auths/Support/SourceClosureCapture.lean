import Mathlib.Data.List.Basic

/-!
Operational subset for the actual straight-line source closure-return witness.
`return_capture_plan` lowers every original source statement accepted by
Return_signature into these commands, preserving move order and storage ends.
Generated cases instantiate this interpreter with the actual source program;
they do not replace an ordinary function result with a supplied value.

Values are opaque here: this proves linear local movement/field order in the
checked subset. The LLBC-to-subset relation, typed reference interpretation,
opaque-signature refinement, native stack/heap/layout, entry retags and loan
liveness remain required before any native claim. No theorem here closes those
gates. All new declarations/cases await the final elaboration/axiom audit.
-/
namespace Auths.Support.SourceClosureCapture

universe u v

inductive Command where
  | openReturn
  | capture (sourceParameters : List Nat)
  | endInput (parameter : Nat)
  | finish
  | nop
  deriving DecidableEq, Repr

structure Frame (Value : Type u) where
  inputs : Nat → Option Value
  ended : Nat → Bool
  returnLive : Bool
  fields : Option (List Value)
  returned : Bool

def initial {Value : Type u} (inputs : List Value) : Frame Value :=
  ⟨fun index => inputs[index]?, fun _ => false, false, none, false⟩

def clearInput {Value : Type u} (inputs : Nat → Option Value) (index : Nat) : Nat → Option Value :=
  fun current => if current = index then none else inputs current

/-- A move consumes its source before another field may read that slot. -/
def moveInputs {Value : Type u} (inputs : Nat → Option Value) :
    List Nat → Option (List Value × (Nat → Option Value))
  | [] => some ([], inputs)
  | index :: rest => do
      let value ← inputs index
      let (values, remaining) ← moveInputs (clearInput inputs index) rest
      pure (value :: values, remaining)

def step {Value : Type u} (command : Command) (before : Frame Value) : Option (Frame Value) := do
  if before.returned then none else
    match command with
    | .openReturn =>
        if before.returnLive || before.fields.isSome then none
        else some { before with returnLive := true }
    | .capture parameters =>
        if !before.returnLive || before.fields.isSome then none else do
          let (values, remaining) ← moveInputs before.inputs parameters
          some { before with inputs := remaining, fields := some values }
    | .endInput index =>
        if (before.inputs index).isSome then none
        else if before.ended index then none
        else some { before with ended := fun current => if current = index then true else before.ended current }
    | .finish =>
        if before.returnLive && before.fields.isSome then some { before with returned := true }
        else none
    | .nop => some before

def run {Value : Type u} : List Command → Frame Value → Option (Frame Value)
  | [], state => some state
  | command :: rest, state => (step command state).bind (run rest)

def returnedFields {Value : Type u} (program : List Command) (inputs : List Value) : Option (List Value) := do
  let after ← run program (initial inputs)
  if after.returned then after.fields else none

structure Runtime (Value : Type u) (Heap : Type v) where
  frame : Frame Value
  heap : Heap

/-- This subset has no memory/call/destructor instruction. The source lowering
must reject any such instruction instead of assigning it a preservation rule. -/
def execute {Value : Type u} {Heap : Type v} (program : List Command)
    (before : Runtime Value Heap) : Option (Runtime Value Heap) :=
  (run program before.frame).map fun frame => { frame, heap := before.heap }

theorem execute_keeps_heap {Value : Type u} {Heap : Type v} (program : List Command)
    (before after : Runtime Value Heap) (accepted : execute program before = some after) :
    after.heap = before.heap := by
  cases outcome : run program before.frame with
  | none => simp [execute, outcome] at accepted
  | some frame =>
      have same : ({ frame, heap := before.heap } : Runtime Value Heap) = after := by
        simpa [execute, outcome] using accepted
      subst after
      rfl

theorem repeated_input_move_refused {Value : Type u} (inputs : Nat → Option Value) (index : Nat) :
    moveInputs inputs [index, index] = none := by
  cases stored : inputs index <;> simp [moveInputs, stored, clearInput]

theorem an_unmoved_input_cannot_end {Value : Type u} (before : Frame Value) (index : Nat)
    (value : Value) (present : before.inputs index = some value) :
    step (.endInput index) before = none := by
  cases returned : before.returned <;> simp [step, returned, present]

theorem returned_frame_cannot_execute_more {Value : Type u} (before : Frame Value)
    (command : Command) (returned : before.returned = true) : step command before = none := by
  simp [step, returned]

theorem return_before_capture_refused {Value : Type u} (inputs : List Value) :
    step .finish (initial inputs) = none := by
  simp [step, initial]

theorem capture_before_return_storage_refused {Value : Type u} (inputs : List Value)
    (parameters : List Nat) : step (.capture parameters) (initial inputs) = none := by
  simp [step, initial]

end Auths.Support.SourceClosureCapture
