import Auths.Support.NativeScopedDefaults
import Auths.Support.NativeRootBindings

/-!
Native assignment from existing whole backward arguments. Argument slots and
source-version channels remain distinct; overlapping projections discharge no
source correspondence. This finite runtime supplies neither source heap/loan
adequacy nor the complete original function's continuation/output semantics.
All scripts await final elaboration.
-/
namespace Auths.Support.NativeOwnedBindings
open NativeRootPayload NativeRootExpressions NativeScopedDefaults
open NativeDefaultBindings (Table lookup put)
open NativeRootBindings (ArgumentSlot)
universe u

structure Argument where
  slot : ArgumentSlot
  variable : Variable
  deriving DecidableEq, Repr

structure Assignment where
  port : NativeBorrowWiring.Port
  slot : ArgumentSlot
  result : Variable
  projection : Term
  deriving DecidableEq, Repr

structure Program where
  target : Nat
  fuel : Nat
  declarations : NativeScopedDefaults.State
  types : List (SourceClosureRegions.Expr × Ty)
  arguments : List Argument
  ports : List NativeBorrowWiring.Port
  assignments : List Assignment
  deriving DecidableEq, Repr

def argumentFor (program : Program) (slot : ArgumentSlot) : Option Argument :=
  program.arguments.find? (fun argument => argument.slot == slot)

def assignmentValid (schemas : List Schema) (program : Program) (assignment : Assignment) : Bool :=
  assignment.port.group == program.target && assignment.port.givenBack &&
    assignment.slot.group == program.target && declared program.declarations assignment.result &&
    assignment.slot.level == assignment.port.level &&
    decide (lookup assignment.port.identity program.declarations.symbols = some assignment.result) &&
    ((program.types.find? (fun pair => pair.1 == assignment.port.nativeType)).map Prod.snd) == some assignment.result.type &&
    match argumentFor program assignment.slot with
    | none => false
    | some argument =>
        argument.variable.identity != assignment.result.identity &&
        assignment.projection.type == arrows [argument.variable.type] assignment.result.type &&
        NativeRootExpressions.check schemas program.fuel [] assignment.projection

def check (schemas : List Schema) (program : Program) : Bool :=
  let slots := program.arguments.map (·.slot)
  let variables := program.arguments.map (·.variable.identity)
  let results := program.assignments.map (·.result.identity)
  let sourceTypes := program.types.map Prod.fst
  stateValid program.declarations &&
    sourceTypes.eraseDups.length == sourceTypes.length &&
    slots.eraseDups.length == slots.length && variables.eraseDups.length == variables.length &&
    results.eraseDups.length == results.length &&
    program.arguments.all (fun argument => argument.slot.group == program.target &&
      NativeTypeSyntax.validType program.fuel argument.variable.type && declared program.declarations argument.variable) &&
    program.assignments.all (fun assignment => !decide (assignment.result.identity ∈ variables)) &&
    program.assignments.map (·.port) == program.ports &&
    program.assignments.all (assignmentValid schemas program)

abbrev Arguments (Atom : Ty → Type u) := List (ArgumentSlot × Dynamic Atom)

def suppliedArgument {Atom : Ty → Type u} (slot : ArgumentSlot) (arguments : Arguments Atom) : Option (Dynamic Atom) :=
  (arguments.find? (fun pair => pair.1 == slot)).map Prod.snd

def argumentsValid {Atom : Ty → Type u} (schemas : List Schema) (program : Program)
    (arguments : Arguments Atom) : Bool :=
  decide (arguments.map Prod.fst = program.arguments.map (·.slot)) &&
    (program.arguments.zip arguments).all (fun (declaration, pair) =>
      pair.2.type == declaration.variable.type && validValue schemas program.fuel pair.2)

structure Runtime (Atom : Ty → Type u) where
  values : Table (Dynamic Atom)
  visited : List NativeBorrowWiring.Port

/-- The operand is the supplied whole argument for the exact original slot.
Missing arguments cannot be replaced by a lazy default or an ordinary result.
Only the result runtime value changes; source declarations/defaults are data. -/
def executeAssignment {Atom : Ty → Type u} (schemas : List Schema) (fuel : Nat)
    (arguments : Arguments Atom) (before : Runtime Atom) (assignment : Assignment) : Option (Runtime Atom) := do
  if (lookup assignment.result.identity before.values).isSome then none else do
    let argument ← suppliedArgument assignment.slot arguments
    let value ← NativeRootExpressions.execute schemas fuel assignment.projection [argument]
    if value.type ≠ assignment.result.type then none else
      some ⟨put assignment.result.identity value before.values, before.visited ++ [assignment.port]⟩

def executeAssignments {Atom : Ty → Type u} (schemas : List Schema) (fuel : Nat)
    (arguments : Arguments Atom) : Runtime Atom → List Assignment → Option (Runtime Atom)
  | state, [] => some state
  | state, first :: rest => do
      let state ← executeAssignment schemas fuel arguments state first
      executeAssignments schemas fuel arguments state rest

def run {Atom : Ty → Type u} (schemas : List Schema) (program : Program)
    (arguments : Arguments Atom) (current : Table (Dynamic Atom)) : Option (Runtime Atom) :=
  if check schemas program then
    if argumentsValid schemas program arguments then
      executeAssignments schemas program.fuel arguments ⟨current, []⟩ program.assignments
    else none
  else none

theorem supplied_fresh_values_are_not_overwritten {Atom : Ty → Type u}
    (schemas : List Schema) (fuel : Nat) (arguments : Arguments Atom)
    (before : Runtime Atom) (assignment : Assignment)
    (present : (lookup assignment.result.identity before.values).isSome = true) :
    executeAssignment schemas fuel arguments before assignment = none := by
  simp [executeAssignment, present]

theorem missing_whole_argument_cannot_use_a_default {Atom : Ty → Type u}
    (schemas : List Schema) (fuel : Nat) (arguments : Arguments Atom)
    (before : Runtime Atom) (assignment : Assignment)
    (missing : suppliedArgument assignment.slot arguments = none) :
    executeAssignment schemas fuel arguments before assignment = none := by
  unfold executeAssignment
  split <;> simp_all

theorem a_different_original_argument_roster_is_refused {Atom : Ty → Type u}
    (schemas : List Schema) (program : Program) (arguments : Arguments Atom) (current : Table (Dynamic Atom))
    (different : arguments.map Prod.fst ≠ program.arguments.map (·.slot)) :
    run schemas program arguments current = none := by
  simp [run, argumentsValid, different]

theorem invalid_whole_arguments_are_refused {Atom : Ty → Type u}
    (schemas : List Schema) (program : Program) (arguments : Arguments Atom) (current : Table (Dynamic Atom))
    (invalid : argumentsValid schemas program arguments = false) :
    run schemas program arguments current = none := by
  simp [run, invalid]

theorem successful_run_checks_every_whole_argument {Atom : Ty → Type u}
    (schemas : List Schema) (program : Program) (arguments : Arguments Atom)
    (current : Table (Dynamic Atom)) (after : Runtime Atom)
    (accepted : run schemas program arguments current = some after) :
    argumentsValid schemas program arguments = true := by
  cases valid : argumentsValid schemas program arguments with
  | false => simp [run, valid] at accepted
  | true => rfl

/-- Any produced value came from executing the projection on the supplied
whole argument for this exact slot. This exposes the operand and result; no
registered default or ordinary function result is an alternative operand. -/
theorem successful_assignment_uses_its_supplied_whole_argument {Atom : Ty → Type u}
    (schemas : List Schema) (fuel : Nat) (arguments : Arguments Atom)
    (before after : Runtime Atom) (assignment : Assignment)
    (accepted : executeAssignment schemas fuel arguments before assignment = some after) :
    ∃ argument value,
      suppliedArgument assignment.slot arguments = some argument ∧
      NativeRootExpressions.execute schemas fuel assignment.projection [argument] = some value ∧
      value.type = assignment.result.type ∧
      after.values = put assignment.result.identity value before.values := by
  unfold executeAssignment at accepted
  split at accepted
  · simp at accepted
  · cases supplied : suppliedArgument assignment.slot arguments with
    | none => simp [supplied] at accepted
    | some argument =>
      cases result : NativeRootExpressions.execute schemas fuel assignment.projection [argument] with
      | none => simp [supplied, result] at accepted
      | some value =>
        by_cases same : value.type = assignment.result.type
        · have equal : Runtime.mk (put assignment.result.identity value before.values)
              (before.visited ++ [assignment.port]) = after := by
            simpa [supplied, result, same] using accepted
          subst after
          exact ⟨argument, value, supplied, result, same, rfl⟩
        · simp [supplied, result, same] at accepted

theorem executed_assignment_visits_exact_given_port {Atom : Ty → Type u}
    (schemas : List Schema) (fuel : Nat) (arguments : Arguments Atom)
    (before after : Runtime Atom) (assignment : Assignment)
    (accepted : executeAssignment schemas fuel arguments before assignment = some after) :
    after.visited = before.visited ++ [assignment.port] := by
  unfold executeAssignment at accepted
  split at accepted
  · simp at accepted
  · cases supplied : suppliedArgument assignment.slot arguments with
    | none => simp [supplied] at accepted
    | some argument =>
      cases result : NativeRootExpressions.execute schemas fuel assignment.projection [argument] with
      | none => simp [supplied, result] at accepted
      | some value =>
        by_cases same : value.type = assignment.result.type
        · have equal : Runtime.mk (put assignment.result.identity value before.values)
              (before.visited ++ [assignment.port]) = after := by
            simpa [supplied, result, same] using accepted
          subst after
          rfl
        · simp [supplied, result, same] at accepted

theorem successful_run_visits_every_owned_given_port {Atom : Ty → Type u}
    (schemas : List Schema) (program : Program) (arguments : Arguments Atom)
    (current : Table (Dynamic Atom)) (after : Runtime Atom)
    (accepted : run schemas program arguments current = some after) : after.visited = program.ports := by
  have sequence : ∀ (assignments : List Assignment) (before after : Runtime Atom),
      executeAssignments schemas program.fuel arguments before assignments = some after →
      after.visited = before.visited ++ assignments.map (·.port) := by
    intro assignments
    induction assignments with
    | nil => intro before after accepted; simp [executeAssignments] at accepted; subst after; simp
    | cons first rest ih =>
      intro before after accepted
      cases result : executeAssignment schemas program.fuel arguments before first with
      | none => simp [executeAssignments, result] at accepted
      | some next =>
        have tail : executeAssignments schemas program.fuel arguments next rest = some after := by
          simpa [executeAssignments, result] using accepted
        rw [ih next after tail, executed_assignment_visits_exact_given_port schemas program.fuel arguments before next first result]
        simp [List.append_assoc]
  unfold run at accepted
  split at accepted
  · rename_i checked
    have valid : check schemas program = true := checked
    have ports : program.assignments.map (·.port) = program.ports := by
      by_cases same : program.assignments.map (·.port) = program.ports
      · exact same
      · simp [check, same] at valid
    split at accepted
    · simpa [ports] using sequence program.assignments ⟨current, []⟩ after accepted
    · simp at accepted
  · simp at accepted

end Auths.Support.NativeOwnedBindings
