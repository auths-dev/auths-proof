import Auths.Support.NativeOwnedBindings

/-!
Complete finite ending traces with explicit SSA availability, whole arguments,
current carrier frames and saved backward outputs. No source-version, heap,
loan, original continuation or candidate-ABI adequacy is implied by admission.
All new scripts await final elaboration.
-/
namespace Auths.Support.NativeRootPrograms
open NativeRootPayload NativeRootExpressions NativeScopedDefaults
open NativeDefaultBindings (Table lookup put)
open NativeBorrowWiring (Port Event)
universe u

inductive Role where
  | initialize (symbol : Nat)
  | given (port : Port)
  | frame
  deriving DecidableEq, Repr

def Role.ports : Role → List Port
  | .given port => [port]
  | _ => []

structure Definition where
  role : Role
  result : Variable
  captures : List Variable
  code : Term
  deriving DecidableEq, Repr

inductive Step where
  | define (definition : Definition)
  | consume (port : Port) (variable : Variable)
  | output (index : Nat) (variable : Variable)
  deriving DecidableEq, Repr

def Step.ports : Step → List Port
  | .define definition => definition.role.ports
  | .consume port _ => [port]
  | .output _ _ => []

structure Ending where
  event : Event
  steps : List Step
  deriving DecidableEq, Repr

structure Program where
  target : Nat
  parents : List Nat
  fuel : Nat
  parameters : NativeTypeSyntax.Expr
  predicates : NativeTypeSyntax.Expr
  inputs : List Variable
  forwardSymbols : List Nat
  symbols : Table Variable
  types : List (SourceClosureRegions.Expr × Ty)
  initialization : List Definition
  endings : List Ending
  outputTypes : List Ty
  outputs : List Variable
  deriving DecidableEq, Repr

def typed (available : Table Ty) (variable : Variable) : Bool :=
  decide (lookup variable.identity available = some variable.type)

def portTyped (program : Program) (port : Port) (variable : Variable) : Bool :=
  decide (lookup port.identity program.symbols = some variable) &&
    ((program.types.find? (fun pair => pair.1 == port.nativeType)).map Prod.snd) == some variable.type

def roleValid (program : Program) (result : Variable) : Role → Bool
  | .initialize symbol => decide (symbol ∈ program.forwardSymbols) && decide (lookup symbol program.symbols = some result)
  | .frame => !decide (result.identity ∈ program.symbols.map (·.2.identity))
  | .given port => port.givenBack && portTyped program port result &&
      (port.group == program.target || decide (port.group ∈ program.parents))

def checkDefinition (schemas : List Schema) (program : Program) (available : Table Ty)
    (definition : Definition) : Option (Table Ty) :=
  let ids := definition.captures.map (·.identity)
  if (lookup definition.result.identity available).isNone && roleValid program definition.result definition.role &&
      ids.eraseDups.length == ids.length && definition.captures.all (typed available) &&
      definition.code.type == arrows (definition.captures.map (·.type)) definition.result.type &&
      NativeRootExpressions.check schemas program.fuel [] definition.code then
    some (put definition.result.identity definition.result.type available)
  else none

def checkInitialization (schemas : List Schema) (program : Program) :
    Table Ty → List Definition → Option (Table Ty)
  | available, [] => some available
  | available, definition :: rest => do
      match definition.role with
      | .initialize _ =>
          let available ← checkDefinition schemas program available definition
          checkInitialization schemas program available rest
      | _ => none

structure Checked where
  available : Table Ty
  outputs : List Nat

def checkSteps (schemas : List Schema) (program : Program) : Checked → List Step → Option Checked
  | checked, [] => some checked
  | checked, first :: rest => do
      let next ← match first with
        | .define definition =>
            match definition.role with
            | .initialize _ => none
            | _ => do
                let available ← checkDefinition schemas program checked.available definition
                pure { checked with available }
        | .consume port variable =>
            if !port.givenBack && typed checked.available variable && portTyped program port variable then some checked else none
        | .output index variable =>
            if !decide (index ∈ checked.outputs) && typed checked.available variable &&
                program.outputs[index]? == some variable &&
                program.outputTypes[index]? == some variable.type then
              some { checked with outputs := checked.outputs ++ [index] }
            else none
      checkSteps schemas program next rest

def checkEndings (schemas : List Schema) (program : Program) : Checked → List Ending → Option Checked
  | checked, [] => some checked
  | checked, first :: rest => do
      if first.steps.flatMap Step.ports != first.event.ports then none else do
        let checked ← checkSteps schemas program checked first.steps
        checkEndings schemas program checked rest

def check (schemas : List Schema) (source : NativeBorrowWiring.Program) (program : Program) : Bool :=
  let keys := program.inputs.map (·.identity)
  let sourceTypes := program.types.map Prod.fst
  program.target == source.target && program.endings.map (·.event) == source.events &&
    NativeTypeSyntax.validParameters program.fuel program.parameters &&
    NativeTypeSyntax.validPredicates program.fuel program.predicates &&
    NativeBorrowWiring.check source &&
    keys.eraseDups.length == keys.length && uniqueKeys program.symbols &&
    sourceTypes.eraseDups.length == sourceTypes.length &&
    program.inputs.all (fun variable => NativeTypeSyntax.validType program.fuel variable.type) &&
    match checkInitialization schemas program (program.inputs.map fun variable => (variable.identity, variable.type)) program.initialization with
    | none => false
    | some available =>
        match checkEndings schemas program ⟨available, []⟩ program.endings with
        | none => false
        | some after => program.outputs.map (·.type) == program.outputTypes &&
            program.outputs.all (typed after.available) &&
            after.outputs.length == program.outputTypes.length &&
            (List.range program.outputTypes.length).all (fun index => decide (index ∈ after.outputs))

structure Runtime (Atom : Ty → Type u) where
  values : Table (Dynamic Atom)
  outputs : Table (Dynamic Atom)
  visited : List Port

def executeDefinition {Atom : Ty → Type u} (schemas : List Schema) (fuel : Nat)
    (values : Table (Dynamic Atom)) (definition : Definition) : Option (Table (Dynamic Atom)) := do
  if (lookup definition.result.identity values).isSome then none else do
    let captures ← definition.captures.mapM (fun variable => lookup variable.identity values)
    let result ← NativeRootExpressions.execute schemas fuel definition.code captures
    if result.type ≠ definition.result.type then none else
      some (put definition.result.identity result values)

def executeInitialization {Atom : Ty → Type u} (schemas : List Schema) (fuel : Nat) :
    Table (Dynamic Atom) → List Definition → Option (Table (Dynamic Atom))
  | values, [] => some values
  | values, first :: rest => do
      let values ← executeDefinition schemas fuel values first
      executeInitialization schemas fuel values rest

def executeStep {Atom : Ty → Type u} (schemas : List Schema) (program : Program)
    (before : Runtime Atom) : Step → Option (Runtime Atom)
  | .define definition => do
      let values ← executeDefinition schemas program.fuel before.values definition
      pure { before with values, visited := before.visited ++ definition.role.ports }
  | .consume port variable => do
      let value ← lookup variable.identity before.values
      if value.type ≠ variable.type then none else
        some { before with visited := before.visited ++ [port] }
  | .output index variable => do
      if (lookup index before.outputs).isSome then none else do
        let value ← lookup variable.identity before.values
        if value.type ≠ variable.type ∨ program.outputTypes[index]? ≠ some variable.type ∨
            program.outputs[index]? ≠ some variable then none else
          some { before with outputs := put index value before.outputs }

def executeSteps {Atom : Ty → Type u} (schemas : List Schema) (program : Program) :
    Runtime Atom → List Step → Option (Runtime Atom)
  | state, [] => some state
  | state, first :: rest => do
      let state ← executeStep schemas program state first
      executeSteps schemas program state rest

def executeEndings {Atom : Ty → Type u} (schemas : List Schema) (program : Program) :
    Runtime Atom → List Ending → Option (Runtime Atom)
  | state, [] => some state
  | state, first :: rest => do
      let state ← executeSteps schemas program state first.steps
      executeEndings schemas program state rest

def argumentsValid {Atom : Ty → Type u} (schemas : List Schema) (program : Program) (arguments : List (Dynamic Atom)) : Bool :=
  arguments.map (·.type) == program.inputs.map (·.type) && arguments.all (validValue schemas program.fuel)

def run {Atom : Ty → Type u} (schemas : List Schema) (source : NativeBorrowWiring.Program)
    (program : Program) (arguments : List (Dynamic Atom)) : Option (Runtime Atom) := do
  if check schemas source program && argumentsValid schemas program arguments then
    let initial := program.inputs.zip arguments |>.map (fun (variable, value) => (variable.identity, value))
    let values ← executeInitialization schemas program.fuel initial program.initialization
    executeEndings schemas program ⟨values, [], []⟩ program.endings
  else none

def results {Atom : Ty → Type u} (program : Program) (after : Runtime Atom) : Option (List (Dynamic Atom)) :=
  (List.range program.outputTypes.length).mapM (fun index => lookup index after.outputs)

def runValues {Atom : Ty → Type u} (schemas : List Schema) (source : NativeBorrowWiring.Program)
    (program : Program) (arguments : List (Option (Dynamic Atom))) : Option (List (Dynamic Atom)) := do
  let arguments ← arguments.mapM id
  let after ← run schemas source program arguments
  results program after

/-- The native simplifier erases a singleton result tuple. This wrapper only
packages independently computed carrier outputs for comparison to native code. -/
def tupleResults {Atom : Ty → Type u} (type : Ty) (outputs : List (Option (Dynamic Atom))) : Option (Dynamic Atom) := do
  let outputs ← outputs.mapM id
  match outputs with
  | [one] => some one
  | _ => some (.constructor type none outputs)

def resultType (payload : Ty) : Ty :=
  .node .adt [.node .builtin [.natural 0], .node .arguments
    [.node .types [payload], .node .constants [], .node .traits []]]

/-- Decode the actual native forward envelope and complete result tuple.
Failure, malformed tags/types/field lists and truncated closure rosters refuse. -/
def returnedFields {Atom : Ty → Type u} (schemas : List Schema) (mayFail : Bool) (payload : Ty)
    (result : Dynamic Atom) : Option (List (Dynamic Atom)) := do
  let value ← if mayFail then
      match result with
      | .constructor type (some 0) [value] => if type = resultType payload then some value else none
      | _ => none
    else some result
  match value with
  | .constructor type none values =>
      if type ≠ payload then none else do
        let expected ← fields schemas payload none
        if values.map Dynamic.type = expected then some values else none
  | _ => none

def runReturned {Atom : Ty → Type u} (schemas : List Schema) (fuel : Nat)
    (function : Term) (mayFail : Bool) (payload : Ty) (index : Nat)
    (forward backward : List (Option (Dynamic Atom))) : Option (Dynamic Atom) := do
  let result ← executeValues schemas fuel function forward
  let values ← returnedFields schemas mayFail payload result
  let closure ← values[index]?
  let arguments ← backward.mapM id
  applyReturned schemas fuel closure arguments

def runForward {Atom : Ty → Type u} (schemas : List Schema) (fuel : Nat)
    (function : Term) (mayFail : Bool) (payload : Ty)
    (arguments : List (Option (Dynamic Atom))) : Option (Dynamic Atom) := do
  let result ← executeValues schemas fuel function arguments
  let values ← returnedFields schemas mayFail payload result
  values[0]?

theorem a_native_failure_cannot_be_a_successful_closure_roster {Atom : Ty → Type u}
    (schemas : List Schema) (payload : Ty) (error : Dynamic Atom) :
    returnedFields schemas true payload (.constructor (resultType payload) (some 1) [error]) = none := by rfl

theorem a_missing_returned_closure_cannot_use_a_separate_factory {Atom : Ty → Type u}
    (schemas : List Schema) (fuel : Nat) (function : Term) (mayFail : Bool) (payload : Ty) (index : Nat)
    (forward backward : List (Option (Dynamic Atom))) (result : Dynamic Atom) (values : List (Dynamic Atom))
    (evaluated : executeValues schemas fuel function forward = some result)
    (decoded : returnedFields schemas mayFail payload result = some values)
    (missing : values[index]? = none) :
    runReturned schemas fuel function mayFail payload index forward backward = none := by
  simp [runReturned, evaluated, decoded, missing]

theorem a_returned_closure_invocation_uses_the_actual_captured_scopes {Atom : Ty → Type u}
    (schemas : List Schema) (fuel : Nat) (function : Term) (mayFail : Bool) (payload : Ty)
    (index : Nat) (forward backward : List (Option (Dynamic Atom)))
    (result : Dynamic Atom) (values arguments : List (Dynamic Atom))
    (type : Ty) (pattern : Pattern) (body : Term) (captured : List (List (Dynamic Atom)))
    (evaluated : executeValues schemas fuel function forward = some result)
    (decoded : returnedFields schemas mayFail payload result = some values)
    (selected : values[index]? = some (.closure type pattern body captured))
    (inputs : backward.mapM id = some arguments) :
    runReturned schemas fuel function mayFail payload index forward backward =
      applyReturned schemas fuel (.closure type pattern body captured) arguments := by
  simp [runReturned, evaluated, decoded, selected, inputs]

theorem a_native_failure_cannot_produce_a_forward_capture {Atom : Ty → Type u}
    (schemas : List Schema) (fuel : Nat) (function : Term) (payload : Ty)
    (arguments : List (Option (Dynamic Atom))) (error : Dynamic Atom)
    (failed : executeValues schemas fuel function arguments =
      some (.constructor (resultType payload) (some 1) [error])) :
    runForward schemas fuel function true payload arguments = none := by
  simp [runForward, failed, returnedFields]

theorem a_native_failure_cannot_invoke_a_backward_closure {Atom : Ty → Type u}
    (schemas : List Schema) (fuel : Nat) (function : Term) (payload : Ty) (index : Nat)
    (forward backward : List (Option (Dynamic Atom))) (error : Dynamic Atom)
    (failed : executeValues schemas fuel function forward =
      some (.constructor (resultType payload) (some 1) [error])) :
    runReturned schemas fuel function true payload index forward backward = none := by
  simp [runReturned, failed, returnedFields]

def visitedPorts (program : Program) : List Port :=
  program.endings.flatMap (fun ending => ending.steps.flatMap Step.ports)

theorem a_future_declared_variable_is_not_an_available_value {Atom : Ty → Type u}
    (schemas : List Schema) (fuel : Nat) (values : Table (Dynamic Atom))
    (definition : Definition) (first : Variable) (rest : List Variable)
    (captures : definition.captures = first :: rest) (missing : lookup first.identity values = none) :
    executeDefinition schemas fuel values definition = none := by
  unfold executeDefinition
  split <;> simp_all

/-- SSA materialization cannot change a value that was already available.
This preserves distinct source versions even when their storage coordinates
coincide. It does not equate either version to a Rust heap observation. -/
theorem materialization_preserves_existing_source_versions {Atom : Ty → Type u}
    (schemas : List Schema) (fuel : Nat) (before after : Table (Dynamic Atom))
    (definition : Definition) (observed : Nat) (value : Dynamic Atom)
    (present : lookup observed before = some value)
    (accepted : executeDefinition schemas fuel before definition = some after) :
    lookup observed after = some value := by
  cases target : lookup definition.result.identity before with
  | some old => simp [executeDefinition, target] at accepted
  | none =>
    cases captured : definition.captures.mapM (fun variable => lookup variable.identity before) with
    | none => simp [executeDefinition, target, captured] at accepted
    | some arguments =>
      cases evaluated : NativeRootExpressions.execute schemas fuel definition.code arguments with
      | none => simp [executeDefinition, target, captured, evaluated] at accepted
      | some result =>
        by_cases correct : result.type = definition.result.type
        · have equal : put definition.result.identity result before = after := by
            simpa [executeDefinition, target, captured, evaluated, correct] using accepted
          have separate : observed ≠ definition.result.identity := by
            intro same
            have impossible := present
            rw [same, target] at impossible
            contradiction
          rw [← equal, NativeDefaultBindings.lookup_put_other observed definition.result.identity result before separate]
          exact present
        · simp [executeDefinition, target, captured, evaluated, correct] at accepted

theorem malformed_whole_arguments_are_refused {Atom : Ty → Type u}
    (schemas : List Schema) (source : NativeBorrowWiring.Program) (program : Program) (arguments : List (Dynamic Atom))
    (invalid : argumentsValid schemas program arguments = false) : run schemas source program arguments = none := by
  simp [run, invalid]

theorem consume_preserves_current_values_and_saved_outputs {Atom : Ty → Type u}
    (schemas : List Schema) (program : Program) (before after : Runtime Atom) (port : Port) (variable : Variable)
    (accepted : executeStep schemas program before (.consume port variable) = some after) :
    after.values = before.values ∧ after.outputs = before.outputs := by
  cases found : lookup variable.identity before.values with
  | none => simp [executeStep, found] at accepted
  | some value =>
    by_cases same : value.type = variable.type
    · have equal : { before with visited := before.visited ++ [port] } = after := by
        simpa [executeStep, found, same] using accepted
      subst after
      exact ⟨rfl, rfl⟩
    · simp [executeStep, found, same] at accepted

theorem executed_step_visits_exact_ports {Atom : Ty → Type u}
    (schemas : List Schema) (program : Program) (before after : Runtime Atom) (step : Step)
    (accepted : executeStep schemas program before step = some after) :
    after.visited = before.visited ++ step.ports := by
  cases step with
  | define definition =>
    cases found : executeDefinition schemas program.fuel before.values definition with
    | none => simp [executeStep, found] at accepted
    | some values =>
      have equal : { before with values := values, visited := before.visited ++ definition.role.ports } = after := by
        simpa [executeStep, found] using accepted
      subst after
      rfl
  | consume port variable =>
    cases found : lookup variable.identity before.values with
    | none => simp [executeStep, found] at accepted
    | some value =>
      by_cases same : value.type = variable.type
      · have equal : { before with visited := before.visited ++ [port] } = after := by
          simpa [executeStep, found, same] using accepted
        subst after
        rfl
      · simp [executeStep, found, same] at accepted
  | output index variable =>
    cases saved : lookup index before.outputs with
    | some value => simp [executeStep, saved] at accepted
    | none =>
      cases found : lookup variable.identity before.values with
      | none => simp [executeStep, saved, found] at accepted
      | some value =>
        by_cases bad : value.type ≠ variable.type ∨ program.outputTypes[index]? ≠ some variable.type ∨
            program.outputs[index]? ≠ some variable
        · simp [executeStep, saved, found, bad] at accepted
        · have equal : { before with outputs := put index value before.outputs } = after := by
            simpa [executeStep, saved, found, bad] using accepted
          subst after
          simp [Step.ports]

theorem executed_steps_visit_exact_ports {Atom : Ty → Type u}
    (schemas : List Schema) (program : Program) (before after : Runtime Atom) (steps : List Step)
    (accepted : executeSteps schemas program before steps = some after) :
    after.visited = before.visited ++ steps.flatMap Step.ports := by
  induction steps generalizing before with
  | nil => simp [executeSteps] at accepted; subst after; simp
  | cons first rest ih =>
    cases result : executeStep schemas program before first with
    | none => simp [executeSteps, result] at accepted
    | some next =>
      have tail : executeSteps schemas program next rest = some after := by
        simpa [executeSteps, result] using accepted
      rw [ih next tail, executed_step_visits_exact_ports schemas program before next first result]
      simp [List.append_assoc]

theorem executed_endings_visit_exact_ports {Atom : Ty → Type u}
    (schemas : List Schema) (program : Program) (before after : Runtime Atom) (endings : List Ending)
    (accepted : executeEndings schemas program before endings = some after) :
    after.visited = before.visited ++ endings.flatMap (fun ending => ending.steps.flatMap Step.ports) := by
  induction endings generalizing before with
  | nil => simp [executeEndings] at accepted; subst after; simp
  | cons first rest ih =>
    cases result : executeSteps schemas program before first.steps with
    | none => simp [executeEndings, result] at accepted
    | some next =>
      have tail : executeEndings schemas program next rest = some after := by
        simpa [executeEndings, result] using accepted
      rw [ih next tail, executed_steps_visit_exact_ports schemas program before next first.steps result]
      simp [List.append_assoc]

theorem successful_run_visits_every_program_port {Atom : Ty → Type u}
    (schemas : List Schema) (source : NativeBorrowWiring.Program) (program : Program)
    (arguments : List (Dynamic Atom)) (after : Runtime Atom)
    (accepted : run schemas source program arguments = some after) : after.visited = visitedPorts program := by
  by_cases checked : (check schemas source program && argumentsValid schemas program arguments) = true
  · let initial := program.inputs.zip arguments |>.map (fun (variable, value) => (variable.identity, value))
    cases initialized : executeInitialization schemas program.fuel initial program.initialization with
    | none => simp [run, checked, initial, initialized] at accepted
    | some values =>
      have executed : executeEndings schemas program ⟨values, [], []⟩ program.endings = some after := by
        simpa [run, checked, initial, initialized] using accepted
      simpa [visitedPorts] using executed_endings_visit_exact_ports schemas program ⟨values, [], []⟩ after program.endings executed
  · simp [run, checked] at accepted

theorem executed_step_preserves_existing_source_versions {Atom : Ty → Type u}
    (schemas : List Schema) (program : Program) (before after : Runtime Atom) (step : Step)
    (observed : Nat) (value : Dynamic Atom) (present : lookup observed before.values = some value)
    (accepted : executeStep schemas program before step = some after) :
    lookup observed after.values = some value := by
  cases step with
  | define definition =>
    cases built : executeDefinition schemas program.fuel before.values definition with
    | none => simp [executeStep, built] at accepted
    | some values =>
      have equal : { before with values, visited := before.visited ++ definition.role.ports } = after := by
        simpa [executeStep, built] using accepted
      subst after
      exact materialization_preserves_existing_source_versions schemas program.fuel before.values values definition observed value present built
  | consume port variable =>
    rw [(consume_preserves_current_values_and_saved_outputs schemas program before after port variable accepted).1]
    exact present
  | output index variable =>
    cases saved : lookup index before.outputs with
    | some old => simp [executeStep, saved] at accepted
    | none =>
      cases found : lookup variable.identity before.values with
      | none => simp [executeStep, saved, found] at accepted
      | some output =>
        by_cases invalid : output.type ≠ variable.type ∨ program.outputTypes[index]? ≠ some variable.type ∨
            program.outputs[index]? ≠ some variable
        · simp [executeStep, saved, found, invalid] at accepted
        · have equal : { before with outputs := put index output before.outputs } = after := by
            simpa [executeStep, saved, found, invalid] using accepted
          subst after
          exact present

theorem executed_steps_preserve_existing_source_versions {Atom : Ty → Type u}
    (schemas : List Schema) (program : Program) (before after : Runtime Atom) (steps : List Step)
    (observed : Nat) (value : Dynamic Atom) (present : lookup observed before.values = some value)
    (accepted : executeSteps schemas program before steps = some after) :
    lookup observed after.values = some value := by
  induction steps generalizing before with
  | nil => simp [executeSteps] at accepted; subst after; exact present
  | cons first rest ih =>
    cases executed : executeStep schemas program before first with
    | none => simp [executeSteps, executed] at accepted
    | some next =>
      have tail : executeSteps schemas program next rest = some after := by
        simpa [executeSteps, executed] using accepted
      exact ih next
        (executed_step_preserves_existing_source_versions schemas program before next first observed value present executed) tail

theorem executed_endings_preserve_existing_source_versions {Atom : Ty → Type u}
    (schemas : List Schema) (program : Program) (before after : Runtime Atom) (endings : List Ending)
    (observed : Nat) (value : Dynamic Atom) (present : lookup observed before.values = some value)
    (accepted : executeEndings schemas program before endings = some after) :
    lookup observed after.values = some value := by
  induction endings generalizing before with
  | nil => simp [executeEndings] at accepted; subst after; exact present
  | cons first rest ih =>
    cases executed : executeSteps schemas program before first.steps with
    | none => simp [executeEndings, executed] at accepted
    | some next =>
      have tail : executeEndings schemas program next rest = some after := by
        simpa [executeEndings, executed] using accepted
      exact ih next
        (executed_steps_preserve_existing_source_versions schemas program before next first.steps observed value present executed) tail

/-- Saved whole outputs are immutable snapshots. Later carrier-frame writes
may extend runtime values but cannot revise an output saved at an earlier
source ending. This is an invariant of the explicit runtime, not yet a Rust
continuation refinement. -/
theorem executed_step_preserves_saved_output_snapshots {Atom : Ty → Type u}
    (schemas : List Schema) (program : Program) (before after : Runtime Atom) (step : Step)
    (observed : Nat) (value : Dynamic Atom) (present : lookup observed before.outputs = some value)
    (accepted : executeStep schemas program before step = some after) :
    lookup observed after.outputs = some value := by
  cases step with
  | define definition =>
    cases built : executeDefinition schemas program.fuel before.values definition with
    | none => simp [executeStep, built] at accepted
    | some values =>
      have equal : { before with values, visited := before.visited ++ definition.role.ports } = after := by
        simpa [executeStep, built] using accepted
      subst after
      exact present
  | consume port variable =>
    rw [(consume_preserves_current_values_and_saved_outputs schemas program before after port variable accepted).2]
    exact present
  | output index variable =>
    cases saved : lookup index before.outputs with
    | some old => simp [executeStep, saved] at accepted
    | none =>
      cases found : lookup variable.identity before.values with
      | none => simp [executeStep, saved, found] at accepted
      | some output =>
        by_cases invalid : output.type ≠ variable.type ∨ program.outputTypes[index]? ≠ some variable.type ∨
            program.outputs[index]? ≠ some variable
        · simp [executeStep, saved, found, invalid] at accepted
        · have equal : { before with outputs := put index output before.outputs } = after := by
            simpa [executeStep, saved, found, invalid] using accepted
          have separate : observed ≠ index := by
            intro same
            have impossible := present
            rw [same, saved] at impossible
            contradiction
          subst after
          rw [NativeDefaultBindings.lookup_put_other observed index output before.outputs separate]
          exact present

theorem executed_steps_preserve_saved_output_snapshots {Atom : Ty → Type u}
    (schemas : List Schema) (program : Program) (before after : Runtime Atom) (steps : List Step)
    (observed : Nat) (value : Dynamic Atom) (present : lookup observed before.outputs = some value)
    (accepted : executeSteps schemas program before steps = some after) :
    lookup observed after.outputs = some value := by
  induction steps generalizing before with
  | nil => simp [executeSteps] at accepted; subst after; exact present
  | cons first rest ih =>
    cases executed : executeStep schemas program before first with
    | none => simp [executeSteps, executed] at accepted
    | some next =>
      have tail : executeSteps schemas program next rest = some after := by
        simpa [executeSteps, executed] using accepted
      exact ih next
        (executed_step_preserves_saved_output_snapshots schemas program before next first observed value present executed) tail

theorem executed_endings_preserve_saved_output_snapshots {Atom : Ty → Type u}
    (schemas : List Schema) (program : Program) (before after : Runtime Atom) (endings : List Ending)
    (observed : Nat) (value : Dynamic Atom) (present : lookup observed before.outputs = some value)
    (accepted : executeEndings schemas program before endings = some after) :
    lookup observed after.outputs = some value := by
  induction endings generalizing before with
  | nil => simp [executeEndings] at accepted; subst after; exact present
  | cons first rest ih =>
    cases executed : executeSteps schemas program before first.steps with
    | none => simp [executeEndings, executed] at accepted
    | some next =>
      have tail : executeEndings schemas program next rest = some after := by
        simpa [executeEndings, executed] using accepted
      exact ih next
        (executed_steps_preserve_saved_output_snapshots schemas program before next first.steps observed value present executed) tail

def OutputsTyped {Atom : Ty → Type u} (program : Program) (state : Runtime Atom) : Prop :=
  ∀ index value, lookup index state.outputs = some value → program.outputTypes[index]? = some value.type

theorem executed_step_preserves_original_output_types {Atom : Ty → Type u}
    (schemas : List Schema) (program : Program) (before after : Runtime Atom) (step : Step)
    (typed : OutputsTyped program before)
    (accepted : executeStep schemas program before step = some after) : OutputsTyped program after := by
  cases step with
  | define definition =>
    cases built : executeDefinition schemas program.fuel before.values definition with
    | none => simp [executeStep, built] at accepted
    | some values =>
      have equal : { before with values, visited := before.visited ++ definition.role.ports } = after := by
        simpa [executeStep, built] using accepted
      subst after
      exact typed
  | consume port variable =>
    have unchanged := (consume_preserves_current_values_and_saved_outputs schemas program before after port variable accepted).2
    intro index value present
    rw [unchanged] at present
    exact typed index value present
  | output index variable =>
    cases saved : lookup index before.outputs with
    | some old => simp [executeStep, saved] at accepted
    | none =>
      cases found : lookup variable.identity before.values with
      | none => simp [executeStep, saved, found] at accepted
      | some output =>
        by_cases invalid : output.type ≠ variable.type ∨ program.outputTypes[index]? ≠ some variable.type ∨
            program.outputs[index]? ≠ some variable
        · simp [executeStep, saved, found, invalid] at accepted
        · have equal : { before with outputs := put index output before.outputs } = after := by
            simpa [executeStep, saved, found, invalid] using accepted
          have actualType : output.type = variable.type := not_not.mp (not_or.mp invalid).1
          have expectedType : program.outputTypes[index]? = some variable.type :=
            not_not.mp (not_or.mp (not_or.mp invalid).2).1
          subst after
          intro observed value present
          by_cases same : observed = index
          · subst observed
            have actual : output = value := by
              simpa only [NativeDefaultBindings.lookup_put_self, Option.some.injEq] using present
            subst value
            simpa [actualType] using expectedType
          · rw [NativeDefaultBindings.lookup_put_other observed index output before.outputs same] at present
            exact typed observed value present

theorem executed_steps_preserve_original_output_types {Atom : Ty → Type u}
    (schemas : List Schema) (program : Program) (before after : Runtime Atom) (steps : List Step)
    (typed : OutputsTyped program before)
    (accepted : executeSteps schemas program before steps = some after) : OutputsTyped program after := by
  induction steps generalizing before with
  | nil => simp [executeSteps] at accepted; subst after; exact typed
  | cons first rest ih =>
    cases executed : executeStep schemas program before first with
    | none => simp [executeSteps, executed] at accepted
    | some next =>
      have tail : executeSteps schemas program next rest = some after := by
        simpa [executeSteps, executed] using accepted
      exact ih next (executed_step_preserves_original_output_types schemas program before next first typed executed) tail

theorem executed_endings_preserve_original_output_types {Atom : Ty → Type u}
    (schemas : List Schema) (program : Program) (before after : Runtime Atom) (endings : List Ending)
    (typed : OutputsTyped program before)
    (accepted : executeEndings schemas program before endings = some after) : OutputsTyped program after := by
  induction endings generalizing before with
  | nil => simp [executeEndings] at accepted; subst after; exact typed
  | cons first rest ih =>
    cases executed : executeSteps schemas program before first.steps with
    | none => simp [executeEndings, executed] at accepted
    | some next =>
      have tail : executeEndings schemas program next rest = some after := by
        simpa [executeEndings, executed] using accepted
      exact ih next (executed_steps_preserve_original_output_types schemas program before next first.steps typed executed) tail

theorem successful_run_retains_every_saved_original_output_type {Atom : Ty → Type u}
    (schemas : List Schema) (source : NativeBorrowWiring.Program) (program : Program)
    (arguments : List (Dynamic Atom)) (after : Runtime Atom)
    (accepted : run schemas source program arguments = some after) : OutputsTyped program after := by
  by_cases admitted : (check schemas source program && argumentsValid schemas program arguments) = true
  · let initial := program.inputs.zip arguments |>.map (fun (variable, value) => (variable.identity, value))
    cases initialized : executeInitialization schemas program.fuel initial program.initialization with
    | none => simp [run, admitted, initial, initialized] at accepted
    | some values =>
      have executed : executeEndings schemas program ⟨values, [], []⟩ program.endings = some after := by
        simpa [run, admitted, initial, initialized] using accepted
      apply executed_endings_preserve_original_output_types schemas program ⟨values, [], []⟩ after program.endings _ executed
      intro index value present
      simp [lookup] at present
  · simp [run, admitted] at accepted

end Auths.Support.NativeRootPrograms
