import Auths.Support.NativeBorrowDefaults
import Auths.Support.NativeBorrowWiring
import Auths.Support.NativeBorrowView

/-!
Pure-data execution of selected-level synthesis endings. Incoming values are
backward-interface parameters, not ordinary Rust function results. A foreign
ancestor synthesis return or higher input may activate its current default. Every
consumed port is read, including foreign parent ports. Current symbolic
versions remain distinct. Native heap/loan ending and source adequacy remain
required; this interpreter is not a replacement for those relations.
All new scripts await final elaboration.
-/
namespace Auths.Support.NativeBorrowExecution
open SourceClosureRegions BorrowProjection BorrowTransport
open NativeBorrowDefaults NativeBorrowWiring
universe u

structure Access where
  candidateShape : Shape
  selected : Plan candidateShape
  nativeShape : Shape
  transport : Change candidateShape nativeShape
  mapping : List (Nat × Nat)

def Access.nativePlan (access : Access) : Plan access.nativeShape :=
  mapPlan access.transport access.selected

def Access.ofRecipe (recipe : Recipe) (mapping : List (Nat × Nat)) : Access :=
  ⟨recipe.candidateShape, recipe.selected, recipe.nativeShape, recipe.transport, mapping⟩

inductive Operation where
  | receive (port : Port) (access : Access)
  | foreignDefault (port : Port) (recipe : Recipe) (mapping : List (Nat × Nat))
  | emit (port : Port) (access : Access)
  | observe (port : Port) (access : Access)

def Operation.port : Operation → Port
  | .receive port _ | .foreignDefault port _ _ | .emit port _ | .observe port _ => port

def Operation.access : Operation → Access
  | .receive _ access | .emit _ access | .observe _ access => access
  | .foreignDefault _ recipe mapping => .ofRecipe recipe mapping

structure Ending where
  abstraction : Nat
  group : Nat
  input : Bool
  level : Nat
  operations : List Operation

structure Program where
  target : Nat
  parents : List Nat
  fuel : Nat
  endings : List Ending

def accessValid (fuel : Nat) (port : Port) (access : Access) : Bool :=
  validMap access.mapping && metadataMatch access.mapping fuel access.transport &&
  decide (NativeBorrowView.rootType fuel access.nativeShape = some port.nativeType) &&
  decide (NativeBorrowProtocol.typeShape fuel port.nativeType = some port.payloadType)

def operationValid (program : Program) (ending : Ending) (operation : Operation) : Bool :=
  let port := operation.port
  port.abstraction == ending.abstraction && port.group == ending.group &&
  port.inputAbstraction == ending.input && port.level == ending.level &&
  accessValid program.fuel port operation.access &&
  match operation with
  | .receive port _ => port.group == program.target && externalInput port
  | .emit port _ => port.group == program.target && externalOutput port
  | .foreignDefault port recipe _ =>
      port.group != program.target && decide (port.group ∈ program.parents) &&
      (!port.inputAbstraction || decide (port.level > 0)) && port.givenBack && port.identity == recipe.target
  | .observe port _ =>
      port.group != program.target && decide (port.group ∈ program.parents) &&
      !port.givenBack

def check (program : Program) : Bool :=
  !program.endings.isEmpty && program.endings.all fun ending =>
    ending.operations.all (operationValid program ending)

structure State (Atom : Expr → Type u) where
  current : Current Atom
  outputs : List (Entry Atom)
  visited : List Port

def readNative {Atom : Expr → Type u} (access : Access) (identity : Nat) (current : Current Atom) :
    Option (View Atom access.nativePlan) :=
  (readCurrent current (.symbolic identity) access.candidateShape access.selected).map
    (forwardView access.transport access.selected)

def bindIncoming {Atom : Expr → Type u} (access : Access) (identity : Nat)
    (current incoming : Current Atom) : Option (Current Atom) := do
  let actual ← readCurrent incoming (.symbolic identity) access.nativeShape access.nativePlan
  let value := backwardView access.transport access.selected actual
  pure fun key => if key = .symbolic identity then
    some ⟨access.candidateShape, access.selected, value⟩ else current key

def executeValueOperation {Atom : Expr → Type u} (incoming : Current Atom)
    (state : State Atom) (operation : Operation) : Option (State Atom) :=
  match operation with
    | .receive port access => do
        let current ← bindIncoming access port.identity state.current incoming
        pure { state with current }
    | .foreignDefault _ recipe _ => do
        let value ← evaluate recipe state.current
        pure { state with current := recordCurrent recipe state.current value }
    | .emit port access => do
        let value ← readNative access port.identity state.current
        pure { state with outputs := state.outputs ++ [⟨access.nativeShape, access.nativePlan, value⟩] }
    | .observe port access => do
        let _ ← readNative access port.identity state.current
        pure state

def executeOperation {Atom : Expr → Type u} (incoming : Current Atom)
    (state : State Atom) (operation : Operation) : Option (State Atom) :=
  (executeValueOperation incoming state operation).map fun next =>
    { next with visited := state.visited ++ [operation.port] }

def executeOperations {Atom : Expr → Type u} (incoming : Current Atom) :
    State Atom → List Operation → Option (State Atom)
  | state, [] => some state
  | state, first :: rest => do
      let state ← executeOperation incoming state first
      executeOperations incoming state rest

def executeEndings {Atom : Expr → Type u} (incoming : Current Atom) :
    State Atom → List Ending → Option (State Atom)
  | state, [] => some state
  | state, first :: rest => do
      let state ← executeOperations incoming state first.operations
      executeEndings incoming state rest

def run {Atom : Expr → Type u} (program : Program) (current incoming : Current Atom) : Option (State Atom) :=
  if check program then executeEndings incoming ⟨current, [], []⟩ program.endings else none

/-- Entry through the actual forward preparation, without fixed symbolic or
borrow keys and without supplied backward results. Full Rust/native adequacy
and unsupported continuation roles remain separate requirements. -/
def runPrepared {Atom : Expr → Type u} (forward : NativeCaptureValue.Program)
    (program : Program) (inputs : List (Datum Atom)) (incoming : Current Atom) : Option (State Atom) := do
  let current ← prepareCurrent forward inputs
  run program current incoming

theorem prepared_run_uses_exact_current {Atom : Expr → Type u}
    (forward : NativeCaptureValue.Program) (program : Program) (inputs : List (Datum Atom))
    (incoming : Current Atom) (value : Datum Atom) (state : NativeCaptureValue.State Atom)
    (prepared : NativeCaptureValue.runWithState forward inputs = some (value, state)) :
    runPrepared forward program inputs incoming = run program (currentOfForward forward state) incoming := by
  simp [runPrepared, prepared_current_uses_exact_forward_state forward inputs value state prepared]

theorem failed_forward_refuses_execution {Atom : Expr → Type u}
    (forward : NativeCaptureValue.Program) (program : Program) (inputs : List (Datum Atom))
    (incoming : Current Atom) (failed : NativeCaptureValue.runWithState forward inputs = none) :
    runPrepared forward program inputs incoming = none := by
  simp [runPrepared, failed_forward_preparation_refuses_current forward inputs failed]

theorem invalid_program_is_refused {Atom : Expr → Type u} (program : Program)
    (current incoming : Current Atom) (invalid : check program = false) :
    run program current incoming = none := by simp [run, invalid]

theorem incoming_value_is_not_replaced_by_a_default {Atom : Expr → Type u}
    (access : Access) (identity : Nat) (current incoming : Current Atom)
    (missing : incoming (.symbolic identity) = none) :
    bindIncoming access identity current incoming = none := by
  simp [bindIncoming, readCurrent, missing]

theorem observed_value_is_required {Atom : Expr → Type u} (port : Port) (access : Access)
    (state : State Atom) (incoming : Current Atom)
    (missing : readNative access port.identity state.current = none) :
    executeOperation incoming state (.observe port access) = none := by
  simp [executeOperation, executeValueOperation, missing]

theorem executed_operation_visits_its_exact_port {Atom : Expr → Type u}
    (incoming : Current Atom) (before after : State Atom) (operation : Operation)
    (accepted : executeOperation incoming before operation = some after) :
    after.visited = before.visited ++ [operation.port] := by
  cases result : executeValueOperation incoming before operation with
  | none => simp [executeOperation, result] at accepted
  | some next =>
      have same : { next with visited := before.visited ++ [operation.port] } = after := by
        simpa [executeOperation, result] using accepted
      subst after
      rfl

theorem executed_operations_visit_every_port {Atom : Expr → Type u}
    (incoming : Current Atom) (before after : State Atom) (operations : List Operation)
    (accepted : executeOperations incoming before operations = some after) :
    after.visited = before.visited ++ operations.map Operation.port := by
  induction operations generalizing before with
  | nil =>
      have same : before = after := Option.some.inj accepted
      subst after
      simp
  | cons first rest ih =>
      cases result : executeOperation incoming before first with
      | none => simp [executeOperations, result] at accepted
      | some next =>
          have tail : executeOperations incoming next rest = some after := by
            simpa [executeOperations, result] using accepted
          rw [ih next tail, executed_operation_visits_its_exact_port incoming before next first result]
          simp [List.append_assoc]

theorem executed_endings_visit_every_port {Atom : Expr → Type u}
    (incoming : Current Atom) (before after : State Atom) (endings : List Ending)
    (accepted : executeEndings incoming before endings = some after) :
    after.visited = before.visited ++ endings.flatMap (fun ending => ending.operations.map Operation.port) := by
  induction endings generalizing before with
  | nil =>
      have same : before = after := Option.some.inj accepted
      subst after
      simp
  | cons first rest ih =>
      cases result : executeOperations incoming before first.operations with
      | none => simp [executeEndings, result] at accepted
      | some next =>
          have tail : executeEndings incoming next rest = some after := by
            simpa [executeEndings, result] using accepted
          rw [ih next tail, executed_operations_visit_every_port incoming before next first.operations result]
          simp [List.append_assoc]

theorem successful_run_visits_every_port {Atom : Expr → Type u} (program : Program)
    (current incoming : Current Atom) (after : State Atom)
    (accepted : run program current incoming = some after) :
    after.visited = program.endings.flatMap (fun ending => ending.operations.map Operation.port) := by
  cases valid : check program with
  | false => simp [run, valid] at accepted
  | true =>
      have executed : executeEndings incoming ⟨current, [], []⟩ program.endings = some after := by
        simpa [run, valid] using accepted
      simpa using executed_endings_visit_every_port incoming ⟨current, [], []⟩ after program.endings executed

end Auths.Support.NativeBorrowExecution
