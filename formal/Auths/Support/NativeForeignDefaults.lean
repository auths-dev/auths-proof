import Auths.Support.NativeScopedDefaults
import Auths.Support.NativeBorrowWiring

/-!
Explicit activation of defaults for foreign ancestor synthesis ports. The
native compiler emits internal default lets without adding caller parameters.
Consumed-port observations remain explicit in this model; native pure code may
erase a successful, effect-free variable observation. No original owned port,
backward argument, fresh result or source heap/loan adequacy is supplied here.
All scripts await final elaboration.
-/
namespace Auths.Support.NativeForeignDefaults
open NativeRootPayload NativeRootExpressions NativeScopedDefaults
open NativeDefaultBindings (Table lookup put)
open NativeBorrowWiring
universe u

inductive Operation where
  | bind (port : Port) (registry : NativeScopedDefaults.State) (entry : Default)
  | observe (port : Port) (registry : NativeScopedDefaults.State) (variable : Variable)
  deriving DecidableEq, Repr

def Operation.port : Operation → Port
  | .bind port _ _ | .observe port _ _ => port

structure Program where
  target : Nat
  parents : List Nat
  fuel : Nat
  types : List (SourceClosureRegions.Expr × Ty)
  ports : List Port
  operations : List Operation
  deriving DecidableEq, Repr

def translatedType (program : Program) (port : Port) : Option Ty :=
  (program.types.find? fun pair => pair.1 == port.nativeType).map Prod.snd

def ancestorPort (program : Program) (port : Port) : Bool :=
  port.group != program.target && decide (port.group ∈ program.parents)

def operationValid (schemas : List Schema) (program : Program) : Operation → Bool
  | .bind port registry entry =>
      ancestorPort program port && port.givenBack && (!port.inputAbstraction || decide (port.level > 0)) &&
      port.identity == entry.symbol && translatedType program port == some entry.variable.type &&
      valid schemas program.fuel registry entry &&
      decide (lookup entry.variable.identity registry.defaults = some entry)
  | .observe port registry variable =>
      ancestorPort program port && !port.givenBack && stateValid registry && declared registry variable &&
      translatedType program port == some variable.type &&
      decide (lookup port.identity registry.symbols = some variable)

def check (schemas : List Schema) (program : Program) : Bool :=
  let keys := program.types.map Prod.fst
  keys.eraseDups.length == keys.length &&
    program.operations.map Operation.port == program.ports &&
    program.operations.all (operationValid schemas program)

structure Runtime (Atom : Ty → Type u) where
  values : Table (Dynamic Atom)
  visited : List Port

/-- A foreign default defines a fresh runtime variable. A supplied fresh value
cannot be overwritten by an implicit default. Observations read the actual
current variable; no missing-value/default-origin fallback exists. -/
def executeOperation {Atom : Ty → Type u} (schemas : List Schema) (fuel : Nat)
    (before : Runtime Atom) (operation : Operation) : Option (Runtime Atom) := do
  match operation with
  | .bind port _ entry =>
      if (lookup entry.variable.identity before.values).isSome then none else do
        let value ← activate schemas fuel entry before.values
        if value.type ≠ entry.variable.type then none else
          some ⟨put entry.variable.identity value before.values, before.visited ++ [port]⟩
  | .observe port _ variable =>
      let value ← lookup variable.identity before.values
      if value.type ≠ variable.type then none else some ⟨before.values, before.visited ++ [port]⟩

def executeOperations {Atom : Ty → Type u} (schemas : List Schema) (fuel : Nat) :
    Runtime Atom → List Operation → Option (Runtime Atom)
  | state, [] => some state
  | state, first :: rest => do
      let state ← executeOperation schemas fuel state first
      executeOperations schemas fuel state rest

def run {Atom : Ty → Type u} (schemas : List Schema) (program : Program)
    (values : Table (Dynamic Atom)) : Option (Runtime Atom) :=
  if check schemas program then executeOperations schemas program.fuel ⟨values, []⟩ program.operations else none

theorem supplied_fresh_values_are_not_overwritten {Atom : Ty → Type u}
    (schemas : List Schema) (fuel : Nat) (state : Runtime Atom) (port : Port)
    (registry : NativeScopedDefaults.State) (entry : Default)
    (present : (lookup entry.variable.identity state.values).isSome = true) :
    executeOperation schemas fuel state (.bind port registry entry) = none := by
  simp [executeOperation, present]

theorem missing_observation_cannot_use_a_default {Atom : Ty → Type u}
    (schemas : List Schema) (fuel : Nat) (state : Runtime Atom) (port : Port)
    (registry : NativeScopedDefaults.State) (variable : Variable)
    (missing : lookup variable.identity state.values = none) :
    executeOperation schemas fuel state (.observe port registry variable) = none := by
  simp [executeOperation, missing]

theorem successful_observation_preserves_values {Atom : Ty → Type u}
    (schemas : List Schema) (fuel : Nat) (before after : Runtime Atom) (port : Port)
    (registry : NativeScopedDefaults.State) (variable : Variable)
    (accepted : executeOperation schemas fuel before (.observe port registry variable) = some after) :
    after.values = before.values := by
  cases found : lookup variable.identity before.values with
  | none => simp [executeOperation, found] at accepted
  | some value =>
      by_cases same : value.type = variable.type
      · have result : Runtime.mk before.values (before.visited ++ [port]) = after := by
          simpa [executeOperation, found, same] using accepted
        subst after
        rfl
      · simp [executeOperation, found, same] at accepted

theorem executed_operation_visits_exact_source_port {Atom : Ty → Type u}
    (schemas : List Schema) (fuel : Nat) (before after : Runtime Atom) (operation : Operation)
    (accepted : executeOperation schemas fuel before operation = some after) :
    after.visited = before.visited ++ [operation.port] := by
  cases operation with
  | bind port registry entry =>
      unfold executeOperation at accepted
      split at accepted
      · simp at accepted
      · cases activated : activate schemas fuel entry before.values with
        | none => simp [activated] at accepted
        | some value =>
            by_cases same : value.type = entry.variable.type
            · have result : Runtime.mk (put entry.variable.identity value before.values) (before.visited ++ [port]) = after := by
                simpa [activated, same] using accepted
              subst after
              rfl
            · simp [activated, same] at accepted
  | observe port registry variable =>
      cases found : lookup variable.identity before.values with
      | none => simp [executeOperation, found] at accepted
      | some value =>
          by_cases same : value.type = variable.type
          · have result : Runtime.mk before.values (before.visited ++ [port]) = after := by
              simpa [executeOperation, found, same] using accepted
            subst after
            rfl
          · simp [executeOperation, found, same] at accepted

theorem successful_run_visits_every_foreign_port {Atom : Ty → Type u}
    (schemas : List Schema) (program : Program) (values : Table (Dynamic Atom)) (after : Runtime Atom)
    (accepted : run schemas program values = some after) : after.visited = program.ports := by
  have sequence : ∀ (operations : List Operation) (before after : Runtime Atom),
      executeOperations schemas program.fuel before operations = some after →
      after.visited = before.visited ++ operations.map Operation.port := by
    intro operations
    induction operations with
    | nil => intro before after accepted; cases accepted; simp
    | cons first rest ih =>
        intro before after accepted
        cases result : executeOperation schemas program.fuel before first with
        | none => simp [executeOperations, result] at accepted
        | some next =>
            have tail : executeOperations schemas program.fuel next rest = some after := by
              simpa [executeOperations, result] using accepted
            rw [ih next after tail, executed_operation_visits_exact_source_port schemas program.fuel before next first result]
            simp [List.append_assoc]
  cases checked : check schemas program with
  | false => simp [run, checked] at accepted
  | true =>
      have executed : executeOperations schemas program.fuel ⟨values, []⟩ program.operations = some after := by
        simpa [run, checked] using accepted
      have ports : program.operations.map Operation.port = program.ports := by
        by_cases same : program.operations.map Operation.port = program.ports
        · exact same
        · simp [check, same] at checked
      simpa [ports] using sequence program.operations ⟨values, []⟩ after executed

end Auths.Support.NativeForeignDefaults
