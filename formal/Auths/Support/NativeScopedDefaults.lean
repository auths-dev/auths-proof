import Auths.Support.NativeRootExpressions
import Auths.Support.NativeDefaultBindings

/-!
Full-type lazy native default expressions with explicit current-version captures.
Registration does not bind or evaluate a fresh given-back value. The native
constructor checks exact current variable declarations and stores the algebraic
expression using the shared native registry operation. This model is not a
complete synthesis context, EndAbs rule or Rust heap/loan semantics.
Scripts await final elaboration.
-/
namespace Auths.Support.NativeScopedDefaults
open NativeRootPayload NativeRootExpressions
open NativeDefaultBindings (Table lookup put)
universe u

structure Variable where
  identity : Nat
  type : Ty
  deriving DecidableEq, Repr

structure Capture where
  symbol : Nat
  variable : Variable
  deriving DecidableEq, Repr

structure Default where
  symbol : Nat
  variable : Variable
  captures : List Capture
  code : Term
  deriving DecidableEq, Repr

structure State where
  next : Nat
  symbols : Table Variable
  variables : Table Variable
  types : Table Ty
  defaults : Table Default
  deriving DecidableEq, Repr

def declared (state : State) (variable : Variable) : Bool :=
  decide (lookup variable.identity state.variables = some variable) &&
    decide (lookup variable.identity state.types = some variable.type)

def uniqueKeys (table : Table α) : Bool :=
  let keys := table.map Prod.fst
  keys.eraseDups.length == keys.length

/-- Native maps have unique keys and one consistent declaration/type entry per
native variable. Reflected lists must establish those same properties rather
than hiding a conflicting declaration behind first-match lookup. -/
def stateValid (state : State) : Bool :=
  uniqueKeys state.symbols && uniqueKeys state.variables && uniqueKeys state.types && uniqueKeys state.defaults &&
    state.variables.map Prod.fst == state.types.map Prod.fst &&
    state.variables.all (fun pair => pair.1 == pair.2.identity &&
      decide (pair.2.identity < state.next) && declared state pair.2) &&
    state.symbols.all (fun pair => declared state pair.2) &&
    state.defaults.all (fun pair => pair.1 == pair.2.variable.identity && declared state pair.2.variable &&
      decide (lookup pair.2.symbol state.symbols = some pair.2.variable))

def valid (schemas : List Schema) (fuel : Nat) (state : State) (entry : Default) : Bool :=
  stateValid state && declared state entry.variable && decide (lookup entry.symbol state.symbols = some entry.variable) &&
    let ids := entry.captures.map (·.variable.identity)
    ids.eraseDups.length == ids.length && entry.captures.all (fun capture =>
      capture.variable.identity != entry.variable.identity && declared state capture.variable &&
        decide (lookup capture.symbol state.symbols = some capture.variable)) &&
    entry.code.type == arrows (entry.captures.map (·.variable.type)) entry.variable.type &&
    check schemas fuel [] entry.code

def register (schemas : List Schema) (fuel : Nat) (state : State) (entry : Default) : Option State :=
  if valid schemas fuel state entry then
    some { state with defaults := put entry.variable.identity entry state.defaults }
  else none

/-- Activation reads exactly the captured current variable identities from an
explicit value table. It never follows another variable's registered default. -/
def activate {Atom : Ty → Type u} (schemas : List Schema) (fuel : Nat)
    (entry : Default) (values : Table (Dynamic Atom)) : Option (Dynamic Atom) := do
  let arguments ← entry.captures.mapM fun capture => lookup capture.variable.identity values
  execute schemas fuel entry.code arguments

theorem registration_preserves_all_symbolic_bindings (schemas : List Schema) (fuel : Nat)
    (before after : State) (entry : Default) (accepted : register schemas fuel before entry = some after) :
    after.symbols = before.symbols := by
  cases checked : valid schemas fuel before entry with
  | false => simp [register, checked] at accepted
  | true =>
      have same : { before with defaults := put entry.variable.identity entry before.defaults } = after := by
        simpa [register, checked] using accepted
      subst after
      rfl

theorem registration_preserves_current_declarations (schemas : List Schema) (fuel : Nat)
    (before after : State) (entry : Default) (accepted : register schemas fuel before entry = some after) :
    after.variables = before.variables ∧ after.types = before.types := by
  cases checked : valid schemas fuel before entry with
  | false => simp [register, checked] at accepted
  | true =>
      have same : { before with defaults := put entry.variable.identity entry before.defaults } = after := by
        simpa [register, checked] using accepted
      subst after
      exact ⟨rfl, rfl⟩

theorem registration_preserves_allocation_counter (schemas : List Schema) (fuel : Nat)
    (before after : State) (entry : Default) (accepted : register schemas fuel before entry = some after) :
    after.next = before.next := by
  cases checked : valid schemas fuel before entry with
  | false => simp [register, checked] at accepted
  | true =>
      have same : { before with defaults := put entry.variable.identity entry before.defaults } = after := by
        simpa [register, checked] using accepted
      subst after
      rfl

theorem fresh_given_back_binding_is_not_its_default (schemas : List Schema) (fuel : Nat)
    (before after : State) (entry : Default) (accepted : register schemas fuel before entry = some after) :
    lookup entry.symbol after.symbols = lookup entry.symbol before.symbols := by
  rw [registration_preserves_all_symbolic_bindings schemas fuel before after entry accepted]

theorem invalid_scope_is_refused (schemas : List Schema) (fuel : Nat) (state : State) (entry : Default)
    (invalid : valid schemas fuel state entry = false) : register schemas fuel state entry = none := by
  simp [register, invalid]

theorem missing_current_capture_is_not_a_default_fallback {Atom : Ty → Type u}
    (schemas : List Schema) (fuel : Nat) (entry : Default) (first : Capture) (rest : List Capture)
    (captures : entry.captures = first :: rest) (values : Table (Dynamic Atom))
    (missing : lookup first.variable.identity values = none) : activate schemas fuel entry values = none := by
  simp [activate, captures, missing]

end Auths.Support.NativeScopedDefaults
