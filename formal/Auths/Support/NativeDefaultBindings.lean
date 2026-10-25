import Auths.Support.NativePurePayload

/-!
Independent finite variable/default registry semantics for the explicitly
reflected native fragment. Registration stores an expression naming an
immediate variable; it neither evaluates that variable nor activates a foreign
default. Missing borrow defaults remain absent, as in the original translator.
Missing non-unit symbolic lookup is an admission refusal; the source constructor
must reject the corresponding native diagnostic/error placeholder. This is not
a complete synthesis context, native environment or Rust loan model.
All scripts await final elaboration.
-/
namespace Auths.Support.NativeDefaultBindings
open NativePurePayload
universe u

structure Variable where
  identity : Nat
  type : Ty
  deriving DecidableEq, Repr

inductive Expression where
  | variable (value : Variable)
  | unit
  deriving DecidableEq, Repr

abbrev Table (α : Type u) := List (Nat × α)

def lookup (key : Nat) : Table α → Option α
  | [] => none
  | (actual, value) :: rest => if key = actual then some value else lookup key rest

/-- Sorted insertion mirrors the native identifier maps, including replacement
of an existing key. The native generator supplies fresh variable identifiers. -/
def put (key : Nat) (value : α) : Table α → Table α
  | [] => [(key, value)]
  | (actual, old) :: rest =>
      if key = actual then (key, value) :: rest
      else if key < actual then (key, value) :: (actual, old) :: rest
      else (actual, old) :: put key value rest

theorem lookup_put_self (key : Nat) (value : α) (values : Table α) :
    lookup key (put key value values) = some value := by
  induction values with
  | nil => simp [put, lookup]
  | cons entry rest ih =>
      rcases entry with ⟨actual, old⟩
      by_cases same : key = actual
      · subst actual; simp [put, lookup]
      · by_cases early : key < actual
        · simp [put, lookup, same, early]
        · simp [put, lookup, same, early, ih]

theorem lookup_put_other (observed key : Nat) (value : α) (values : Table α)
    (separate : observed ≠ key) : lookup observed (put key value values) = lookup observed values := by
  induction values with
  | nil => simp [put, lookup, separate]
  | cons entry rest ih =>
      rcases entry with ⟨actual, old⟩
      by_cases same : key = actual
      · subst actual; simp [put, lookup, separate]
      · by_cases early : key < actual
        · simp [put, lookup, same, early, separate]
        · simp [put, lookup, same, early, separate, ih]

structure State where
  next : Nat
  symbols : Table Variable
  variables : Table Variable
  types : Table Ty
  borrows : Table Expression
  defaults : Table Expression
  deriving DecidableEq, Repr

def empty : State := ⟨0, [], [], [], [], []⟩

def bindSymbolic (symbol : Nat) (type : Ty) (state : State) : State × Variable :=
  let variable := Variable.mk state.next type
  ({ state with next := state.next + 1,
      symbols := put symbol variable state.symbols,
      variables := put variable.identity variable state.variables,
      types := put variable.identity type state.types }, variable)

def symbolicExpression (symbol : Nat) (type : Ty) (state : State) : Option Expression :=
  if type = .tuple [] then some .unit
  else (lookup symbol state.symbols).map Expression.variable

def bindInputs : List (Nat × Ty) → State → State
  | [], state => state
  | (symbol, type) :: rest, state => bindInputs rest (bindSymbolic symbol type state).1

def bindBorrows : List (Nat × Nat) → State → Option State
  | [], state => some state
  | (borrow, symbol) :: rest, state => do
      let variable ← lookup symbol state.symbols
      let value ← symbolicExpression symbol variable.type state
      bindBorrows rest { state with borrows := put borrow value state.borrows }

def initialize (inputs : List (Nat × Ty)) (borrows : List (Nat × Nat)) : Option State :=
  bindBorrows borrows (bindInputs inputs empty)

inductive Origin where
  | borrow (identity : Nat)
  | projection (symbol : Nat) (type : Ty)
  deriving DecidableEq, Repr

structure Registration where
  symbol : Nat
  type : Ty
  origin : Origin
  deriving DecidableEq, Repr

def register (before : State) (registration : Registration) : Option State := do
  let (state, variable) := bindSymbolic registration.symbol registration.type before
  match registration.origin with
  | .borrow identity =>
      match lookup identity state.borrows with
      | none => some state
      | some value => some { state with defaults := put variable.identity value state.defaults }
  | .projection symbol type => do
      let value ← symbolicExpression symbol type state
      pure { state with defaults := put variable.identity value state.defaults }

def scan (before : State) : List Registration → Option (List State)
  | [] => some []
  | registration :: rest => do
      let after ← register before registration
      let remaining ← scan after rest
      pure (after :: remaining)

def defaultForSymbol (state : State) (symbol : Nat) : Option Expression := do
  let variable ← lookup symbol state.symbols
  lookup variable.identity state.defaults

theorem unit_lookup_needs_no_symbol (state : State) (symbol : Nat) :
    symbolicExpression symbol (.tuple []) state = some .unit := by
  simp [symbolicExpression]

theorem missing_nonunit_symbol_is_refused (state : State) (symbol : Nat) (type : Ty)
    (notUnit : type ≠ .tuple []) (missing : lookup symbol state.symbols = none) :
    symbolicExpression symbol type state = none := by
  simp [symbolicExpression, notUnit, missing]

theorem missing_borrow_default_preserves_registry (state : State) (symbol borrow : Nat) (type : Ty)
    (missing : lookup borrow state.borrows = none) :
    (register state ⟨symbol, type, .borrow borrow⟩).map State.defaults = some state.defaults := by
  simp [register, bindSymbolic, missing]

end Auths.Support.NativeDefaultBindings
