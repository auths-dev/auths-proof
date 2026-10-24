import Auths.Support.SourceClosureRegions

/-!
Name/type-shape provenance for ordered native backward metadata. This checks
both the abstraction values and continuation against the same incoming scope.
Repeated observations of one producer at different native levels are retained
and must agree on owner, origin and full type. They are not repeated execution
or permission to merge distinct native projector occurrences.

Region erasure below is used only for type-*shape* agreement of projections.
Full types remain in the certificate. Region validity, values, native ending,
the backward ABI, aliasing and heap/loan adequacy are not established here.
-/
namespace Auths.Support.NativeBorrowProtocol
open SourceClosureRegions

inductive Origin where
  | borrow (identity : Nat)
  | symbolic (identity : Nat)
  deriving DecidableEq, Repr

structure Binding where
  identity : Nat
  sort : Expr
  owner : Option Nat
  origin : Option Origin
  deriving DecidableEq, Repr

inductive Observation where
  | use (identity : Nat) (projectionType : Expr)
  | borrow (identity : Nat) (projectionType : Expr)
  | define (identity : Nat) (sort : Expr) (origin : Origin)
  | control (input : Bool) (group : Nat)
  deriving DecidableEq, Repr

structure Event where
  abstraction : Nat
  input : Bool
  group : Nat
  level : Nat
  canEnd : Bool
  parents : List Nat
  abstractValues : List Observation
  continuation : List Observation
  activeAbstractLevels : List Nat
  activeContinuationLevels : List Nat
  nativeNoLiveAbove : Bool
  deriving DecidableEq, Repr

structure Terminal where
  abstraction : Nat
  input : Bool
  group : Nat
  activeAbstractLevels : List Nat
  activeContinuationLevels : List Nat
  nativeHasLiveBorrows : Bool
  nativeHasLiveLoans : Bool
  deriving DecidableEq, Repr

structure Program where
  target : Nat
  allowedGroups : List Nat
  initial : List Binding
  borrows : List (Nat × Expr)
  events : List Event
  typeFuel : Nat
  terminal : List Terminal
  deriving Repr

def lookup (identity : Nat) : List Binding → Option Binding
  | [] => none
  | first :: rest => if first.identity = identity then some first else lookup identity rest

def borrowType (identity : Nat) : List (Nat × Expr) → Option Expr
  | [] => none
  | (actual, sort) :: rest => if actual = identity then some sort else borrowType identity rest

/-- Refuse exhaustion/holes; preserve all non-region constructors, dictionaries,
identifiers and binder metadata. This is not lifetime unification. -/
def typeShape : Nat → Expr → Option Expr
  | 0, _ => none
  | _, .outputSlot _ => none
  | _ + 1, .natural value => some (.natural value)
  | _ + 1, .bytes value => some (.bytes value)
  | _ + 1, .region _ => some (.region .erased)
  | fuel + 1, .node tag children => do
      let children ← children.mapM (typeShape fuel)
      pure (.node tag children)
  | fuel + 1, .binder names contents => do
      let contents ← typeShape fuel contents
      pure (.binder names contents)

def sameShape (fuel : Nat) (left right : Expr) : Bool :=
  match typeShape fuel left, typeShape fuel right with
  | some left, some right => decide (left = right)
  | _, _ => false

def originType (program : Program) (bindings : List Binding) : Origin → Option Expr
  | .symbolic identity => (lookup identity bindings).map Binding.sort
  | .borrow identity => do
      let sort ← borrowType identity program.borrows
      match sort with
      | .node .mutRef [_, contents] => some contents
      | _ => none

def observe (program : Program) (event : Event) (bindings : List Binding) :
    Observation → Option (List Binding)
  | .use identity projectionType => do
      let original ← lookup identity bindings
      if sameShape program.typeFuel original.sort projectionType then some bindings else none
  | .borrow identity projectionType => do
      let original ← borrowType identity program.borrows
      if sameShape program.typeFuel original projectionType then some bindings else none
  | .define identity sort origin => do
      let original ← originType program bindings origin
      if !sameShape program.typeFuel original sort then none else
        let introduced : Binding := ⟨identity, sort, some event.abstraction, some origin⟩
        match lookup identity bindings with
        | none => some (introduced :: bindings)
        | some previous => if previous = introduced then some bindings else none
  | .control input group =>
      if input = event.input ∧ group = event.group then some bindings else none

def observations (program : Program) (event : Event) (bindings : List Binding) :
    List Observation → Option (List Binding)
  | [] => some bindings
  | first :: rest => do
      let bindings ← observe program event bindings first
      observations program event bindings rest

structure Ending where
  abstraction : Nat
  input : Bool
  group : Nat
  lastLevel : Nat
  deriving DecidableEq, Repr

def ending (identity : Nat) : List Ending → Option Ending
  | [] => none
  | first :: rest => if first.abstraction = identity then some first else ending identity rest

/-- Nonconsecutive native endings require both complete active-level scans and
the original native borrow/loan query to report no live higher level. These
retained source receipts do not themselves establish full native loan adequacy. -/
def clearAbove (event : Event) : Bool :=
  event.nativeNoLiveAbove &&
    event.activeAbstractLevels.all (fun level => decide (level ≤ event.level)) &&
    event.activeContinuationLevels.all (fun level => decide (level ≤ event.level))

def advance (previous : List Ending) (event : Event) : Option (List Ending) := do
  match ending event.abstraction previous with
  | none => pure (⟨event.abstraction, event.input, event.group, event.level⟩ :: previous)
  | some before =>
      if before.input = event.input ∧ before.group = event.group ∧ event.level < before.lastLevel ∧
          (before.lastLevel = event.level + 1 ∨ clearAbove event = true) then
        pure (previous.map fun item => if item.abstraction = event.abstraction then
          { item with lastLevel := event.level } else item)
      else none

def controlCount : List Observation → Nat
  | [] => 0
  | .control _ _ :: rest => 1 + controlCount rest
  | _ :: rest => controlCount rest

def events (program : Program) (bindings : List Binding) (ended : List Ending) :
    List Event → Option (List Binding × List Ending)
  | [] => some (bindings, ended)
  | first :: rest => do
      if !first.canEnd || !first.parents.isEmpty || !program.allowedGroups.contains first.group ||
          controlCount first.abstractValues != 0 || controlCount first.continuation != 1 then none else do
        let ended ← advance ended first
        let fromAbstract ← observations program first bindings first.abstractValues
        let fromContinuation ← observations program first bindings first.continuation
        if fromAbstract = fromContinuation then events program fromAbstract ended rest else none

/-- Retain every original terminal row, including unselected/empty scopes.
Target and ancestor synthesis scopes must have no live owned borrow/loan in
either representation or original native query. Full source heap/environment
and loan semantics remain separate from this finite scope projection. -/
def terminalClosed (program : Program) : Bool :=
  let identities := program.terminal.map Terminal.abstraction
  decide (identities.eraseDups.length = identities.length) &&
    program.terminal.all fun entry =>
      !program.allowedGroups.contains entry.group ||
        (entry.activeAbstractLevels.isEmpty && entry.activeContinuationLevels.isEmpty &&
          !entry.nativeHasLiveBorrows && !entry.nativeHasLiveLoans)

def check (program : Program) : Bool :=
  let uniqueInputs := program.initial.map Binding.identity
  let uniqueBorrows := program.borrows.map Prod.fst
  if !terminalClosed program || uniqueInputs.eraseDups.length != uniqueInputs.length ||
      uniqueBorrows.eraseDups.length != uniqueBorrows.length ||
      program.initial.any (fun binding => binding.owner.isSome || binding.origin.isSome) then false else
  match events program program.initial [] program.events with
  | none => false
  | some (_, ended) =>
      ended.all (fun item => item.lastLevel == 0 &&
        ended.any (fun other => other.group == item.group && other.input != item.input) &&
        (ended.filter fun other => other.group == item.group && other.input == item.input).length == 1) &&
      ended.any (fun item => item.group == program.target && item.input) &&
      ended.any (fun item => item.group == program.target && !item.input)

theorem unknown_symbol_refuses (program : Program) (event : Event) (bindings : List Binding)
    (identity : Nat) (sort : Expr) (missing : lookup identity bindings = none) :
    observe program event bindings (.use identity sort) = none := by
  simp [observe, missing]

theorem unknown_borrow_refuses (program : Program) (event : Event) (bindings : List Binding)
    (identity : Nat) (sort : Expr) (missing : borrowType identity program.borrows = none) :
    observe program event bindings (.borrow identity sort) = none := by
  simp [observe, missing]

theorem completed_abstraction_cannot_end_again (before : List Ending) (event : Event)
    (original : Ending) (known : ending event.abstraction before = some original)
    (completed : original.lastLevel = 0) : advance before event = none := by
  simp [advance, known, completed]

end Auths.Support.NativeBorrowProtocol
