import Auths.Support.NativeDefaultBindings
import Auths.Support.NativeBorrowWiring

/-!
Complete typed projector trees and selected-level ports. Fuel exhaustion and
an active projector at the selected level refuse admission. An ended outer
borrow retains every inner loan; selecting its outer given-back value does not
consume, erase or merge the child return. The native constructor compares both
original AV/EV trees and reads each consumed symbol through the actual shared
native symbolic lookup at the corresponding ending's registry state.

These definitions describe scheduling and immediate variable references. They
do not activate defaults, reconstruct a projected Rust value, prove an EndAbs
continuation, or turn a registry into a native heap/permission environment.
Proof scripts await final elaboration.
-/
namespace Auths.Support.NativeProjectorLevels
open NativeBorrowWiring NativeDefaultBindings

structure Symbol where
  identity : Nat
  sourceType : SourceClosureRegions.Expr
  nativeType : NativePurePayload.Ty
  deriving DecidableEq, Repr

inductive Tree where
  | empty (annotation : SourceClosureRegions.Expr)
  | loan (annotation : SourceClosureRegions.Expr) (ended : Bool) (original : Symbol)
      (consumed borrows : List (Symbol × Tree))
  | borrow (annotation : SourceClosureRegions.Expr) (original : Symbol)
      (givenBack : Option Symbol) (loans : List (Symbol × Tree))
  deriving DecidableEq, Repr

structure Port where
  symbol : Symbol
  givenBack : Bool
  level : Nat
  path : List Edge
  deriving DecidableEq, Repr

private def one (selected current : Nat) (path : List Edge)
    (givenBack : Bool) (symbol : Symbol) : List Port :=
  if selected = current then [⟨symbol, givenBack, current, path⟩] else []

/-- Descending into a stored reprojection increases the sub-abstraction level.
Pair metadata supplies the child's original annotation, never a guessed type. -/
def select : Nat → Nat → Nat → List Edge → Tree → Option (List Port)
  | 0, _, _, _, _ => none
  | fuel + 1, selected, current, path, tree => do
      let edges (tag : Nat → Edge) (pairs : List (Symbol × Tree)) :=
        pairs.zipIdx.foldlM (fun result (pair, index) => do
          let child ← select fuel selected (current + 1) (path ++ [tag index]) pair.2
          pure (result ++ child)) []
      match tree with
      | .empty _ => pure []
      | .loan _ ended original consumed borrows =>
          if !ended && decide (selected = current) then none else do
            let consumedChildren ← edges Edge.consumed consumed
            let borrowChildren ← edges Edge.borrowReprojection borrows
            let header := if !ended then [] else if consumed.isEmpty then
                one selected current path false original
              else consumed.zipIdx.flatMap fun (pair, index) =>
                one selected current (path ++ [.consumed index]) false pair.1
            pure (header ++ consumedChildren ++ borrowChildren)
      | .borrow _ _ givenBack loans =>
          if givenBack.isNone && decide (selected = current) then none else do
            let children ← edges Edge.loanReprojection loans
            let header := match givenBack with
              | none => []
              | some symbol => one selected current path true symbol
            pure (header ++ children)

/-- A typed immediate lookup additionally requires the reflected variable and
its declared type table entry to agree. It never follows a registered default. -/
def read (state : State) (symbol : Symbol) : Option Expression := do
  if symbol.nativeType = .tuple [] then pure .unit else do
    let variable ← lookup symbol.identity state.symbols
    if variable.type ≠ symbol.nativeType then none else do
      let declared ← lookup variable.identity state.variables
      let type ← lookup variable.identity state.types
      if declared = variable ∧ type = symbol.nativeType then pure (.variable variable) else none

/-- A receipt records the actual immediate lookup at the earlier ending.
Original abstraction/path/typed-tree matching is performed by the constructor;
this check makes chronology, polarity, level and variable lookup explicit. -/
structure Receipt where
  givenEnding : Nat
  consumedEnding : Nat
  given : Port
  consumed : Port
  state : State
  expression : Expression
  deriving DecidableEq, Repr

def receiptValid (receipt : Receipt) : Bool :=
  decide (receipt.consumedEnding < receipt.givenEnding) &&
    receipt.given.givenBack && !receipt.consumed.givenBack &&
    decide (receipt.given.level < receipt.consumed.level) &&
    decide (read receipt.state receipt.consumed.symbol = some receipt.expression)

theorem read_ignores_defaults (state : State) (symbol : Symbol)
    (defaults : Table Expression) :
    read { state with defaults := defaults } symbol = read state symbol := by rfl

theorem read_ignores_consumed_borrow_defaults (state : State) (symbol : Symbol)
    (borrows : Table Expression) :
    read { state with borrows := borrows } symbol = read state symbol := by rfl

/-- The nested child is retained even when only the outer header is selected. -/
def innerLoanSymbols : Tree → List Nat
  | .borrow _ _ _ loans => loans.map (fun pair => pair.1.identity)
  | _ => []

example (annotation : SourceClosureRegions.Expr) (original given source result : Symbol) :
    select 3 0 0 [] (.borrow annotation original (some given)
      [(source, .loan annotation true source [(result, .empty annotation)] [])]) =
      some [⟨given, true, 0, []⟩] := by simp [select, one]

example (annotation : SourceClosureRegions.Expr) (original given source result : Symbol) :
    select 3 1 0 [] (.borrow annotation original (some given)
      [(source, .loan annotation true source [(result, .empty annotation)] [])]) =
      some [⟨result, false, 1, [.loanReprojection 0, .consumed 0]⟩] := by simp [select, one]

example (annotation : SourceClosureRegions.Expr) (original : Symbol) :
    select 1 0 0 [] (.loan annotation false original [] []) = none := by rfl

example (annotation : SourceClosureRegions.Expr) (original given source : Symbol) :
    select 1 0 0 [] (.borrow annotation original (some given)
      [(source, .empty annotation)]) = none := by rfl

end Auths.Support.NativeProjectorLevels
