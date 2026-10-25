import Auths.Support.BorrowProjection

/-!
An executable pure-data interpretation of the supported native forward trace.
Inputs and borrow names come from the native interpreter, rather than fixed
symbolic identifiers. Record expansion retains every actual field. Mutable
borrow reconstruction must use a previously expanded borrow name and its exact
regionful shape. No heap address, permission, native abstraction, effect or
backward continuation is modeled here. Native-to-data and source/loan adequacy
remain separate requirements. All new scripts await final elaboration.
-/
namespace Auths.Support.NativeCaptureValue

open BorrowProjection
universe u

inductive Value where
  | symbolic (identity : Nat)
  | mutableBorrow (identity : Nat) (contents : Value)
  | record (shape : Shape) (fields : List Value)
  | boxed (contents : Value)
  deriving Repr

inductive Step where
  | mutableBorrow (source borrow contents : Nat)
  | record (source : Nat) (fields : List Nat)
  | boxed (source contents : Nat)
  deriving DecidableEq, Repr

structure Program where
  inputs : List Nat
  steps : List Step
  result : Value
  valueFuel : Nat
  deriving Repr

structure State (Atom : SourceClosureRegions.Expr → Type u) where
  values : List (Nat × Datum Atom)
  borrows : List (Nat × Shape)
  expanded : List Nat

def find (identity : Nat) : List (Nat × α) → Option α
  | [] => none
  | (actual, value) :: rest => if actual = identity then some value else find identity rest

def castData {Atom : SourceClosureRegions.Expr → Type u} (shape : Shape)
    (value : Datum Atom) : Option (Data Atom shape) :=
  if same : value.1 = shape then some (same ▸ value.2) else none

def initialize {Atom : SourceClosureRegions.Expr → Type u} :
    List Nat → List (Datum Atom) → Option (List (Nat × Datum Atom))
  | [], [] => some []
  | identity :: names, value :: values => do
      let rest ← initialize names values
      if (find identity rest).isSome then none else some ((identity, value) :: rest)
  | _, _ => none

def bindValues {Atom : SourceClosureRegions.Expr → Type u}
    (original : List (Nat × Datum Atom)) :
    List Nat → List (Datum Atom) → Option (List (Nat × Datum Atom))
  | [], [] => some original
  | identity :: names, value :: values => do
      if (find identity original).isSome then none else
        bindValues ((identity, value) :: original) names values
  | _, _ => none

def expand {Atom : SourceClosureRegions.Expr → Type u} (state : State Atom)
    (step : Step) : Option (State Atom) := do
  let source := match step with
    | .mutableBorrow source _ _ | .record source _ | .boxed source _ => source
  if source ∈ state.expanded then none else do
    let value ← find source state.values
    match step, value with
    | .mutableBorrow _ borrow contents, ⟨.borrow true region body, .borrow value⟩ => do
        if (find borrow state.borrows).isSome then none else do
          let values ← bindValues state.values [contents] [⟨body, value⟩]
          pure ⟨values, (borrow, .borrow true region body) :: state.borrows,
            source :: state.expanded⟩
    | .record _ names, value => do
        let fields ← capturedFields value.2
        let values ← bindValues state.values names fields
        pure ⟨values, state.borrows, source :: state.expanded⟩
    | .boxed _ contents, ⟨.named .boxed body, .named value⟩ => do
        let values ← bindValues state.values [contents] [⟨body, value⟩]
        pure ⟨values, state.borrows, source :: state.expanded⟩
    | _, _ => none

def buildFields {Atom : SourceClosureRegions.Expr → Type u} (index : Nat) :
    (shape : Shape) → List (Datum Atom) → Option (Data Atom shape)
  | .unit, [] => some .unit
  | .product (.named (.field actual _) body) tail, first :: rest => do
      if actual = index then
        let first ← castData body first
        let rest ← buildFields (index + 1) tail rest
        pure (.product (.named first) rest)
      else none
  | _, _ => none

def evaluate {Atom : SourceClosureRegions.Expr → Type u} :
    Nat → State Atom → Value → Option (Datum Atom)
  | 0, _, _ => none
  | _ + 1, state, .symbolic identity => find identity state.values
  | fuel + 1, state, .mutableBorrow identity contents => do
      let shape ← find identity state.borrows
      let contents ← evaluate fuel state contents
      match shape with
      | .borrow true region body => do
          let contents ← castData body contents
          pure ⟨.borrow true region body, .borrow contents⟩
      | _ => none
  | fuel + 1, state, .record shape fields => do
      let fields ← fields.mapM (evaluate fuel state)
      match shape with
      | .named (.nominal identity) body => do
          let value ← buildFields 0 body fields
          pure ⟨.named (.nominal identity) body, .named value⟩
      | _ => none
  | fuel + 1, state, .boxed contents => do
      let contents ← evaluate fuel state contents
      pure ⟨.named .boxed contents.1, .named contents.2⟩

def execute {Atom : SourceClosureRegions.Expr → Type u}
    (state : State Atom) : List Step → Option (State Atom)
  | [] => some state
  | first :: rest => do
      let state ← expand state first
      execute state rest

def runWithState {Atom : SourceClosureRegions.Expr → Type u} (program : Program)
    (inputs : List (Datum Atom)) : Option (Datum Atom × State Atom) := do
  let values ← initialize program.inputs inputs
  let state ← execute ⟨values, [], []⟩ program.steps
  let value ← evaluate program.valueFuel state program.result
  pure (value, state)

def run {Atom : SourceClosureRegions.Expr → Type u} (program : Program)
    (inputs : List (Datum Atom)) : Option (Datum Atom) :=
  (runWithState program inputs).map Prod.fst

theorem run_projects_actual_state {Atom : SourceClosureRegions.Expr → Type u}
    (program : Program) (inputs : List (Datum Atom)) :
    (runWithState program inputs).map Prod.fst = run program inputs := rfl

theorem unknown_symbolic_is_refused {Atom : SourceClosureRegions.Expr → Type u}
    (state : State Atom) (fuel identity : Nat) (missing : find identity state.values = none) :
    evaluate (fuel + 1) state (.symbolic identity) = none := missing

theorem unknown_borrow_is_refused {Atom : SourceClosureRegions.Expr → Type u}
    (state : State Atom) (fuel identity : Nat) (value : Value)
    (missing : find identity state.borrows = none) :
    evaluate (fuel + 1) state (.mutableBorrow identity value) = none := by
  simp [evaluate, missing]

end Auths.Support.NativeCaptureValue
