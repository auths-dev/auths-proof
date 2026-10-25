import Auths.Support.BorrowTransport
import Auths.Support.BorrowViewRestriction
import Auths.Support.NativeCaptureValue

/-!
Default expressions read the immediate current symbolic version or borrow
pointee. They do not chase an origin chain to a forward snapshot. In particular,
a reprojection default from symbol 13 requires current symbol 13, not symbol 6.
Computing a default does not install a given-back result or execute a native
continuation. Actual results must be supplied explicitly to `recordCurrent`.
This pure-data store establishes no Rust reference or loan permission.
All new proof scripts await final elaboration.
-/
namespace Auths.Support.NativeBorrowDefaults
open SourceClosureRegions BorrowProjection BorrowTransport BorrowViewRestriction
universe u

inductive Key where
  | symbolic (identity : Nat)
  | borrow (identity : Nat)
  deriving DecidableEq, Repr

structure Recipe where
  target : Nat
  source : Key
  candidateShape : Shape
  nativeShape : Shape
  transport : Change candidateShape nativeShape
  available : Plan candidateShape
  selected : Plan candidateShape
  restriction : Restriction available selected

abbrev Entry (Atom : Expr → Type u) := Σ shape : Shape, Σ plan : Plan shape, View Atom plan
abbrev Current (Atom : Expr → Type u) := Key → Option (Entry Atom)

/-- A borrow's pointee name comes from its unique original expansion. Neither
a later symbolic name nor the identity of a nearby borrow is a substitute. -/
def forwardBorrowContents (borrow : Nat) (steps : List NativeCaptureValue.Step) : Option Nat :=
  match steps.filterMap (fun step => match step with
      | .mutableBorrow _ actual contents => if actual = borrow then some contents else none
      | _ => none) with
  | [contents] => some contents
  | _ => none

/-- Initialize logical current views from the same actual forward state.
This supplies preparation data, not Rust alias or loan permissions. It creates
no backward result and does not chase any given-back default. -/
def currentOfForward {Atom : Expr → Type u} (program : NativeCaptureValue.Program)
    (state : NativeCaptureValue.State Atom) : Current Atom
  | .symbolic identity =>
      (NativeCaptureValue.find identity state.values).map fun value =>
        ⟨value.1, .keep, value.2⟩
  | .borrow identity => do
      let shape ← NativeCaptureValue.find identity state.borrows
      let contents ← forwardBorrowContents identity program.steps
      let value ← NativeCaptureValue.find contents state.values
      match shape with
      | .borrow true _ body => do
          let actual ← NativeCaptureValue.castData body value
          pure ⟨body, .keep, actual⟩
      | _ => none

def prepareCurrent {Atom : Expr → Type u} (program : NativeCaptureValue.Program)
    (inputs : List (Datum Atom)) : Option (Current Atom) := do
  let (_, state) ← NativeCaptureValue.runWithState program inputs
  pure (currentOfForward program state)

theorem prepared_current_uses_exact_forward_state {Atom : Expr → Type u}
    (program : NativeCaptureValue.Program) (inputs : List (Datum Atom))
    (value : Datum Atom) (state : NativeCaptureValue.State Atom)
    (prepared : NativeCaptureValue.runWithState program inputs = some (value, state)) :
    prepareCurrent program inputs = some (currentOfForward program state) := by
  simp [prepareCurrent, prepared]

theorem successful_forward_has_prepared_current {Atom : Expr → Type u}
    (program : NativeCaptureValue.Program) (inputs : List (Datum Atom)) (value : Datum Atom)
    (accepted : NativeCaptureValue.run program inputs = some value) :
    ∃ current, prepareCurrent program inputs = some current := by
  cases result : NativeCaptureValue.runWithState program inputs with
  | none => simp [NativeCaptureValue.run, result] at accepted
  | some prepared =>
      exact ⟨currentOfForward program prepared.2, by simp [prepareCurrent, result]⟩

theorem missing_forward_symbol_is_not_fabricated {Atom : Expr → Type u}
    (program : NativeCaptureValue.Program) (state : NativeCaptureValue.State Atom)
    (identity : Nat) (missing : NativeCaptureValue.find identity state.values = none) :
    currentOfForward program state (.symbolic identity) = none := by
  simp [currentOfForward, missing]

theorem unknown_forward_borrow_is_not_fabricated {Atom : Expr → Type u}
    (program : NativeCaptureValue.Program) (state : NativeCaptureValue.State Atom)
    (identity : Nat) (missing : NativeCaptureValue.find identity state.borrows = none) :
    currentOfForward program state (.borrow identity) = none := by
  simp [currentOfForward, missing]

theorem failed_forward_preparation_refuses_current {Atom : Expr → Type u}
    (program : NativeCaptureValue.Program) (inputs : List (Datum Atom))
    (failed : NativeCaptureValue.runWithState program inputs = none) :
    prepareCurrent program inputs = none := by
  simp [prepareCurrent, failed]

def castEntry {Atom : Expr → Type u} (shape : Shape) (plan : Plan shape)
    (entry : Entry Atom) : Option (View Atom plan) := by
  rcases entry with ⟨actualShape, actualPlan, value⟩
  exact if sameShape : actualShape = shape then by
    subst actualShape
    exact if samePlan : actualPlan = plan then some (samePlan ▸ value) else none
  else none

def readCurrent {Atom : Expr → Type u} (current : Current Atom) (key : Key)
    (shape : Shape) (plan : Plan shape) : Option (View Atom plan) :=
  (current key).bind (castEntry shape plan)

theorem forward_symbol_has_exact_original_value {Atom : Expr → Type u}
    (program : NativeCaptureValue.Program) (state : NativeCaptureValue.State Atom)
    (identity : Nat) (shape : Shape) (value : Data Atom shape)
    (present : NativeCaptureValue.find identity state.values = some ⟨shape, value⟩) :
    readCurrent (currentOfForward program state) (.symbolic identity) shape .keep = some value := by
  simp [readCurrent, currentOfForward, present, castEntry]

theorem forward_borrow_has_exact_expanded_pointee {Atom : Expr → Type u}
    (program : NativeCaptureValue.Program) (state : NativeCaptureValue.State Atom)
    (identity contents : Nat) (region : Region) (body : Shape) (value : Data Atom body)
    (borrow : NativeCaptureValue.find identity state.borrows = some (.borrow true region body))
    (expansion : forwardBorrowContents identity program.steps = some contents)
    (present : NativeCaptureValue.find contents state.values = some ⟨body, value⟩) :
    readCurrent (currentOfForward program state) (.borrow identity) body .keep = some value := by
  simp [readCurrent, currentOfForward, borrow, expansion, present,
    NativeCaptureValue.castData, castEntry]

def Recipe.nativePlan (recipe : Recipe) : Plan recipe.nativeShape :=
  mapPlan recipe.transport recipe.selected

def evaluate {Atom : Expr → Type u} (recipe : Recipe) (current : Current Atom) :
    Option (View Atom recipe.nativePlan) :=
  (readCurrent current recipe.source recipe.candidateShape recipe.available).map fun value =>
    forwardView recipe.transport recipe.selected (restrict recipe.restriction value)

/-- Register an explicitly supplied actual result, after converting its exact
native representation. A default candidate alone never creates this result. -/
def recordCurrent {Atom : Expr → Type u} (recipe : Recipe) (current : Current Atom)
    (actual : View Atom recipe.nativePlan) : Current Atom :=
  fun key => if key = .symbolic recipe.target then
    some ⟨recipe.candidateShape, recipe.selected, backwardView recipe.transport recipe.selected actual⟩ else current key

theorem missing_immediate_source_is_refused {Atom : Expr → Type u}
    (recipe : Recipe) (current : Current Atom) (missing : current recipe.source = none) :
    evaluate recipe current = none := by
  simp [evaluate, readCurrent, missing]

theorem default_depends_only_on_immediate_current {Atom : Expr → Type u}
    (recipe : Recipe) (first second : Current Atom)
    (same : first recipe.source = second recipe.source) :
    evaluate recipe first = evaluate recipe second := by
  simp only [evaluate, readCurrent, same]

theorem exact_current_source_is_transported {Atom : Expr → Type u}
    (recipe : Recipe) (current : Current Atom) (value : View Atom recipe.available)
    (present : current recipe.source = some ⟨recipe.candidateShape, recipe.available, value⟩) :
    evaluate recipe current = some (forwardView recipe.transport recipe.selected (restrict recipe.restriction value)) := by
  simp [evaluate, readCurrent, present, castEntry]

theorem recorded_target_is_exact {Atom : Expr → Type u}
    (recipe : Recipe) (current : Current Atom) (actual : View Atom recipe.nativePlan) :
    readCurrent (recordCurrent recipe current actual) (.symbolic recipe.target) recipe.candidateShape recipe.selected =
      some (backwardView recipe.transport recipe.selected actual) := by
  simp [readCurrent, recordCurrent, castEntry]

theorem recording_preserves_other_versions {Atom : Expr → Type u}
    (recipe : Recipe) (current : Current Atom) (actual : View Atom recipe.nativePlan)
    (key : Key) (different : key ≠ .symbolic recipe.target) :
    recordCurrent recipe current actual key = current key := by
  simp [recordCurrent, different]

theorem recorded_native_value_round_trip {Atom : Expr → Type u}
    (recipe : Recipe) (actual : View Atom recipe.nativePlan) :
    forwardView recipe.transport recipe.selected (backwardView recipe.transport recipe.selected actual) = actual :=
  view_inverse_forward recipe.transport recipe.selected actual

theorem wrong_current_shape_is_refused {Atom : Expr → Type u}
    (shape actualShape : Shape) (plan : Plan shape) (actualPlan : Plan actualShape)
    (value : View Atom actualPlan) (different : actualShape ≠ shape) :
    castEntry shape plan ⟨actualShape, actualPlan, value⟩ = none := by
  simp [castEntry, different]

theorem wrong_current_view_is_refused {Atom : Expr → Type u}
    (shape : Shape) (plan actualPlan : Plan shape) (value : View Atom actualPlan)
    (different : actualPlan ≠ plan) : castEntry shape plan ⟨shape, actualPlan, value⟩ = none := by
  simp [castEntry, different]

end Auths.Support.NativeBorrowDefaults
