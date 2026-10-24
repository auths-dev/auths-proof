import Auths.Support.NativeBorrowWiring

/-!
Selected-level ownership classification over complete, typed header observations.
Different levels do not compete for one classification. The producer retains
actual source AV trees and immediate reprojection-edge annotations; this model
checks the finite native classification and its actual mutable-port roster.
It supplies neither values nor defaults and establishes no Rust heap/loan or
backward continuation adequacy. Scripts await final elaboration.
-/
namespace Auths.Support.NativeProjectorKinds
open SourceClosureRegions NativeBorrowWiring

/-- Exact source metadata selected by the native given-back pattern path.
A consumed identity describes a lazy default; it never supplies the fresh value. -/
structure SelectedBorrow where
  consumedIdentity : Nat
  givenIdentity : Nat
  edgeType : Expr
  currentType : Expr
  deriving DecidableEq, Repr

def selectedBorrowRoster (headers : List SelectedBorrow) : List (Nat × Expr) :=
  headers.map (fun header => (header.givenIdentity, header.currentType))

def givenBackPortRoster (ports : List Port) : List (Nat × Expr) :=
  (ports.filter (fun port => port.givenBack)).map (fun port => (port.identity, port.nativeType))

/-- Exact roster equality includes every source identity, current type, duplicate
and position. Equal storage coordinates or equal erased types do not suffice. -/
theorem selected_borrow_roster_preserves_each_position
    (headers : List SelectedBorrow) (ports : List Port)
    (exact : selectedBorrowRoster headers = givenBackPortRoster ports) (index : Nat) :
    (selectedBorrowRoster headers)[index]? = (givenBackPortRoster ports)[index]? := by
  rw [exact]

theorem changing_a_default_identity_does_not_change_the_fresh_roster
    (headers : List SelectedBorrow) (change : Nat → Nat) :
    selectedBorrowRoster (headers.map (fun header =>
      { header with consumedIdentity := change header.consumedIdentity })) =
      selectedBorrowRoster headers := by
  simp [selectedBorrowRoster, List.map_map]

inductive Kind where
  | unknown
  | borrow (mutable : Bool)
  | loan (mutable : Bool)
  deriving DecidableEq, Repr

structure Observation where
  level : Nat
  sourceType : Expr
  classificationType : Expr
  kind : Kind
  deriving DecidableEq, Repr

/-- Compare complete source syntax while permitting different lifetime labels.
All other tags, identifiers, constants, dictionaries, binders and children must
agree. This is type-shape compatibility, never runtime value equality. -/
def onlyRegionsDiffer : Nat → Expr → Expr → Bool
  | 0, _, _ => false
  | _, .region _, .region _ => true
  | _, .natural first, .natural second => first == second
  | _, .bytes first, .bytes second => first == second
  | _, .outputSlot first, .outputSlot second => first == second
  | fuel + 1, .binder first left, .binder second right =>
      first == second && onlyRegionsDiffer fuel left right
  | fuel + 1, .node first left, .node second right =>
      first == second && left.length == right.length &&
        (left.zip right).all (fun pair => onlyRegionsDiffer fuel pair.1 pair.2)
  | _, _, _ => false

theorem current_lifetime_labels_can_differ (fuel : Nat) (original current : Region) :
    onlyRegionsDiffer (fuel + 1) (.region original) (.region current) = true := rfl

theorem non_lifetime_identifiers_cannot_change (fuel first second : Nat) :
    onlyRegionsDiffer (fuel + 1) (.natural first) (.natural second) = true ↔ first = second := by
  simp [onlyRegionsDiffer]

/-- The complete source projector branching used by given-back selection.
Every immediate consumed/reprojection child remains in source order. An ended
borrow carries its exact original consumed identity and actual fresh type. -/
inductive GivenBackTree where
  | empty
  | loan (ended : Bool) (consumed borrows : List GivenBackTree)
  | borrow (header : Option SelectedBorrow) (loans : List GivenBackTree)
  deriving DecidableEq, Repr

/-- Fuel bounds traversal only; exhaustion refuses. A future subtree does not
belong to this ending, so it is not materialized. Its original tree is retained
for the separate call selecting its own level. -/
def selectBorrowHeaders : Nat → Nat → Nat → Nat → GivenBackTree → Option (List SelectedBorrow)
  | 0, _, _, _, _ => none
  | fuel + 1, typeFuel, selectedLevel, currentLevel, tree =>
      if currentLevel > selectedLevel then some [] else do
        let edges (children : List GivenBackTree) := children.foldlM (fun found child => do
          let next ← selectBorrowHeaders fuel typeFuel selectedLevel (currentLevel + 1) child
          pure (found ++ next)) []
        match tree with
        | .empty => pure []
        | .loan ended consumed borrows =>
            if !ended && decide (currentLevel = selectedLevel) then none else do
              let first ← edges consumed
              let second ← edges borrows
              pure (first ++ second)
        | .borrow header loans =>
            if currentLevel = selectedLevel then
              match header with
              | none => none
              | some actual =>
                  if onlyRegionsDiffer typeFuel actual.edgeType actual.currentType then
                    pure [actual]
                  else none
            else edges loans

/-- Pattern materialization must account for every selected header. A caller
cannot choose the first of several independently returned source values. -/
def singleBorrowHeader : List SelectedBorrow → Option (Option SelectedBorrow)
  | [] => some none
  | [header] => some (some header)
  | _ => none

theorem selected_outer_borrow_does_not_materialize_its_descendants
    (fuel typeFuel level : Nat) (header : SelectedBorrow) (loans : List GivenBackTree)
    (sameShape : onlyRegionsDiffer typeFuel header.edgeType header.currentType = true) :
    selectBorrowHeaders (fuel + 1) typeFuel level level (.borrow (some header) loans) =
      some [header] := by
  simp [selectBorrowHeaders, sameShape]

theorem a_future_projector_belongs_to_a_later_ending
    (fuel typeFuel selectedLevel currentLevel : Nat) (tree : GivenBackTree)
    (future : selectedLevel < currentLevel) :
    selectBorrowHeaders (fuel + 1) typeFuel selectedLevel currentLevel tree = some [] := by
  simp [selectBorrowHeaders, future]

theorem active_selected_borrow_cannot_mint_a_fresh_header
    (fuel typeFuel level : Nat) (loans : List GivenBackTree) :
    selectBorrowHeaders (fuel + 1) typeFuel level level (.borrow none loans) = none := by
  simp [selectBorrowHeaders]

theorem multiple_selected_headers_require_reconstruction
    (first second : SelectedBorrow) (remaining : List SelectedBorrow) :
    singleBorrowHeader (first :: second :: remaining) = none := by rfl

theorem a_single_selected_header_is_not_replaced (header : SelectedBorrow) :
    singleBorrowHeader [header] = some (some header) := by rfl

def Kind.isBorrow : Kind → Bool
  | .borrow _ => true
  | _ => false

def Kind.isLoan : Kind → Bool
  | .loan _ => true
  | _ => false

def selected (level : Nat) (observations : List Observation) : List Observation :=
  observations.filter (fun observation => observation.level == level)

/-- A level requiring both polarities needs a richer continuation and refuses;
no preferred branch or source value is chosen to make classification succeed. -/
def classify (level : Nat) (observations : List Observation) : Option Kind :=
  let current := selected level observations
  let borrows := current.any (fun observation => observation.kind.isBorrow)
  let loans := current.any (fun observation => observation.kind.isLoan)
  if borrows && loans then none
  else if borrows then some (.borrow (current.any (fun observation => observation.kind == .borrow true)))
  else if loans then some (.loan (current.any (fun observation => observation.kind == .loan true)))
  else some .unknown

/-- Every actual source wiring port is a mutable owned value and requires its
exact polarity. Origin classification can also retain an unchanged container
with no fresh ports; complete event-roster equality is checked separately. -/
def portsAgree (kind : Kind) (ports : List Port) : Bool :=
  match kind with
  | .borrow true => ports.all (·.givenBack)
  | .loan true => ports.all (fun port => !port.givenBack)
  | _ => ports.isEmpty

theorem borrow_classification_exact (level : Nat) (observations : List Observation) (mutable : Bool) :
    classify level observations = some (.borrow mutable) ↔
      (selected level observations).any (fun observation => observation.kind.isBorrow) = true ∧
      (selected level observations).any (fun observation => observation.kind.isLoan) = false ∧
      (selected level observations).any (fun observation => observation.kind == .borrow true) = mutable := by
  unfold classify
  cases borrows : (selected level observations).any (fun observation => observation.kind.isBorrow) <;>
    cases loans : (selected level observations).any (fun observation => observation.kind.isLoan) <;>
    simp [borrows, loans]

theorem loan_classification_exact (level : Nat) (observations : List Observation) (mutable : Bool) :
    classify level observations = some (.loan mutable) ↔
      (selected level observations).any (fun observation => observation.kind.isBorrow) = false ∧
      (selected level observations).any (fun observation => observation.kind.isLoan) = true ∧
      (selected level observations).any (fun observation => observation.kind == .loan true) = mutable := by
  unfold classify
  cases borrows : (selected level observations).any (fun observation => observation.kind.isBorrow) <;>
    cases loans : (selected level observations).any (fun observation => observation.kind.isLoan) <;>
    simp [borrows, loans]

theorem mixed_classification_refuses_exactly (level : Nat) (observations : List Observation) :
    classify level observations = none ↔
      (selected level observations).any (fun observation => observation.kind.isBorrow) = true ∧
      (selected level observations).any (fun observation => observation.kind.isLoan) = true := by
  unfold classify
  cases borrows : (selected level observations).any (fun observation => observation.kind.isBorrow) <;>
    cases loans : (selected level observations).any (fun observation => observation.kind.isLoan) <;>
    simp [borrows, loans]

theorem unknown_classification_exact (level : Nat) (observations : List Observation) :
    classify level observations = some .unknown ↔
      (selected level observations).any (fun observation => observation.kind.isBorrow) = false ∧
      (selected level observations).any (fun observation => observation.kind.isLoan) = false := by
  unfold classify
  cases borrows : (selected level observations).any (fun observation => observation.kind.isBorrow) <;>
    cases loans : (selected level observations).any (fun observation => observation.kind.isLoan) <;>
    simp [borrows, loans]

/-- A mutable classification needs a matching selected source observation.
That observation can record a retained container origin; fresh owned ports
remain a separate exact source roster, never inferred from the kind tag. -/
theorem mutable_borrow_classification_has_a_selected_observation
    (level : Nat) (observations : List Observation)
    (classified : classify level observations = some (.borrow true)) :
    ∃ observation ∈ observations, observation.level = level ∧ observation.kind = .borrow true := by
  have witness := (borrow_classification_exact level observations true).mp classified
  obtain ⟨observation, member, mutable⟩ := List.any_eq_true.mp witness.2.2
  have present := List.mem_filter.mp member
  refine ⟨observation, present.1, ?_, ?_⟩
  · simpa using present.2
  · simpa using mutable

theorem mutable_loan_classification_has_a_selected_observation
    (level : Nat) (observations : List Observation)
    (classified : classify level observations = some (.loan true)) :
    ∃ observation ∈ observations, observation.level = level ∧ observation.kind = .loan true := by
  have witness := (loan_classification_exact level observations true).mp classified
  obtain ⟨observation, member, mutable⟩ := List.any_eq_true.mp witness.2.2
  have present := List.mem_filter.mp member
  refine ⟨observation, present.1, ?_, ?_⟩
  · simpa using present.2
  · simpa using mutable

theorem borrow_ports_agree_exact (ports : List Port) :
    portsAgree (.borrow true) ports = true ↔
      ∀ port ∈ ports, port.givenBack = true := by
  simp [portsAgree, Bool.and_eq_true, List.all_eq_true]

theorem loan_ports_agree_exact (ports : List Port) :
    portsAgree (.loan true) ports = true ↔
      ∀ port ∈ ports, port.givenBack = false := by
  simp [portsAgree, Bool.and_eq_true, List.all_eq_true]

/-- A mixed mutable source roster cannot be certified by choosing either
polarity, a shared result, or an absent classification. -/
theorem mixed_mutable_ports_cannot_pass (kind : Kind) (ports : List Port)
    (given consumed : Port) (givenMember : given ∈ ports) (consumedMember : consumed ∈ ports)
    (givenBack : given.givenBack = true) (taken : consumed.givenBack = false) :
    portsAgree kind ports ≠ true := by
  have nonempty : ports.isEmpty = false := by
    cases ports with
    | nil => simp at givenMember
    | cons => rfl
  cases kind with
  | unknown => simp [portsAgree, nonempty]
  | borrow mutable =>
    cases mutable with
    | false => simp [portsAgree, nonempty]
    | true =>
      intro accepted
      have observed := (borrow_ports_agree_exact ports).mp accepted consumed consumedMember
      rw [taken] at observed
      contradiction
  | loan mutable =>
    cases mutable with
    | false => simp [portsAgree, nonempty]
    | true =>
      intro accepted
      have observed := (loan_ports_agree_exact ports).mp accepted given givenMember
      rw [givenBack] at observed
      contradiction

theorem other_levels_do_not_change_classification (level : Nat) (first rest : List Observation)
    (unrelated : ∀ observation ∈ first, observation.level ≠ level) :
    classify level (first ++ rest) = classify level rest := by
  have absent : selected level first = [] := by
    apply List.filter_eq_nil.mpr
    intro observation member
    simpa using unrelated observation member
  simp [classify, selected, List.filter_append, show first.filter (fun observation => observation.level == level) = [] from absent]

theorem a_deeper_opposite_header_does_not_change_the_current_level (level : Nat) (source : Expr) :
    classify level [⟨level, source, source, .borrow true⟩, ⟨level + 1, source, source, .loan true⟩] = some (.borrow true) := by
  simp [classify, selected, Kind.isBorrow, Kind.isLoan]

theorem a_mixed_selected_level_refuses (level : Nat) (first second : Expr) :
    classify level [⟨level, first, first, .borrow true⟩, ⟨level, second, second, .loan true⟩] = none := by
  simp [classify, selected, Kind.isBorrow, Kind.isLoan]

theorem no_observations_means_no_projected_ownership (level : Nat) :
    classify level [] = some .unknown := rfl

/-- No fresh ownership is invented for a context-only container. -/
theorem an_empty_roster_can_retain_its_container_origin (kind : Kind) :
    portsAgree kind [] = true := by
  cases kind with
  | unknown => rfl
  | borrow mutable => cases mutable <;> rfl
  | loan mutable => cases mutable <;> rfl

end Auths.Support.NativeProjectorKinds
