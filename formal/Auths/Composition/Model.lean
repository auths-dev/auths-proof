import Auths.Composition.Diagnostics

open auths_composition
namespace Auths.Composition.Model

def retainMinimum {α : Type} (rank : α → Nat) (previous : Option α) (candidate : α) : Option α :=
  match previous with
  | none => some candidate
  | some previous => if rank candidate < rank previous then some candidate else some previous

structure Summary where
  authorized : Nat
  indeterminate : Nat
  denial : Option auths_composition.auths_model.DenialReason
  requirement : Option auths_composition.auths_model.Requirement

def record (state : Summary) : BranchOutcome → Summary
  | .Authorized => { state with authorized := state.authorized + 1 }
  | .Denied reason | .StructurallyInvalid reason =>
      { state with denial := retainMinimum denialRank state.denial reason }
  | .Indeterminate requirement =>
      ⟨state.authorized, state.indeterminate + 1, state.denial,
        retainMinimum requirementRank state.requirement requirement⟩

def allOutcome (state : Summary) : BranchOutcome :=
  match state.denial, state.requirement with
  | some reason, _ => .Denied reason
  | none, some requirement => .Indeterminate requirement
  | none, none => .Authorized

def thresholdOutcome (required : Nat) (state : Summary) : BranchOutcome :=
  if required ≤ state.authorized then .Authorized
  else if required ≤ state.authorized + state.indeterminate then
    .Indeterminate (state.requirement.getD .ExternalFactUnavailable)
  else .Denied (state.denial.getD .AuthorizationPlanInvalid)


def empty : Summary := ⟨0, 0, none, none⟩

def summarize (outcomes : List BranchOutcome) : Summary := outcomes.foldl record empty

def authorizedCount (outcomes : List BranchOutcome) : Nat :=
  outcomes.countP fun | .Authorized => true | _ => false

def indeterminateCount (outcomes : List BranchOutcome) : Nat :=
  outcomes.countP fun | .Indeterminate _ => true | _ => false

def denialOf : BranchOutcome → Option auths_composition.auths_model.DenialReason
  | .Denied reason | .StructurallyInvalid reason => some reason
  | _ => none

def requirementOf : BranchOutcome → Option auths_composition.auths_model.Requirement
  | .Indeterminate requirement => some requirement
  | _ => none

def Least {α : Type} (rank : α → Nat) (inputs : List α) : Option α → Prop
  | none => inputs = []
  | some value => value ∈ inputs ∧ ∀ candidate ∈ inputs, rank value ≤ rank candidate

theorem retain_minimum_least {α : Type} (rank : α → Nat) (inputs : List α)
    (previous : Option α) (candidate : α) (least : Least rank inputs previous) :
    Least rank (inputs ++ [candidate]) (retainMinimum rank previous candidate) := by
  cases previous with
  | none => simp_all [Least, retainMinimum]
  | some previous =>
    simp only [Least] at least
    simp only [retainMinimum]
    split <;> rename_i before
    · simp only [Least, List.mem_append, List.mem_singleton]
      constructor
      · exact Or.inr trivial
      · intro value present
        rcases present with present | rfl
        · have bound := least.2 value present
          omega
        · omega
    · simp only [Least, List.mem_append, List.mem_singleton]
      constructor
      · exact Or.inl least.1
      · intro value present
        rcases present with present | rfl
        · exact least.2 value present
        · omega

def Matches (state : Summary) (outcomes : List BranchOutcome) : Prop :=
  state.authorized = authorizedCount outcomes ∧
  state.indeterminate = indeterminateCount outcomes ∧
  Least denialRank (outcomes.filterMap denialOf) state.denial ∧
  Least requirementRank (outcomes.filterMap requirementOf) state.requirement

theorem record_matches (state : Summary) (outcomes : List BranchOutcome)
    (outcome : BranchOutcome) (invariant : Matches state outcomes) :
    Matches (record state outcome) (outcomes ++ [outcome]) := by
  rcases invariant with ⟨authorized, indeterminate, denial, requirement⟩
  have denialNext (candidate : auths_composition.auths_model.DenialReason) :=
    retain_minimum_least denialRank (outcomes.filterMap denialOf) state.denial candidate denial
  have requirementNext (candidate : auths_composition.auths_model.Requirement) :=
    retain_minimum_least requirementRank (outcomes.filterMap requirementOf) state.requirement candidate requirement
  cases h : outcome <;>
    simp_all [Matches, record, authorizedCount, indeterminateCount, denialOf,
      requirementOf, List.countP_append]

theorem summarize_matches (outcomes : List BranchOutcome) :
    Matches (summarize outcomes) outcomes := by
  induction outcomes using List.reverseRecOn with
  | nil => simp [Matches, summarize, empty, authorizedCount, indeterminateCount, Least]
  | append_singleton previous outcome ih =>
    simpa [summarize, List.foldl_append] using record_matches _ _ outcome ih

theorem threshold_authorized_iff (required : Nat) (state : Summary) :
    thresholdOutcome required state = .Authorized ↔ required ≤ state.authorized := by
  unfold thresholdOutcome
  split <;> (try split) <;> simp_all

theorem all_authorized_iff (state : Summary) :
    allOutcome state = .Authorized ↔ state.denial = none ∧ state.requirement = none := by
  cases hd : state.denial <;> cases hi : state.requirement <;>
    simp [allOutcome, hd, hi]

theorem least_none_iff_empty {α : Type} (rank : α → Nat) (inputs : List α)
    (selected : Option α) (least : Least rank inputs selected) :
    selected = none ↔ inputs = [] := by
  cases selected with
  | none => simp_all [Least]
  | some value =>
    simp only [Least] at least
    constructor
    · intro impossible
      cases impossible
    · intro empty
      simp [empty] at least

theorem all_children_authorize_iff (outcomes : List BranchOutcome) :
    allOutcome (summarize outcomes) = .Authorized ↔
      ∀ outcome ∈ outcomes, outcome = .Authorized := by
  have invariant := summarize_matches outcomes
  rw [all_authorized_iff,
    least_none_iff_empty denialRank _ _ invariant.2.2.1,
    least_none_iff_empty requirementRank _ _ invariant.2.2.2]
  clear invariant
  induction outcomes with
  | nil => simp
  | cons outcome remaining ih =>
    cases h : outcome <;> simp_all [denialOf, requirementOf]

theorem threshold_children_authorize_iff (required : Nat) (outcomes : List BranchOutcome) :
    thresholdOutcome required (summarize outcomes) = .Authorized ↔
      required ≤ authorizedCount outcomes := by
  rw [threshold_authorized_iff, (summarize_matches outcomes).1]

end Auths.Composition.Model
