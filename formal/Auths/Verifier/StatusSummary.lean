import Auths.Verifier.StatusLatest
namespace Auths.StatusSelection.Algebra
open Model

def candidates {Subject : Type} [BEq Subject] (rules : List Rule) (subject : Subject)
    (view : View) (rows : List (Statement Subject)) : List (Statement Subject) :=
  rows.filter (fun row => row.subject == subject && visible rules row.issuer view)

def matching {Subject : Type} (method : String) (rows : List (Statement Subject)) : List (Statement Subject) :=
  rows.filter (fun row => row.method == method)

def trusted {Subject : Type} (method : String) (rules : List Rule)
    (rows : List (Statement Subject)) : List (Statement Subject × Nat) :=
  rows.filterMap (fun row => (sequenceFloor rules method row.issuer).map (fun floor => (row, floor)))

def latestRow {Subject : Type} (cap age now : Nat) (pair : Statement Subject × Nat) : Latest :=
  ⟨pair.1.sequence, !fresh age pair.1.observed pair.1.expiresAt now, !pair.1.active,
    min cap (deadline age pair.1.observed pair.1.expiresAt)⟩

def independentAggregate {Subject : Type} [BEq Subject] (cap age now : Nat)
    (method : String) (rules : List Rule) (subject : Subject) (view : View)
    (rows : List (Statement Subject)) : Summary :=
  let selected := candidates rules subject view rows
  let exact := matching method selected
  let admitted := trusted method rules exact
  if admitted.any (fun pair => pair.1.sequence < pair.2) then .rollback
  else .details ⟨!selected.isEmpty, !exact.isEmpty,
    collectLatest (admitted.map (latestRow cap age now))⟩

theorem aggregate_independent {Subject : Type} [BEq Subject] (cap age now : Nat)
    (method : String) (rules : List Rule) (subject : Subject) (view : View)
    (rows : List (Statement Subject)) :
    aggregate cap age now method rules subject view rows =
      independentAggregate cap age now method rules subject view rows := by
  induction rows with
  | nil => rfl
  | cons row rest ih =>
    rw [aggregate, ih]
    unfold prepared independentAggregate candidates matching trusted
    by_cases candidate : (row.subject == subject && visible rules row.issuer view) = true
    · simp only [List.filter_cons, candidate, ↓reduceIte]
      by_cases matched : (row.method == method) = true
      · simp only [matched, ↓reduceIte]
        cases floorEquation : sequenceFloor rules method row.issuer with
        | none =>
          simp only [List.filterMap_cons, floorEquation, Option.map_none,
            List.isEmpty_cons]
          split_ifs <;> simp [combine, mergeLatest_none_left]
        | some floor =>
          simp only [List.filterMap_cons, floorEquation, Option.map_some,
            List.map_cons, List.isEmpty_cons, List.any_cons, collectLatest]
          by_cases below : row.sequence < floor
          · simp [below, combine]
          · simp only [below, decide_false, Bool.false_or, ↓reduceIte]
            split_ifs <;> simp [combine, latestRow]
      · simp only [matched, Bool.false_eq_true, ↓reduceIte, List.isEmpty_cons]
        split_ifs <;> simp [combine, mergeLatest_none_left]
    · simp only [candidate, Bool.false_eq_true, ↓reduceIte, List.filter_cons]
      exact combine_empty_left _

end Auths.StatusSelection.Algebra
