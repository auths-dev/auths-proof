import Auths.Verifier.StatusSummary
namespace Auths.StatusSelection.Algebra
open Model

def summaryFinish (cap now : Nat) : Summary → Evaluation
  | .rollback => ⟨.rollback, now⟩
  | .details facts =>
    if !facts.candidate then ⟨.missing, cap⟩
    else if !facts.matching then ⟨.wrongMethod, now⟩
    else match facts.latest with
      | none => ⟨.untrusted, now⟩
      | some latest => if latest.stale then ⟨.stale, now⟩
        else ⟨if latest.revoked then .revoked else .active, latest.through⟩

theorem finish_normalize (cap now : Nat) (state : Scan) (bound : state.through ≤ cap) :
    finish cap now state = summaryFinish cap now (normalize cap state) := by
  cases state with
  | mk candidate matching rollback maximum stale revoked through =>
    cases candidate <;> cases matching <;> cases rollback <;>
      cases maximum <;> cases stale <;> cases revoked <;>
      simp_all [finish, normalize, summaryFinish]

theorem contribute_bound {Subject : Type} (cap age now : Nat) (row : Statement Subject)
    (state : Scan) (bound : state.through ≤ cap) :
    (contribute cap age now row state).through ≤ cap := by
  unfold contribute
  cases state.maximum <;> dsimp only <;> (try split_ifs) <;> simp_all

theorem record_bound {Subject : Type} [BEq Subject] (cap age now : Nat)
    (method : String) (rules : List Rule) (subject : Subject) (view : View)
    (row : Statement Subject) (state : Scan) (bound : state.through ≤ cap) :
    (record cap age now method rules subject view row state).through ≤ cap := by
  unfold record
  split_ifs
  · cases sequenceFloor rules method row.issuer <;> dsimp only
    · exact bound
    · split_ifs
      · exact bound
      · exact contribute_bound cap age now row _ bound
  · exact bound
  · exact bound

theorem scan_bound {Subject : Type} [BEq Subject] (cap age now : Nat)
    (method : String) (rules : List Rule) (subject : Subject) (view : View)
    (rows : List (Statement Subject)) (state : Scan) (bound : state.through ≤ cap) :
    (scan cap age now method rules subject view rows state).through ≤ cap := by
  induction rows generalizing state with
  | nil => exact bound
  | cons row rest ih =>
    simp only [scan]
    split_ifs
    · exact bound
    · exact ih _ (record_bound cap age now method rules subject view row state bound)

theorem scan_finish_independent {Subject : Type} [BEq Subject] (cap age now : Nat)
    (method : String) (rules : List Rule) (subject : Subject) (view : View)
    (rows : List (Statement Subject)) :
    finish cap now (scan cap age now method rules subject view rows (initial cap)) =
      summaryFinish cap now (independentAggregate cap age now method rules subject view rows) := by
  rw [finish_normalize cap now _ (scan_bound cap age now method rules subject view rows _ (by rfl))]
  rw [normalize_scan, normalize_initial, combine_empty_left, aggregate_independent]

end Auths.StatusSelection.Algebra
