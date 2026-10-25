import Auths.Verifier.StatusModel
import Mathlib.Tactic
namespace Auths.StatusSelection.Algebra
open Model

structure Latest where
  sequence : Nat
  stale : Bool
  revoked : Bool
  through : Nat
  deriving DecidableEq

def mergeLatest : Option Latest → Option Latest → Option Latest
  | none, right => right
  | left, none => left
  | some left, some right =>
    if left.sequence < right.sequence then some right
    else if right.sequence < left.sequence then some left
    else some ⟨left.sequence, left.stale || right.stale, left.revoked || right.revoked,
      min left.through right.through⟩

theorem mergeLatest_none_left (right : Option Latest) : mergeLatest none right = right := rfl

theorem mergeLatest_none_right (left : Option Latest) : mergeLatest left none = left := by
  cases left <;> rfl

theorem mergeLatest_comm (left right : Option Latest) : mergeLatest left right = mergeLatest right left := by
  cases left <;> cases right <;> simp only [mergeLatest]
  split_ifs <;> simp_all [Latest.mk.injEq, Bool.or_comm, Nat.min_comm] <;> omega

theorem mergeLatest_assoc (left middle right : Option Latest) :
    mergeLatest (mergeLatest left middle) right = mergeLatest left (mergeLatest middle right) := by
  cases left with
  | none => simp [mergeLatest]
  | some a =>
    cases middle with
    | none => simp [mergeLatest]
    | some b =>
      cases right with
      | none => simp [mergeLatest_none_right]
      | some c =>
        by_cases ab : a.sequence < b.sequence <;>
          by_cases ba : b.sequence < a.sequence <;>
          by_cases ac : a.sequence < c.sequence <;>
          by_cases ca : c.sequence < a.sequence <;>
          by_cases bc : b.sequence < c.sequence <;>
          by_cases cb : c.sequence < b.sequence <;>
          simp only [mergeLatest, ab, ba, ac, ca, bc, cb, ↓reduceIte] <;>
          simp_all [Latest.mk.injEq, Bool.or_assoc, Nat.min_assoc] <;> omega

structure Facts where
  candidate : Bool
  matching : Bool
  latest : Option Latest
  deriving DecidableEq

inductive Summary where
  | rollback
  | details (facts : Facts)
  deriving DecidableEq

def combine : Summary → Summary → Summary
  | .rollback, _ => .rollback
  | _, .rollback => .rollback
  | .details left, .details right => .details
      ⟨left.candidate || right.candidate, left.matching || right.matching, mergeLatest left.latest right.latest⟩

def empty : Summary := .details ⟨false, false, none⟩

theorem combine_assoc (left middle right : Summary) :
    combine (combine left middle) right = combine left (combine middle right) := by
  cases left <;> cases middle <;> cases right <;>
    simp [combine, mergeLatest_assoc, Bool.or_assoc]

theorem combine_empty_left (right : Summary) : combine empty right = right := by
  cases right <;> simp [combine, empty, mergeLatest]

theorem combine_empty_right (left : Summary) : combine left empty = left := by
  cases left <;> simp [combine, empty, mergeLatest_none_right]

def normalize (expiresAt : Nat) (state : Scan) : Summary :=
  if state.rollback then .rollback
  else .details ⟨state.candidateSeen, state.methodSeen,
    state.maximum.map (fun sequence =>
      ⟨sequence, state.stale, state.revoked, min expiresAt state.through⟩)⟩

def prepared {Subject : Type} [BEq Subject] (expiresAt age now : Nat)
    (method : String) (rules : List Rule) (subject : Subject) (view : View) (row : Statement Subject) : Summary :=
  if row.subject == subject && visible rules row.issuer view then
    if row.method == method then
      match sequenceFloor rules method row.issuer with
      | none => .details ⟨true, true, none⟩
      | some floor => if row.sequence < floor then .rollback
        else .details ⟨true, true, some ⟨row.sequence, !fresh age row.observed row.expiresAt now,
          !row.active, min expiresAt (deadline age row.observed row.expiresAt)⟩⟩
    else .details ⟨true, false, none⟩
  else empty

theorem normalize_contribute {Subject : Type} (expiresAt age now : Nat)
    (row : Statement Subject) (state : Scan) :
    normalize expiresAt (contribute expiresAt age now row state) =
      combine (normalize expiresAt state)
        (.details ⟨false, false, some ⟨row.sequence,
          !fresh age row.observed row.expiresAt now, !row.active,
          min expiresAt (deadline age row.observed row.expiresAt)⟩⟩) := by
  cases state with
  | mk candidate matching rollback maximum stale revoked through =>
    cases rollback <;> cases maximum <;>
      simp only [normalize, contribute, combine, mergeLatest, Option.map,
        Bool.false_eq_true, ↓reduceIte]
    all_goals split_ifs <;>
      simp_all [Latest.mk.injEq, Facts.mk.injEq, Bool.or_comm,
        Nat.min_assoc, Nat.min_left_comm] <;> omega

theorem normalize_record {Subject : Type} [BEq Subject] (expiresAt age now : Nat)
    (method : String) (rules : List Rule) (subject : Subject) (view : View)
    (row : Statement Subject) (state : Scan) :
    normalize expiresAt (record expiresAt age now method rules subject view row state) =
      combine (normalize expiresAt state) (prepared expiresAt age now method rules subject view row) := by
  unfold record prepared
  split_ifs
  · cases floorEquation : sequenceFloor rules method row.issuer with
    | none =>
      cases state with
      | mk candidate matching rollback maximum stale revoked through =>
        cases rollback <;> simp [normalize, combine, mergeLatest_none_right]
    | some floor =>
      dsimp only
      split_ifs
      · cases state with
        | mk candidate matching rollback maximum stale revoked through =>
          cases rollback <;> simp [normalize, combine]
      · rw [normalize_contribute]
        cases state with
        | mk candidate matching rollback maximum stale revoked through =>
          cases rollback <;> simp [normalize, combine]
  · cases state with
    | mk candidate matching rollback maximum stale revoked through =>
      cases rollback <;> simp [normalize, combine, mergeLatest_none_right]
  · simp [combine_empty_right]

def aggregate {Subject : Type} [BEq Subject] (expiresAt age now : Nat)
    (method : String) (rules : List Rule) (subject : Subject) (view : View) :
    List (Statement Subject) → Summary
  | [] => empty
  | row :: rest => combine (prepared expiresAt age now method rules subject view row)
      (aggregate expiresAt age now method rules subject view rest)

theorem normalize_scan {Subject : Type} [BEq Subject] (expiresAt age now : Nat)
    (method : String) (rules : List Rule) (subject : Subject) (view : View)
    (rows : List (Statement Subject)) (state : Scan) :
    normalize expiresAt (scan expiresAt age now method rules subject view rows state) =
      combine (normalize expiresAt state) (aggregate expiresAt age now method rules subject view rows) := by
  induction rows generalizing state with
  | nil => simp [scan, aggregate, combine_empty_right]
  | cons row rest ih =>
    simp only [scan, aggregate]
    split_ifs with stopped
    · simp [normalize, stopped, combine]
    · rw [ih, normalize_record, combine_assoc]

theorem normalize_initial (expiresAt : Nat) : normalize expiresAt (initial expiresAt) = empty := rfl

end Auths.StatusSelection.Algebra
