import qualification.aeneas.generated.model.Funs
import Auths.Codec.SnapshotUniqueness

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Codec.SnapshotRefinement
open SnapshotUniqueness

-- Concrete source scans, parametrized only by an explicit element-equality
-- contract. Instantiating that contract with full unsigned statement equality
-- is a separate required derived-comparison obligation. No source function is
-- declared opaque, replaced by an axiom or assumed to return this scan's result.

section Principal
variable {Key : Type} [DecidableEq Key]
variable (view : auths_model.SignedPrincipalStatus → Key)
variable (comparison : ∀ left right,
  auths_model.status_snapshot.principal_equal left right
    ⦃ actual => actual = decide (view left = view right) ⦄)

private theorem principal_prefix_loop (fuel : Nat)
    (values : Slice auths_model.SignedPrincipalStatus) (current position : Std.Usize) (matched : Bool)
    (within : current.val < values.val.length) (remaining : current.val = position.val + fuel) :
    auths_model.status_snapshot.principal_matches_before_loop values current position matched
      ⦃ actual => actual = matched || search (values.val.map view)
        (view values.val[current.val]) position.val fuel ⦄ := by
  induction fuel generalizing position matched with
  | zero =>
    have guard : ¬ position < current := by scalar_tac
    unfold auths_model.status_snapshot.principal_matches_before_loop
    rw [loop.eq_def]
    simp [auths_model.status_snapshot.principal_matches_before_loop.body, guard, search]
  | succ fuel ih =>
    cases matched with
    | true =>
      unfold auths_model.status_snapshot.principal_matches_before_loop
      rw [loop.eq_def]
      simp [auths_model.status_snapshot.principal_matches_before_loop.body]
    | false =>
      have guard : position < current := by scalar_tac
      have indexedBound : position.val < values.val.length := by omega
      let first := values.val[position.val]
      let target := values.val[current.val]
      have indexed : Slice.index_usize values position = ok first := by
        simp [Slice.index_usize, first, indexedBound]
      have currentIndexed : Slice.index_usize values current = ok target := by
        simp [Slice.index_usize, target, within]
      obtain ⟨equal, evaluates, equalMeaning⟩ := spec_imp_exists (comparison first target)
      have incrementFits : position.val + 1 ≤ Usize.max := by
        have capacity := values.property
        omega
      obtain ⟨next, addition, nextMeaning⟩ := spec_imp_exists
        (Usize.add_spec (x := position) (y := 1#usize) incrementFits)
      have nextValue : next.val = position.val + 1 := by simpa using nextMeaning
      have nextRemaining : current.val = next.val + fuel := by omega
      have tail := ih next equal nextRemaining
      have present : (values.val.map view)[position.val]? = some (view first) := by
        simp [List.getElem?_map, List.getElem?_eq_getElem indexedBound, first]
      unfold auths_model.status_snapshot.principal_matches_before_loop
      rw [loop.eq_def]
      simp only [auths_model.status_snapshot.principal_matches_before_loop.body, guard,
        Bool.not_false, Bool.true_eq_true, ↓reduceIte, bind_tc_ok,
        indexed, currentIndexed, evaluates, addition]
      apply spec_mono tail
      intro actual meaning
      simpa [search, present, nextValue, equalMeaning, target] using meaning

@[step] theorem principal_before_exact
    (values : Slice auths_model.SignedPrincipalStatus) (current : Std.Usize) :
    auths_model.status_snapshot.principal_matches_before values current
      ⦃ actual => actual = before (values.val.map view) current.val ⦄ := by
  by_cases within : current.val < values.val.length
  · have guard : ¬ current >= Slice.len values := by simpa [Slice.length] using within.not_ge
    unfold auths_model.status_snapshot.principal_matches_before
    simp only [guard, ↓reduceIte]
    have present : (values.val.map view)[current.val]? = some (view values.val[current.val]) := by
      simp [List.getElem?_map, List.getElem?_eq_getElem within]
    apply spec_mono (principal_prefix_loop view comparison current.val values current 0#usize false within (by simp))
    intro actual meaning
    simpa [search_initial _ _ _ present] using meaning
  · have outside : values.val.length ≤ current.val := Nat.le_of_not_gt within
    have guard : current >= Slice.len values := by simpa [Slice.length] using outside
    have absent : (values.val.map view)[current.val]? = none := by
      apply List.getElem?_eq_none_iff.mpr
      simpa using outside
    simp [auths_model.status_snapshot.principal_matches_before, guard, before, absent]

private theorem principal_duplicate_loop (fuel : Nat)
    (values : Slice auths_model.SignedPrincipalStatus) (current : Std.Usize) (matched : Bool)
    (remaining : values.val.length = current.val + fuel) :
    auths_model.status_snapshot.principal_has_duplicate_loop values current matched
      ⦃ actual => actual = matched || from (values.val.map view) current.val fuel ⦄ := by
  induction fuel generalizing current matched with
  | zero =>
    have guard : ¬ current < Slice.len values := by simpa [Slice.length] using Nat.not_lt.mpr (by omega)
    unfold auths_model.status_snapshot.principal_has_duplicate_loop
    rw [loop.eq_def]
    simp [auths_model.status_snapshot.principal_has_duplicate_loop.body, guard, from]
  | succ fuel ih =>
    cases matched with
    | true =>
      unfold auths_model.status_snapshot.principal_has_duplicate_loop
      rw [loop.eq_def]
      simp [auths_model.status_snapshot.principal_has_duplicate_loop.body]
    | false =>
      have inside : current.val < values.val.length := by omega
      have guard : current < Slice.len values := by simpa [Slice.length] using inside
      obtain ⟨equal, evaluates, meaning⟩ := spec_imp_exists (principal_before_exact view comparison values current)
      have incrementFits : current.val + 1 ≤ Usize.max := by
        have capacity := values.property
        omega
      obtain ⟨next, addition, nextMeaning⟩ := spec_imp_exists
        (Usize.add_spec (x := current) (y := 1#usize) incrementFits)
      have nextValue : next.val = current.val + 1 := by simpa using nextMeaning
      have tail := ih next equal (by omega)
      unfold auths_model.status_snapshot.principal_has_duplicate_loop
      rw [loop.eq_def]
      simp only [auths_model.status_snapshot.principal_has_duplicate_loop.body, guard,
        Bool.not_false, Bool.true_eq_true, ↓reduceIte, bind_tc_ok, evaluates, addition]
      apply spec_mono tail
      intro actual result
      simpa [from, nextValue, meaning] using result

/-- The complete shipping duplicate scan agrees with an independent global
no-duplicate relation, conditional on its concrete element-comparison law. -/
@[step] theorem principal_duplicates_exact (values : Slice auths_model.SignedPrincipalStatus) :
    auths_model.status_snapshot.principal_has_duplicate values
      ⦃ actual => actual = hasDuplicate (values.val.map view) ⦄ := by
  unfold auths_model.status_snapshot.principal_has_duplicate
  apply spec_mono (principal_duplicate_loop view comparison values.val.length values 0#usize false (by simp))
  intro actual meaning
  simpa [← complete_scan_exact] using meaning

theorem principal_earns_uniqueness (values : Slice auths_model.SignedPrincipalStatus) :
    auths_model.status_snapshot.principal_has_duplicate values
      ⦃ actual => actual = false → (values.val.map view).Nodup ⦄ := by
  apply spec_mono (principal_duplicates_exact view comparison values)
  intro actual meaning clean
  exact (no_duplicate_iff _).mp (meaning.symm.trans clean)

end Principal

section Grant
variable {Key : Type} [DecidableEq Key]
variable (view : auths_model.SignedGrantStatus → Key)
variable (comparison : ∀ left right,
  auths_model.status_snapshot.grant_equal left right
    ⦃ actual => actual = decide (view left = view right) ⦄)

private theorem grant_prefix_loop (fuel : Nat)
    (values : Slice auths_model.SignedGrantStatus) (current position : Std.Usize) (matched : Bool)
    (within : current.val < values.val.length) (remaining : current.val = position.val + fuel) :
    auths_model.status_snapshot.grant_matches_before_loop values current position matched
      ⦃ actual => actual = matched || search (values.val.map view)
        (view values.val[current.val]) position.val fuel ⦄ := by
  induction fuel generalizing position matched with
  | zero =>
    have guard : ¬ position < current := by scalar_tac
    unfold auths_model.status_snapshot.grant_matches_before_loop
    rw [loop.eq_def]
    simp [auths_model.status_snapshot.grant_matches_before_loop.body, guard, search]
  | succ fuel ih =>
    cases matched with
    | true =>
      unfold auths_model.status_snapshot.grant_matches_before_loop
      rw [loop.eq_def]
      simp [auths_model.status_snapshot.grant_matches_before_loop.body]
    | false =>
      have guard : position < current := by scalar_tac
      have indexedBound : position.val < values.val.length := by omega
      let first := values.val[position.val]
      let target := values.val[current.val]
      have indexed : Slice.index_usize values position = ok first := by
        simp [Slice.index_usize, first, indexedBound]
      have currentIndexed : Slice.index_usize values current = ok target := by
        simp [Slice.index_usize, target, within]
      obtain ⟨equal, evaluates, equalMeaning⟩ := spec_imp_exists (comparison first target)
      have incrementFits : position.val + 1 ≤ Usize.max := by
        have capacity := values.property
        omega
      obtain ⟨next, addition, nextMeaning⟩ := spec_imp_exists
        (Usize.add_spec (x := position) (y := 1#usize) incrementFits)
      have nextValue : next.val = position.val + 1 := by simpa using nextMeaning
      have nextRemaining : current.val = next.val + fuel := by omega
      have tail := ih next equal nextRemaining
      have present : (values.val.map view)[position.val]? = some (view first) := by
        simp [List.getElem?_map, List.getElem?_eq_getElem indexedBound, first]
      unfold auths_model.status_snapshot.grant_matches_before_loop
      rw [loop.eq_def]
      simp only [auths_model.status_snapshot.grant_matches_before_loop.body, guard,
        Bool.not_false, Bool.true_eq_true, ↓reduceIte, bind_tc_ok,
        indexed, currentIndexed, evaluates, addition]
      apply spec_mono tail
      intro actual meaning
      simpa [search, present, nextValue, equalMeaning, target] using meaning

@[step] theorem grant_before_exact
    (values : Slice auths_model.SignedGrantStatus) (current : Std.Usize) :
    auths_model.status_snapshot.grant_matches_before values current
      ⦃ actual => actual = before (values.val.map view) current.val ⦄ := by
  by_cases within : current.val < values.val.length
  · have guard : ¬ current >= Slice.len values := by simpa [Slice.length] using within.not_ge
    unfold auths_model.status_snapshot.grant_matches_before
    simp only [guard, ↓reduceIte]
    have present : (values.val.map view)[current.val]? = some (view values.val[current.val]) := by
      simp [List.getElem?_map, List.getElem?_eq_getElem within]
    apply spec_mono (grant_prefix_loop view comparison current.val values current 0#usize false within (by simp))
    intro actual meaning
    simpa [search_initial _ _ _ present] using meaning
  · have outside : values.val.length ≤ current.val := Nat.le_of_not_gt within
    have guard : current >= Slice.len values := by simpa [Slice.length] using outside
    have absent : (values.val.map view)[current.val]? = none := by
      apply List.getElem?_eq_none_iff.mpr
      simpa using outside
    simp [auths_model.status_snapshot.grant_matches_before, guard, before, absent]

private theorem grant_duplicate_loop (fuel : Nat)
    (values : Slice auths_model.SignedGrantStatus) (current : Std.Usize) (matched : Bool)
    (remaining : values.val.length = current.val + fuel) :
    auths_model.status_snapshot.grant_has_duplicate_loop values current matched
      ⦃ actual => actual = matched || from (values.val.map view) current.val fuel ⦄ := by
  induction fuel generalizing current matched with
  | zero =>
    have guard : ¬ current < Slice.len values := by simpa [Slice.length] using Nat.not_lt.mpr (by omega)
    unfold auths_model.status_snapshot.grant_has_duplicate_loop
    rw [loop.eq_def]
    simp [auths_model.status_snapshot.grant_has_duplicate_loop.body, guard, from]
  | succ fuel ih =>
    cases matched with
    | true =>
      unfold auths_model.status_snapshot.grant_has_duplicate_loop
      rw [loop.eq_def]
      simp [auths_model.status_snapshot.grant_has_duplicate_loop.body]
    | false =>
      have inside : current.val < values.val.length := by omega
      have guard : current < Slice.len values := by simpa [Slice.length] using inside
      obtain ⟨equal, evaluates, meaning⟩ := spec_imp_exists (grant_before_exact view comparison values current)
      have incrementFits : current.val + 1 ≤ Usize.max := by
        have capacity := values.property
        omega
      obtain ⟨next, addition, nextMeaning⟩ := spec_imp_exists
        (Usize.add_spec (x := current) (y := 1#usize) incrementFits)
      have nextValue : next.val = current.val + 1 := by simpa using nextMeaning
      have tail := ih next equal (by omega)
      unfold auths_model.status_snapshot.grant_has_duplicate_loop
      rw [loop.eq_def]
      simp only [auths_model.status_snapshot.grant_has_duplicate_loop.body, guard,
        Bool.not_false, Bool.true_eq_true, ↓reduceIte, bind_tc_ok, evaluates, addition]
      apply spec_mono tail
      intro actual result
      simpa [from, nextValue, meaning] using result

/-- The complete shipping duplicate scan agrees with an independent global
no-duplicate relation, conditional on its concrete element-comparison law. -/
@[step] theorem grant_duplicates_exact (values : Slice auths_model.SignedGrantStatus) :
    auths_model.status_snapshot.grant_has_duplicate values
      ⦃ actual => actual = hasDuplicate (values.val.map view) ⦄ := by
  unfold auths_model.status_snapshot.grant_has_duplicate
  apply spec_mono (grant_duplicate_loop view comparison values.val.length values 0#usize false (by simp))
  intro actual meaning
  simpa [← complete_scan_exact] using meaning

theorem grant_earns_uniqueness (values : Slice auths_model.SignedGrantStatus) :
    auths_model.status_snapshot.grant_has_duplicate values
      ⦃ actual => actual = false → (values.val.map view).Nodup ⦄ := by
  apply spec_mono (grant_duplicates_exact view comparison values)
  intro actual meaning clean
  exact (no_duplicate_iff _).mp (meaning.symm.trans clean)

end Grant

end Auths.Codec.SnapshotRefinement
