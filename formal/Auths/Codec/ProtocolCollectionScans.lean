import qualification.aeneas.generated.protocol_codec.Funs
import Auths.Codec.CollectionInvariants
import Auths.Verifier.StatusLeaves

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Codec.ProtocolCollectionScans
open SnapshotUniqueness
set_option maxHeartbeats 2000000
set_option maxRecDepth 4096

/- This is the actual generic source scan, with an explicit trait-interface
law. The law concerns each element comparison, not an expected scan, constructor
or verifier result. Concrete Auths-derived equality dictionaries still have to
discharge it at constructor callers; an opaque Auths algorithm is not admitted
as an implementation of this law. The view must represent the whole identity
that the relevant constructor compares, not an unproved digest surrogate. -/
variable {T Key : Type} [DecidableEq Key]
variable (equality : Aeneas.Std.core.cmp.PartialEq T T) (view : T → Key)
variable (elementLaw : ∀ left right,
  equality.eq left right = ok (decide (view left = view right)))

private theorem indexed (values : Slice T) (position : Std.Usize) (value : T)
    (present : values.val[position.val]? = some value) :
    Slice.index_usize values position = ok value := by
  simp [Slice.index_usize, present]

private theorem adjacent_stopped (values : Slice T) (position : Std.Usize) :
    @auths_model.collection_scan.adjacent_equal_loop T equality values position true = ok true := by
  rw [auths_model.collection_scan.adjacent_equal_loop.eq_def]
  simp

private theorem adjacent_suffix (values : Slice T) (position : Std.Usize)
    (previous : T) (rest : List T) (positive : 0 < position.val)
    (remaining : values.val.drop position.val = rest)
    (before : values.val[position.val - 1]? = some previous) :
    @auths_model.collection_scan.adjacent_equal_loop T equality values position false =
      ok (CollectionInvariants.adjacent (view previous :: rest.map view)) := by
  induction rest generalizing position previous with
  | nil =>
    have finished : ¬ position < values.len := by
      have size := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at size
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [auths_model.collection_scan.adjacent_equal_loop.eq_def]
    simp [finished, CollectionInvariants.adjacent]
  | cons head tail ih =>
    obtain ⟨guard, atHead⟩ := Auths.StatusSelection.indexed_head values position head tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position head tail remaining
    obtain ⟨prior, subtraction, priorValue, _⟩ := spec_imp_exists
      (Usize.sub_spec (x := position) (y := 1#usize) (by simpa using Nat.succ_le_of_lt positive))
    have atPrior : values.val[prior.val]? = some previous := by simpa [priorValue] using before
    have inside : position.val < values.val.length := by
      simpa only [UScalar.lt_equiv, Slice.len_val, Slice.length] using guard
    have atHeadOption : values.val[position.val]? = some head := by
      have decomposition := List.drop_eq_getElem_cons inside
      rw [remaining] at decomposition
      have same := (List.cons.inj decomposition).1.symm
      simpa [List.getElem?_eq_getElem inside] using congrArg some same
    have nextBefore : values.val[next.val - 1]? = some head := by simpa [nextValue] using atHeadOption
    rw [auths_model.collection_scan.adjacent_equal_loop.eq_def]
    simp only [guard, ↓reduceIte, subtraction, bind_tc_ok, indexed values prior previous atPrior,
      atHead, elementLaw, increment]
    by_cases same : view previous = view head
    · simp [same, adjacent_stopped, CollectionInvariants.adjacent]
    · simpa [same, CollectionInvariants.adjacent] using
        ih next head (by omega) nextRemaining nextBefore

theorem adjacent_exact (values : Slice T) :
    @auths_model.collection_scan.adjacent_equal T equality values =
      ok (CollectionInvariants.adjacent (values.val.map view)) := by
  unfold auths_model.collection_scan.adjacent_equal
  cases contents : values.val with
  | nil =>
    rw [auths_model.collection_scan.adjacent_equal_loop.eq_def]
    simp [contents, Slice.len_val, Slice.length, UScalar.lt_equiv, CollectionInvariants.adjacent]
  | cons first rest =>
    simpa [contents] using adjacent_suffix equality view elementLaw values 1#usize first rest
      (by simp) (by simp [contents]) (by simp [contents])

private theorem prefix_loop (fuel : Nat) (values : Slice T) (target : T)
    (stop position : Std.Usize) (matched : Bool)
    (stopBound : stop.val ≤ values.val.length) (remaining : stop.val = position.val + fuel) :
    @auths_model.collection_scan.prefix_contains_loop T equality values target stop position matched =
      ok (matched || search (values.val.map view) (view target) position.val fuel) := by
  induction fuel generalizing position matched with
  | zero =>
    have finished : ¬ position < stop := by scalar_tac
    rw [auths_model.collection_scan.prefix_contains_loop.eq_def]
    simp [finished, search]
  | succ fuel ih =>
    cases matched with
    | true =>
      rw [auths_model.collection_scan.prefix_contains_loop.eq_def]
      simp
    | false =>
      have guard : position < stop := by scalar_tac
      have within : position.val < values.val.length := by omega
      let first := values.val[position.val]
      have atHead : Slice.index_usize values position = ok first := by
        simp [Slice.index_usize, first, List.getElem?_eq_getElem within]
      have incrementFits : position.val + 1 ≤ Usize.max := by have := values.property; omega
      obtain ⟨next, increment, nextMeaning⟩ := spec_imp_exists
        (Usize.add_spec (x := position) (y := 1#usize) incrementFits)
      have nextValue : next.val = position.val + 1 := by simpa using nextMeaning
      have tail := ih next (decide (view first = view target)) (by omega)
      have present : (values.val.map view)[position.val]? = some (view first) := by
        simp [List.getElem?_map, List.getElem?_eq_getElem within, first]
      rw [auths_model.collection_scan.prefix_contains_loop.eq_def]
      simp only [guard, ↓reduceIte, Bool.not_false, Bool.true_and, atHead, bind_tc_ok,
        elementLaw, increment, tail]
      simp [search, present, nextValue]

/-- The public helper is total even for an end beyond the input: its actual
source clamp scans only the available prefix. -/
theorem prefix_exact (values : Slice T) (target : T) (end : Std.Usize) :
    @auths_model.collection_scan.prefix_contains T equality values target end =
      ok (decide (view target ∈ (values.val.map view).take end.val)) := by
  unfold auths_model.collection_scan.prefix_contains
  by_cases oversized : values.len < end
  · simp only [oversized, ↓reduceIte]
    have contract := prefix_loop equality view elementLaw values.val.length values target values.len
      0#usize false (by simp) (by simp)
    have meaning := search_eq_membership (values.val.map view) (view target) 0 values.val.length (by simp)
    have available : values.val.length ≤ end.val := by
      have stronger : values.val.length < end.val := by simpa [UScalar.lt_equiv, Slice.len_val] using oversized
      omega
    simpa [meaning, List.take_of_length_le (by simpa using available)] using contract
  · simp only [oversized, ↓reduceIte]
    have available : end.val ≤ values.val.length := by
      simpa [UScalar.lt_equiv, Slice.len_val] using Nat.le_of_not_gt oversized
    have contract := prefix_loop equality view elementLaw end.val values target end 0#usize false
      available (by simp)
    simpa [search_eq_membership _ _ 0 end.val (by simpa using available)] using contract

private theorem duplicates_loop (fuel : Nat) (values : Slice T) (position : Std.Usize)
    (matched : Bool) (remaining : values.val.length = position.val + fuel) :
    @auths_model.collection_scan.has_duplicates_loop T equality values position matched =
      ok (matched || from (values.val.map view) position.val fuel) := by
  induction fuel generalizing position matched with
  | zero =>
    have finished : ¬ position < values.len := by simpa [UScalar.lt_equiv, Slice.len_val] using Nat.not_lt.mpr (by omega)
    rw [auths_model.collection_scan.has_duplicates_loop.eq_def]
    simp [finished, from]
  | succ fuel ih =>
    cases matched with
    | true =>
      rw [auths_model.collection_scan.has_duplicates_loop.eq_def]
      simp
    | false =>
      have within : position.val < values.val.length := by omega
      have guard : position < values.len := by simpa [UScalar.lt_equiv, Slice.len_val] using within
      let first := values.val[position.val]
      have indexed : Slice.index_usize values position = ok first := by
        simp [Slice.index_usize, first, List.getElem?_eq_getElem within]
      have present : (values.val.map view)[position.val]? = some (view first) := by
        simp [List.getElem?_map, List.getElem?_eq_getElem within, first]
      have incrementFits : position.val + 1 ≤ Usize.max := by have := values.property; omega
      obtain ⟨next, increment, nextMeaning⟩ := spec_imp_exists
        (Usize.add_spec (x := position) (y := 1#usize) incrementFits)
      have nextValue : next.val = position.val + 1 := by simpa using nextMeaning
      have tail := ih next (decide (view first ∈ (values.val.map view).take position.val)) (by omega)
      rw [auths_model.collection_scan.has_duplicates_loop.eq_def]
      simp only [guard, ↓reduceIte, Bool.not_false, Bool.true_and, indexed, bind_tc_ok,
        prefix_exact equality view elementLaw, increment, tail]
      simp [from, before, present, nextValue]

theorem duplicates_exact (values : Slice T) :
    @auths_model.collection_scan.has_duplicates T equality values =
      ok (SnapshotUniqueness.hasDuplicate (values.val.map view)) := by
  unfold auths_model.collection_scan.has_duplicates
  simpa [← complete_scan_exact] using
    duplicates_loop equality view elementLaw values.val.length values 0#usize false (by simp)

theorem duplicate_refusal_iff (values : Slice T) :
    @auths_model.collection_scan.has_duplicates T equality values = ok true ↔
      ¬ (values.val.map view).Nodup := by
  rw [duplicates_exact equality view elementLaw values]
  simp only [Result.ok.injEq]
  exact SnapshotUniqueness.duplicate_iff _

theorem adjacent_earns_unique (values : Slice T) (relation : Key → Key → Prop)
    (antisymmetric : ∀ left right, relation left right → relation right left → left = right)
    (ordered : (values.val.map view).Pairwise relation)
    (accepted : @auths_model.collection_scan.adjacent_equal T equality values = ok false) :
    (values.val.map view).Nodup := by
  rw [adjacent_exact equality view elementLaw] at accepted
  have clean : CollectionInvariants.adjacent (values.val.map view) = false := by simpa using accepted
  exact (CollectionInvariants.adjacent_false_nodup relation antisymmetric _ ordered).mp clean

end Auths.Codec.ProtocolCollectionScans
