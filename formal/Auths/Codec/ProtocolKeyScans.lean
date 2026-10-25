import Auths.Codec.ProtocolEquality

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Codec.ProtocolKeyScans
set_option maxHeartbeats 2000000

/- Concrete source scans compare the actual unsigned identifier fields. Their
proofs unfold their real loops, getters and derived equality implementations.
No equality law for an opaque Auths comparison is a premise. Canonical sorting,
count checks and component validity remain obligations of constructor callers. -/

private theorem indexed {T : Type} (values : Slice T) (position : Std.Usize) (value : T)
    (present : values.val[position.val]? = some value) :
    Slice.index_usize values position = ok value := by
  simp [Slice.index_usize, present]

private theorem extension_stopped (values : Slice auths_model.CriticalExtension) (position : Std.Usize) :
    auths_model.collection_scan.extension_ids_repeat_loop values position true = ok true := by
  rw [auths_model.collection_scan.extension_ids_repeat_loop.eq_def]
  simp

private theorem extension_suffix (values : Slice auths_model.CriticalExtension) (position : Std.Usize)
    (previous : auths_model.CriticalExtension) (rest : List auths_model.CriticalExtension)
    (positive : 0 < position.val) (remaining : values.val.drop position.val = rest)
    (before : values.val[position.val - 1]? = some previous) :
    auths_model.collection_scan.extension_ids_repeat_loop values position false =
      ok (CollectionInvariants.adjacent (previous.id :: rest.map (fun value => value.id))) := by
  induction rest generalizing position previous with
  | nil =>
    have finished : ¬ position < values.len := by
      have size := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at size
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [auths_model.collection_scan.extension_ids_repeat_loop.eq_def]
    simp [finished, CollectionInvariants.adjacent]
  | cons head tail ih =>
    obtain ⟨guard, atHead⟩ := Auths.StatusSelection.indexed_head values position head tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ := Auths.StatusSelection.indexed_next values position head tail remaining
    obtain ⟨prior, subtraction, priorValue, _⟩ := spec_imp_exists
      (Usize.sub_spec (x := position) (y := 1#usize) (by simpa using Nat.succ_le_of_lt positive))
    have atPrior : values.val[prior.val]? = some previous := by simpa [priorValue] using before
    have inside : position.val < values.val.length := by simpa only [UScalar.lt_equiv, Slice.len_val] using guard
    have atHeadOption : values.val[position.val]? = some head := by
      have decomposition := List.drop_eq_getElem_cons inside
      rw [remaining] at decomposition
      have same := (List.cons.inj decomposition).1.symm
      simpa [List.getElem?_eq_getElem inside] using congrArg some same
    have nextBefore : values.val[next.val - 1]? = some head := by simpa [nextValue] using atHeadOption
    rw [auths_model.collection_scan.extension_ids_repeat_loop.eq_def]
    simp only [guard, ↓reduceIte, subtraction, bind_tc_ok, indexed values prior previous atPrior,
      atHead, auths_model.CriticalExtension.id, core.cmp.impls.PartialEqShared,
      auths_model.ExtensionId.Insts.CoreCmpPartialEqExtensionId, ProtocolEquality.extension_id_exact, increment]
    by_cases same : previous.id = head.id
    · simp [same, extension_stopped, CollectionInvariants.adjacent]
    · simpa [same, CollectionInvariants.adjacent] using ih next head (by omega) nextRemaining nextBefore

theorem extension_exact (values : Slice auths_model.CriticalExtension) :
    auths_model.collection_scan.extension_ids_repeat values =
      ok (CollectionInvariants.adjacent (values.val.map (fun value => value.id))) := by
  unfold auths_model.collection_scan.extension_ids_repeat
  cases contents : values.val with
  | nil =>
    rw [auths_model.collection_scan.extension_ids_repeat_loop.eq_def]
    simp [contents, Slice.len_val, Slice.length, UScalar.lt_equiv, CollectionInvariants.adjacent]
  | cons first rest =>
    simpa [contents] using extension_suffix values 1#usize first rest (by simp) (by simp [contents]) (by simp [contents])

private theorem fact_stopped (values : Slice auths_model.observation.ObservationFact) (position : Std.Usize) :
    auths_model.collection_scan.fact_names_repeat_loop values position true = ok true := by
  rw [auths_model.collection_scan.fact_names_repeat_loop.eq_def]
  simp

private theorem fact_suffix (values : Slice auths_model.observation.ObservationFact) (position : Std.Usize)
    (previous : auths_model.observation.ObservationFact) (rest : List auths_model.observation.ObservationFact)
    (positive : 0 < position.val) (remaining : values.val.drop position.val = rest)
    (before : values.val[position.val - 1]? = some previous) :
    auths_model.collection_scan.fact_names_repeat_loop values position false =
      ok (CollectionInvariants.adjacent (previous.name :: rest.map (fun value => value.name))) := by
  induction rest generalizing position previous with
  | nil =>
    have finished : ¬ position < values.len := by
      have size := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at size
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [auths_model.collection_scan.fact_names_repeat_loop.eq_def]
    simp [finished, CollectionInvariants.adjacent]
  | cons head tail ih =>
    obtain ⟨guard, atHead⟩ := Auths.StatusSelection.indexed_head values position head tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ := Auths.StatusSelection.indexed_next values position head tail remaining
    obtain ⟨prior, subtraction, priorValue, _⟩ := spec_imp_exists
      (Usize.sub_spec (x := position) (y := 1#usize) (by simpa using Nat.succ_le_of_lt positive))
    have atPrior : values.val[prior.val]? = some previous := by simpa [priorValue] using before
    have inside : position.val < values.val.length := by simpa only [UScalar.lt_equiv, Slice.len_val] using guard
    have atHeadOption : values.val[position.val]? = some head := by
      have decomposition := List.drop_eq_getElem_cons inside
      rw [remaining] at decomposition
      have same := (List.cons.inj decomposition).1.symm
      simpa [List.getElem?_eq_getElem inside] using congrArg some same
    have nextBefore : values.val[next.val - 1]? = some head := by simpa [nextValue] using atHeadOption
    rw [auths_model.collection_scan.fact_names_repeat_loop.eq_def]
    simp only [guard, ↓reduceIte, subtraction, bind_tc_ok, indexed values prior previous atPrior,
      atHead, auths_model.observation.ObservationFact.name, core.cmp.impls.PartialEqShared,
      auths_model.observation.FactName.Insts.CoreCmpPartialEqFactName, ProtocolEquality.fact_name_exact, increment]
    by_cases same : previous.name = head.name
    · simp [same, fact_stopped, CollectionInvariants.adjacent]
    · simpa [same, CollectionInvariants.adjacent] using ih next head (by omega) nextRemaining nextBefore

theorem fact_exact (values : Slice auths_model.observation.ObservationFact) :
    auths_model.collection_scan.fact_names_repeat values =
      ok (CollectionInvariants.adjacent (values.val.map (fun value => value.name))) := by
  unfold auths_model.collection_scan.fact_names_repeat
  cases contents : values.val with
  | nil =>
    rw [auths_model.collection_scan.fact_names_repeat_loop.eq_def]
    simp [contents, Slice.len_val, Slice.length, UScalar.lt_equiv, CollectionInvariants.adjacent]
  | cons first rest =>
    simpa [contents] using fact_suffix values 1#usize first rest (by simp) (by simp [contents]) (by simp [contents])

private theorem evidence_stopped (values : Slice auths_model.EvidenceObject) (position : Std.Usize) :
    auths_model.collection_scan.evidence_ids_repeat_loop values position true = ok true := by
  rw [auths_model.collection_scan.evidence_ids_repeat_loop.eq_def]
  simp

private theorem evidence_suffix (values : Slice auths_model.EvidenceObject) (position : Std.Usize)
    (previous : auths_model.EvidenceObject) (rest : List auths_model.EvidenceObject)
    (positive : 0 < position.val) (remaining : values.val.drop position.val = rest)
    (before : values.val[position.val - 1]? = some previous) :
    auths_model.collection_scan.evidence_ids_repeat_loop values position false =
      ok (CollectionInvariants.adjacent (previous.id :: rest.map (fun value => value.id))) := by
  induction rest generalizing position previous with
  | nil =>
    have finished : ¬ position < values.len := by
      have size := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at size
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [auths_model.collection_scan.evidence_ids_repeat_loop.eq_def]
    simp [finished, CollectionInvariants.adjacent]
  | cons head tail ih =>
    obtain ⟨guard, atHead⟩ := Auths.StatusSelection.indexed_head values position head tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ := Auths.StatusSelection.indexed_next values position head tail remaining
    obtain ⟨prior, subtraction, priorValue, _⟩ := spec_imp_exists
      (Usize.sub_spec (x := position) (y := 1#usize) (by simpa using Nat.succ_le_of_lt positive))
    have atPrior : values.val[prior.val]? = some previous := by simpa [priorValue] using before
    have inside : position.val < values.val.length := by simpa only [UScalar.lt_equiv, Slice.len_val] using guard
    have atHeadOption : values.val[position.val]? = some head := by
      have decomposition := List.drop_eq_getElem_cons inside
      rw [remaining] at decomposition
      have same := (List.cons.inj decomposition).1.symm
      simpa [List.getElem?_eq_getElem inside] using congrArg some same
    have nextBefore : values.val[next.val - 1]? = some head := by simpa [nextValue] using atHeadOption
    rw [auths_model.collection_scan.evidence_ids_repeat_loop.eq_def]
    simp only [guard, ↓reduceIte, subtraction, bind_tc_ok, indexed values prior previous atPrior,
      atHead, auths_model.EvidenceObject.id, core.cmp.impls.PartialEqShared,
      auths_model.EvidenceId.Insts.CoreCmpPartialEqEvidenceId, ProtocolEquality.evidence_id_exact, increment]
    by_cases same : previous.id = head.id
    · simp [same, evidence_stopped, CollectionInvariants.adjacent]
    · simpa [same, CollectionInvariants.adjacent] using ih next head (by omega) nextRemaining nextBefore

theorem evidence_exact (values : Slice auths_model.EvidenceObject) :
    auths_model.collection_scan.evidence_ids_repeat values =
      ok (CollectionInvariants.adjacent (values.val.map (fun value => value.id))) := by
  unfold auths_model.collection_scan.evidence_ids_repeat
  cases contents : values.val with
  | nil =>
    rw [auths_model.collection_scan.evidence_ids_repeat_loop.eq_def]
    simp [contents, Slice.len_val, Slice.length, UScalar.lt_equiv, CollectionInvariants.adjacent]
  | cons first rest =>
    simpa [contents] using evidence_suffix values 1#usize first rest (by simp) (by simp [contents]) (by simp [contents])

end Auths.Codec.ProtocolKeyScans
