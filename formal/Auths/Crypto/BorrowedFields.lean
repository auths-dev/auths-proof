import Auths.Crypto.BundleFieldSorting
import Auths.Crypto.BorrowedKeys
import Auths.Verifier.StatusLeaves

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.BorrowedFields
open Auths.Codec

/- Concrete source gathering loops preserve complete borrowed records, then
actual stateless field sorts use proved source selectors/comparison laws.
ReferenceCapacity is an independent native allocation envelope. No successful
collection, desired sorting result or opaque Auths callback is supplied. -/

private theorem action_gather (records : Slice auths_model.SignedAction)
    (position : Std.Usize) (output : alloc.vec.Vec auths_model.SignedAction)
    (rest : List auths_model.SignedAction) (remaining : records.val.drop position.val = rest)
    (capacity : BorrowedKeys.ReferenceCapacity (output.val.length + rest.length)) :
    encode.sorted_action_refs_loop records output position ⦃ result => result.val = output.val ++ rest ⦄ := by
  induction rest generalizing position output with
  | nil =>
    have finished : ¬ position < records.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.sorted_action_refs_loop.eq_def]
    simp [finished, spec_ok]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head records position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next records position first tail remaining
    have room : output.val.length < Usize.max := by
      have words := capacity.1
      simp only [List.length_cons] at words
      omega
    rw [encode.sorted_action_refs_loop.eq_def]
    simp only [guard, ↓reduceIte, atFirst, bind_tc_ok]
    step with alloc.vec.push_spec output first room as ⟨after, appended⟩
    have sameCount : after.val.length + tail.length = output.val.length + (first :: tail).length := by
      simp only [appended, List.length_append, List.length_singleton, List.length_cons]
      omega
    have nextCapacity : BorrowedKeys.ReferenceCapacity (after.val.length + tail.length) := by
      rw [sameCount]
      exact capacity
    simp only [increment, bind_tc_ok]
    apply spec_mono (ih next after nextRemaining nextCapacity)
    intro result exactRest
    rw [exactRest, appended]
    simp [List.append_assoc]

@[step] theorem action_exact (records : Slice auths_model.SignedAction)
    (capacity : BorrowedKeys.ReferenceCapacity records.val.length) :
    encode.sorted_action_refs records ⦃ output =>
      output.val = StableNormalization.sort BundleObjects.actionKey records.val ⦄ := by
  unfold encode.sorted_action_refs
  simp only [lift, bind_tc_ok]
  step with action_gather records 0#usize
    (alloc.vec.Vec.with_capacity auths_model.SignedAction (Slice.len records)) records.val
    (by simp) (by simpa only [alloc.vec.with_capacity_contents, List.length_nil, Nat.zero_add] using capacity)
    as ⟨borrowed, complete⟩
  rw [BundleFieldSorting.actions_exact]
  simp only [spec_ok, SnapshotOrdering.sorted_by_key_contents, complete,
    alloc.vec.with_capacity_contents, List.nil_append]

private theorem evidence_gather (records : Slice auths_model.EvidenceObject)
    (position : Std.Usize) (output : alloc.vec.Vec auths_model.EvidenceObject)
    (rest : List auths_model.EvidenceObject) (remaining : records.val.drop position.val = rest)
    (capacity : BorrowedKeys.ReferenceCapacity (output.val.length + rest.length)) :
    encode.sorted_evidence_refs_loop records output position ⦃ result => result.val = output.val ++ rest ⦄ := by
  induction rest generalizing position output with
  | nil =>
    have finished : ¬ position < records.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.sorted_evidence_refs_loop.eq_def]
    simp [finished, spec_ok]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head records position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next records position first tail remaining
    have room : output.val.length < Usize.max := by
      have words := capacity.1
      simp only [List.length_cons] at words
      omega
    rw [encode.sorted_evidence_refs_loop.eq_def]
    simp only [guard, ↓reduceIte, atFirst, bind_tc_ok]
    step with alloc.vec.push_spec output first room as ⟨after, appended⟩
    have sameCount : after.val.length + tail.length = output.val.length + (first :: tail).length := by
      simp only [appended, List.length_append, List.length_singleton, List.length_cons]
      omega
    have nextCapacity : BorrowedKeys.ReferenceCapacity (after.val.length + tail.length) := by
      rw [sameCount]
      exact capacity
    simp only [increment, bind_tc_ok]
    apply spec_mono (ih next after nextRemaining nextCapacity)
    intro result exactRest
    rw [exactRest, appended]
    simp [List.append_assoc]

@[step] theorem evidence_exact (records : Slice auths_model.EvidenceObject)
    (capacity : BorrowedKeys.ReferenceCapacity records.val.length) :
    encode.sorted_evidence_refs records ⦃ output =>
      output.val = StableNormalization.sort BundleObjects.evidenceKey records.val ⦄ := by
  unfold encode.sorted_evidence_refs
  simp only [lift, bind_tc_ok]
  step with evidence_gather records 0#usize
    (alloc.vec.Vec.with_capacity auths_model.EvidenceObject (Slice.len records)) records.val
    (by simp) (by simpa only [alloc.vec.with_capacity_contents, List.length_nil, Nat.zero_add] using capacity)
    as ⟨borrowed, complete⟩
  rw [BundleFieldSorting.evidence_exact]
  simp only [spec_ok, SnapshotOrdering.sorted_by_key_contents, complete,
    alloc.vec.with_capacity_contents, List.nil_append]

private theorem binding_gather (records : Slice auths_model.ControlBinding)
    (position : Std.Usize) (output : alloc.vec.Vec auths_model.ControlBinding)
    (rest : List auths_model.ControlBinding) (remaining : records.val.drop position.val = rest)
    (capacity : BorrowedKeys.ReferenceCapacity (output.val.length + rest.length)) :
    encode.sorted_binding_refs_loop records output position ⦃ result => result.val = output.val ++ rest ⦄ := by
  induction rest generalizing position output with
  | nil =>
    have finished : ¬ position < records.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.sorted_binding_refs_loop.eq_def]
    simp [finished, spec_ok]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head records position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next records position first tail remaining
    have room : output.val.length < Usize.max := by
      have words := capacity.1
      simp only [List.length_cons] at words
      omega
    rw [encode.sorted_binding_refs_loop.eq_def]
    simp only [guard, ↓reduceIte, atFirst, bind_tc_ok]
    step with alloc.vec.push_spec output first room as ⟨after, appended⟩
    have sameCount : after.val.length + tail.length = output.val.length + (first :: tail).length := by
      simp only [appended, List.length_append, List.length_singleton, List.length_cons]
      omega
    have nextCapacity : BorrowedKeys.ReferenceCapacity (after.val.length + tail.length) := by
      rw [sameCount]
      exact capacity
    simp only [increment, bind_tc_ok]
    apply spec_mono (ih next after nextRemaining nextCapacity)
    intro result exactRest
    rw [exactRest, appended]
    simp [List.append_assoc]

@[step] theorem binding_exact (records : Slice auths_model.ControlBinding)
    (capacity : BorrowedKeys.ReferenceCapacity records.val.length) :
    encode.sorted_binding_refs records ⦃ output =>
      output.val = StableNormalization.sort BundleObjects.bindingKey records.val ⦄ := by
  unfold encode.sorted_binding_refs
  simp only [lift, bind_tc_ok]
  step with binding_gather records 0#usize
    (alloc.vec.Vec.with_capacity auths_model.ControlBinding (Slice.len records)) records.val
    (by simp) (by simpa only [alloc.vec.with_capacity_contents, List.length_nil, Nat.zero_add] using capacity)
    as ⟨borrowed, complete⟩
  rw [BundleFieldSorting.bindings_exact]
  simp only [spec_ok, SnapshotOrdering.sorted_by_key_contents, complete,
    alloc.vec.with_capacity_contents, List.nil_append]

private theorem attachment_gather (records : Slice auths_model.AttachmentDescriptor)
    (position : Std.Usize) (output : alloc.vec.Vec auths_model.AttachmentDescriptor)
    (rest : List auths_model.AttachmentDescriptor) (remaining : records.val.drop position.val = rest)
    (capacity : BorrowedKeys.ReferenceCapacity (output.val.length + rest.length)) :
    encode.sorted_attachment_refs_loop records output position ⦃ result => result.val = output.val ++ rest ⦄ := by
  induction rest generalizing position output with
  | nil =>
    have finished : ¬ position < records.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.sorted_attachment_refs_loop.eq_def]
    simp [finished, spec_ok]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head records position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next records position first tail remaining
    have room : output.val.length < Usize.max := by
      have words := capacity.1
      simp only [List.length_cons] at words
      omega
    rw [encode.sorted_attachment_refs_loop.eq_def]
    simp only [guard, ↓reduceIte, atFirst, bind_tc_ok]
    step with alloc.vec.push_spec output first room as ⟨after, appended⟩
    have sameCount : after.val.length + tail.length = output.val.length + (first :: tail).length := by
      simp only [appended, List.length_append, List.length_singleton, List.length_cons]
      omega
    have nextCapacity : BorrowedKeys.ReferenceCapacity (after.val.length + tail.length) := by
      rw [sameCount]
      exact capacity
    simp only [increment, bind_tc_ok]
    apply spec_mono (ih next after nextRemaining nextCapacity)
    intro result exactRest
    rw [exactRest, appended]
    simp [List.append_assoc]

@[step] theorem attachment_exact (records : Slice auths_model.AttachmentDescriptor)
    (capacity : BorrowedKeys.ReferenceCapacity records.val.length) :
    encode.sorted_attachment_refs records ⦃ output =>
      output.val = StableNormalization.sort BundleObjects.attachmentKey records.val ⦄ := by
  unfold encode.sorted_attachment_refs
  simp only [lift, bind_tc_ok]
  step with attachment_gather records 0#usize
    (alloc.vec.Vec.with_capacity auths_model.AttachmentDescriptor (Slice.len records)) records.val
    (by simp) (by simpa only [alloc.vec.with_capacity_contents, List.length_nil, Nat.zero_add] using capacity)
    as ⟨borrowed, complete⟩
  rw [BundleFieldSorting.attachments_exact]
  simp only [spec_ok, SnapshotOrdering.sorted_by_key_contents, complete,
    alloc.vec.with_capacity_contents, List.nil_append]

end Auths.Crypto.BorrowedFields
