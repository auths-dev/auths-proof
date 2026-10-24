import Auths.Crypto.ContextAnchors
import Auths.Verifier.StatusLeaves

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.ContextAnchorArrays
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Codec.ProtocolArrayWriters

/- Three concrete source loops, preserving every full record and its stored
order. No caller supplies a successful callback or an expected writer result. -/

private theorem anchors_stopped (self : cbor.Encoder) (values : Slice auths_model.TrustAnchor)
    (position : Std.Usize) (failure : error.CodecError) :
    encode.encode_trust_anchors_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [encode.encode_trust_anchors_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem anchors_suffix (values : Slice auths_model.TrustAnchor) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.TrustAnchor)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, ContextAnchors.AnchorStrings value)
    (space : self.output.val.length + allocation ContextObjects.anchorCost rest ≤ Usize.max) :
    encode.encode_trust_anchors_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents ContextObjects.anchor rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.encode_trust_anchors_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, ContextAnchors.AnchorStrings value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + ContextObjects.anchorCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [encode.encode_trust_anchors_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with ContextAnchors.anchor_exact self first firstValid firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := ContextAnchors.anchor_length first
    have tailSpace : after.output.val.length + allocation ContextObjects.anchorCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem anchors_exact (self : cbor.Encoder) (values : Slice auths_model.TrustAnchor)
    (fields : ∀ value ∈ values.val, ContextAnchors.AnchorStrings value)
    (space : self.output.val.length + 9 + allocation ContextObjects.anchorCost values.val ≤ Usize.max) :
    encode.encode_trust_anchors self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map ContextObjects.anchor) ⦄ := by
  unfold encode.encode_trust_anchors
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation ContextObjects.anchorCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with anchors_suffix values 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]


private theorem observers_stopped (self : cbor.Encoder) (values : Slice auths_model.observation.ObserverAnchor)
    (position : Std.Usize) (failure : error.CodecError) :
    observation.encode_observer_anchors_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [observation.encode_observer_anchors_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem observers_suffix (values : Slice auths_model.observation.ObserverAnchor) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.observation.ObserverAnchor)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, ContextAnchors.ObserverStrings value)
    (space : self.output.val.length + allocation ContextObjects.observerCost rest ≤ Usize.max) :
    observation.encode_observer_anchors_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents ContextObjects.observer rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [observation.encode_observer_anchors_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, ContextAnchors.ObserverStrings value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + ContextObjects.observerCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [observation.encode_observer_anchors_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with ContextAnchors.observer_exact self first firstValid firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := ContextAnchors.observer_length first
    have tailSpace : after.output.val.length + allocation ContextObjects.observerCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem observers_exact (self : cbor.Encoder) (values : Slice auths_model.observation.ObserverAnchor)
    (fields : ∀ value ∈ values.val, ContextAnchors.ObserverStrings value)
    (space : self.output.val.length + 9 + allocation ContextObjects.observerCost values.val ≤ Usize.max) :
    observation.encode_observer_anchors self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map ContextObjects.observer) ⦄ := by
  unfold observation.encode_observer_anchors
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation ContextObjects.observerCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with observers_suffix values 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]


private theorem approvers_stopped (self : cbor.Encoder) (values : Slice auths_model.approval.ApproverAnchor)
    (position : Std.Usize) (failure : error.CodecError) :
    approval.encode_approver_anchors_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [approval.encode_approver_anchors_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem approvers_suffix (values : Slice auths_model.approval.ApproverAnchor) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.approval.ApproverAnchor)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, ContextAnchors.ApproverStrings value)
    (space : self.output.val.length + allocation ContextObjects.approverCost rest ≤ Usize.max) :
    approval.encode_approver_anchors_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents ContextObjects.approver rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [approval.encode_approver_anchors_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, ContextAnchors.ApproverStrings value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + ContextObjects.approverCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [approval.encode_approver_anchors_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with ContextAnchors.approver_exact self first firstValid firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := ContextAnchors.approver_length first
    have tailSpace : after.output.val.length + allocation ContextObjects.approverCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem approvers_exact (self : cbor.Encoder) (values : Slice auths_model.approval.ApproverAnchor)
    (fields : ∀ value ∈ values.val, ContextAnchors.ApproverStrings value)
    (space : self.output.val.length + 9 + allocation ContextObjects.approverCost values.val ≤ Usize.max) :
    approval.encode_approver_anchors self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map ContextObjects.approver) ⦄ := by
  unfold approval.encode_approver_anchors
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation ContextObjects.approverCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with approvers_suffix values 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]


end Auths.Crypto.ContextAnchorArrays
