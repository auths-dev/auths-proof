import Auths.Crypto.ResultLeaves

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.ResultSatisfactions
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Codec.ProtocolArrayWriters

theorem constant_allocation {Value : Type} (cost : Nat) (values : List Value) :
    allocation (fun _ => cost) values = cost * values.length := by
  induction values with
  | nil => simp [allocation]
  | cons first rest ih =>
    change cost + allocation (fun _ => cost) rest = cost * (rest.length + 1)
    rw [ih]
    omega

/- Complete reported observation/approval satisfaction IDs and arrays. These
byte statements neither authenticate the referenced records nor establish
that a requirement was in fact satisfied by the real verifier. -/

private theorem digests_stopped (self : cbor.Encoder) (values : Slice auths_model.ApprovalDigest)
    (position : Std.Usize) (failure : error.CodecError) :
    approval.encode_approval_digests_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [approval.encode_approval_digests_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem digests_suffix (values : Slice auths_model.ApprovalDigest) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.ApprovalDigest)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, (fun _ => True) value)
    (space : self.output.val.length + allocation (fun _ => 41) rest ≤ Usize.max) :
    approval.encode_approval_digests_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.digest rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [approval.encode_approval_digests_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, (fun _ => True) value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + (fun _ => 41) first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [approval.encode_approval_digests_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    simp only [auths_model.ApprovalDigest.as_bytes, lift, Array.to_slice, bind_tc_ok]
    step with UnsignedLeaves.digest_exact self first firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := digest_length first
    have tailSpace : after.output.val.length + allocation (fun _ => 41) tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem digests_exact (self : cbor.Encoder) (values : Slice auths_model.ApprovalDigest)
    (space : self.output.val.length + 9 + allocation (fun _ => 41) values.val ≤ Usize.max) :
    approval.encode_approval_digests self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.digest) ⦄ := by
  unfold approval.encode_approval_digests
  step with ProtocolWriter.array_exact self (Slice.len (values)) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation (fun _ => 41) values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with digests_suffix (values) 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) (by simp) loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]

theorem observation_length (value : auths_model.observation.ObservationSatisfaction) :
    (ResultObjects.observationSatisfaction value).length ≤ 109 := by
  have outer := UnsignedWire.map_length [(0, UnsignedObjects.digest value.requirement),
    (1, UnsignedObjects.digest value.observation)]
  have requirement := UnsignedLeaves.digest_length value.requirement
  have observation := UnsignedLeaves.digest_length value.observation
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  omega

@[step] theorem observation_exact (self : cbor.Encoder) (value : auths_model.observation.ObservationSatisfaction)
    (space : self.output.val.length + 109 ≤ Usize.max) :
    observation.encode_observation_satisfaction self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ResultObjects.observationSatisfaction value ⦄ := by
  unfold observation.encode_observation_satisfaction
  step with ProtocolWriter.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.ObservationSatisfaction.impl.requirement, auths_model.ObservationRequirementId.as_bytes, lift, bind_tc_ok]
  step with UnsignedLeaves.digest_exact e1 value.requirement (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := UnsignedLeaves.digest_length value.requirement
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.ObservationSatisfaction.impl.observation, auths_model.AttachmentDigest.as_bytes, lift, bind_tc_ok]
  step with UnsignedLeaves.digest_exact e3 value.observation (by omega) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := UnsignedLeaves.digest_length value.observation
  simp [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes4, bytes3, bytes2, bytes1, bytes0, ResultObjects.observationSatisfaction,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

theorem approval_length (value : auths_model.approval.ApprovalSatisfaction) :
    (ResultObjects.approvalSatisfaction value).length ≤ ResultObjects.approvalSatisfactionCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedObjects.digest value.requirement),
    (1, UnsignedWire.array (value.approvals.val.map UnsignedObjects.digest))]
  have requirement := UnsignedLeaves.digest_length value.requirement
  have approvals := BundleLeaves.evidence_ids_length value.approvals.val
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [ResultObjects.approvalSatisfactionCost]
  omega

@[step] theorem approval_exact (self : cbor.Encoder) (value : auths_model.approval.ApprovalSatisfaction)
    (space : self.output.val.length + ResultObjects.approvalSatisfactionCost value ≤ Usize.max) :
    approval.encode_approval_satisfaction self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ResultObjects.approvalSatisfaction value ⦄ := by
  unfold approval.encode_approval_satisfaction
  simp only [ResultObjects.approvalSatisfactionCost] at space
  step with ProtocolWriter.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.ApprovalSatisfaction.impl.requirement, auths_model.ApprovalRequirementId.as_bytes, lift, bind_tc_ok]
  step with UnsignedLeaves.digest_exact e1 value.requirement (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := UnsignedLeaves.digest_length value.requirement
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.ApprovalSatisfaction.impl.approvals, core.ops.deref.DerefVec, bind_tc_ok]
  step with digests_exact e3 (alloc.vec.Vec.deref value.approvals) (by simpa only [alloc.vec.deref_exact, BundleLeaves.id_allocation] using (show e3.output.val.length + 9 + 41 * value.approvals.val.length ≤ Usize.max by omega)) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := BundleLeaves.evidence_ids_length value.approvals.val
  simp [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes4, bytes3, bytes2, bytes1, bytes0, ResultObjects.approvalSatisfaction,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

private theorem observations_stopped (self : cbor.Encoder) (values : Slice auths_model.observation.ObservationSatisfaction)
    (position : Std.Usize) (failure : error.CodecError) :
    observation.encode_observation_satisfactions_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [observation.encode_observation_satisfactions_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem observations_suffix (values : Slice auths_model.observation.ObservationSatisfaction) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.observation.ObservationSatisfaction)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, (fun _ => True) value)
    (space : self.output.val.length + allocation (fun _ => 109) rest ≤ Usize.max) :
    observation.encode_observation_satisfactions_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents ResultObjects.observationSatisfaction rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [observation.encode_observation_satisfactions_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, (fun _ => True) value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + (fun _ => 109) first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [observation.encode_observation_satisfactions_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with observation_exact self first firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := observation_length first
    have tailSpace : after.output.val.length + allocation (fun _ => 109) tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem observations_exact (self : cbor.Encoder) (values : Slice auths_model.observation.ObservationSatisfaction)
    (fields : ∀ value ∈ values.val, (fun _ => True) value)
    (space : self.output.val.length + 9 + allocation (fun _ => 109) values.val ≤ Usize.max) :
    observation.encode_observation_satisfactions self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map ResultObjects.observationSatisfaction) ⦄ := by
  unfold observation.encode_observation_satisfactions
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation (fun _ => 109) values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with observations_suffix values 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]


private theorem approvals_stopped (self : cbor.Encoder) (values : Slice auths_model.approval.ApprovalSatisfaction)
    (position : Std.Usize) (failure : error.CodecError) :
    approval.encode_approval_satisfactions_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [approval.encode_approval_satisfactions_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem approvals_suffix (values : Slice auths_model.approval.ApprovalSatisfaction) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.approval.ApprovalSatisfaction)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, (fun _ => True) value)
    (space : self.output.val.length + allocation ResultObjects.approvalSatisfactionCost rest ≤ Usize.max) :
    approval.encode_approval_satisfactions_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents ResultObjects.approvalSatisfaction rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [approval.encode_approval_satisfactions_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, (fun _ => True) value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + ResultObjects.approvalSatisfactionCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [approval.encode_approval_satisfactions_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with approval_exact self first firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := approval_length first
    have tailSpace : after.output.val.length + allocation ResultObjects.approvalSatisfactionCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem approvals_exact (self : cbor.Encoder) (values : Slice auths_model.approval.ApprovalSatisfaction)
    (fields : ∀ value ∈ values.val, (fun _ => True) value)
    (space : self.output.val.length + 9 + allocation ResultObjects.approvalSatisfactionCost values.val ≤ Usize.max) :
    approval.encode_approval_satisfactions self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map ResultObjects.approvalSatisfaction) ⦄ := by
  unfold approval.encode_approval_satisfactions
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation ResultObjects.approvalSatisfactionCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with approvals_suffix values 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]


end Auths.Crypto.ResultSatisfactions
